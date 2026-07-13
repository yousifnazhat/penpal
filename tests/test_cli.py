from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from penpal.cli import main
from penpal.ingest import extract_evidence
from penpal.models import Service
from penpal.nmap_parser import parse_nmap_xml
from penpal.workspace import Workspace


RAW_SNMP_OUTPUT = """SNMPv2-MIB::sysName.0 = STRING: mail01.example.local
User: daniel
email: daniel@example.local
/backup.zip Status: 200, Size: 9001
"""


class CliTests(unittest.TestCase):
    def test_pasted_nmap_output_records_services_and_returns_masked_suggestions(self) -> None:
        pasted = """PORT    STATE SERVICE
80/tcp  open  http
445/tcp open  microsoft-ds
User: daniel
password=Winter2024!
/admin Status: 200, Size: 1234
"""
        with TemporaryDirectory() as temp_dir:
            Workspace(temp_dir).create_target("10.10.10.5", name="pasted")
            with patch("penpal.cli.sys.stdin", StringIO(pasted)):
                result = run_json(["--workspace", temp_dir, "ingest", "pasted", "--source", "nmap", "--json"])

        self.assertEqual(
            [(item["protocol"], item["port"], item["name"]) for item in result["detected_services"]],
            [("tcp", 80, "http"), ("tcp", 445, "microsoft-ds")],
        )
        self.assertIn("credentials_to_remote", [item["id"] for item in result["suggestions"]])
        self.assertIn("review_web_paths", [item["id"] for item in result["suggestions"]])
        self.assertIn("<sensitive>", json.dumps(result))
        self.assertNotIn("Winter2024!", json.dumps(result))

    def test_focus_command_exhausts_and_reopens_a_suggestion(self) -> None:
        suggestion_id = "playbook_smb-shares-configs-credentials"
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="focus")
            workspace.merge_services(target.name, [Service(port=445, protocol="tcp", name="microsoft-ds")])

            exhausted = run_json(["--workspace", temp_dir, "focus", target.name, suggestion_id, "exhausted", "--json"])
            reopened = run_json(["--workspace", temp_dir, "focus", target.name, suggestion_id, "reopened", "--json"])
            outcome = next(
                item for item in workspace.load_evidence(target.name) if item.type == "investigation_outcome"
            )

        self.assertEqual(exhausted["outcome"]["metadata"]["status"], "exhausted")
        self.assertNotIn(suggestion_id, [item["id"] for item in exhausted["suggestions"]])
        self.assertEqual(outcome.metadata["status"], "reopened")
        self.assertIn(suggestion_id, [item["id"] for item in reopened["suggestions"]])

    def test_doctor_reports_supported_environment_without_modifying_workspace(self) -> None:
        with (
            TemporaryDirectory() as temp_dir,
            patch("penpal.doctor.sys.version_info", (3, 12)),
            patch("penpal.doctor.platform.python_version", return_value="3.12.0"),
            patch("penpal.doctor.shutil.which", return_value=None),
        ):
            workspace = Workspace(temp_dir)
            workspace.set_scope(["10.10.10.0/24"])
            workspace.create_target("10.10.10.5", name="chain")

            report = run_json(["--workspace", temp_dir, "doctor", "--json"])

        checks = {check["name"]: check for check in report["checks"]}
        self.assertEqual(report["schema"], "penpal-doctor-v1")
        self.assertEqual(report["status"], "warning")
        self.assertEqual(checks["workspace"]["status"], "ok")
        self.assertEqual(checks["pi"]["status"], "warning")

    def test_doctor_returns_json_error_for_invalid_workspace_schema(self) -> None:
        with (
            TemporaryDirectory() as temp_dir,
            patch("penpal.doctor.sys.version_info", (3, 12)),
            patch("penpal.doctor.platform.python_version", return_value="3.12.0"),
            patch("penpal.doctor.shutil.which", return_value=None),
        ):
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="chain")
            workspace.services_path(target.name).write_text('{"schema":"penpal-services-v99"}', encoding="utf-8")
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = main(["--workspace", temp_dir, "doctor", "--json"])

        report = json.loads(stdout.getvalue())
        workspace_check = next(check for check in report["checks"] if check["name"] == "workspace")
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "error")
        self.assertEqual(workspace_check["status"], "error")
        self.assertIn("Unsupported storage schema", workspace_check["message"])

    def test_doctor_warns_without_exposing_plaintext_or_missing_environment_secrets(self) -> None:
        secret = "Winter2024!"
        with (
            TemporaryDirectory() as temp_dir,
            patch("penpal.doctor.sys.version_info", (3, 12)),
            patch("penpal.doctor.platform.python_version", return_value="3.12.0"),
            patch("penpal.doctor.shutil.which", return_value=None),
        ):
            workspace = Workspace(temp_dir, environment={})
            target = workspace.create_target("10.10.10.5", name="chain")
            workspace.set_parameter(target.name, "known_password", secret, sensitive=True)
            workspace.set_environment_parameter(target.name, "api_token", "PENPAL_API_TOKEN")

            report = run_json(["--workspace", temp_dir, "doctor", "--json"])

        body = json.dumps(report)
        workspace_check = next(check for check in report["checks"] if check["name"] == "workspace")
        self.assertEqual(workspace_check["status"], "warning")
        self.assertIn("1 plaintext sensitive parameter(s)", workspace_check["message"])
        self.assertIn("1 missing environment variable(s)", workspace_check["message"])
        self.assertNotIn(secret, body)

    def test_set_env_parameter_resolves_without_writing_or_echoing_the_secret(self) -> None:
        secret = "Winter2024!"
        with TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"PENPAL_CLI_SECRET": secret}):
            Workspace(temp_dir).create_target("10.10.10.5", name="chain")
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = main(
                    [
                        "--workspace",
                        temp_dir,
                        "params",
                        "chain",
                        "set-env",
                        "known_password",
                        "PENPAL_CLI_SECRET",
                    ]
                )
            masked = run_json(["--workspace", temp_dir, "params", "chain", "list", "--json"])
            revealed = run_json(["--workspace", temp_dir, "params", "chain", "list", "--json", "--reveal-secrets"])
            stored = (Path(temp_dir) / "targets" / "chain" / "parameters.json").read_text(encoding="utf-8")

        output = stdout.getvalue()
        password = next(item for item in revealed["parameters"] if item["name"] == "known_password")
        masked_password = next(item for item in masked["parameters"] if item["name"] == "known_password")
        self.assertEqual(code, 0)
        self.assertIn("PENPAL_CLI_SECRET (available)", output)
        self.assertNotIn(secret, output)
        self.assertEqual(masked_password["value"], "<sensitive>")
        self.assertEqual(password["value"], secret)
        self.assertNotIn(secret, stored)

    def test_scope_commands_explain_allowed_and_blocked_hosts(self) -> None:
        with TemporaryDirectory() as temp_dir:
            configured = run_json(
                [
                    "--workspace",
                    temp_dir,
                    "scope",
                    "set",
                    "--include",
                    "10.10.10.0/24",
                    "--exclude",
                    "10.10.10.9",
                    "--json",
                ]
            )
            allowed = run_json(["--workspace", temp_dir, "scope", "check", "10.10.10.5", "--json"])

            stdout = StringIO()
            with redirect_stdout(stdout):
                code = main(["--workspace", temp_dir, "scope", "check", "10.10.10.9", "--json"])
            blocked = json.loads(stdout.getvalue())

        self.assertTrue(configured["enforced"])
        self.assertTrue(allowed["allowed"])
        self.assertEqual(allowed["matched_include"], "10.10.10.0/24")
        self.assertEqual(code, 2)
        self.assertFalse(blocked["allowed"])
        self.assertEqual(blocked["matched_exclude"], "10.10.10.9")

    def test_json_commands_preserve_contract_shapes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(__file__).resolve().parents[1]
            playbooks = root / "playbooks"
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="demo")
            workspace.merge_services(target.name, parse_nmap_xml(root / "examples" / "pi" / "demo-nmap.xml"))
            workspace.append_evidence(
                target.name,
                extract_evidence(RAW_SNMP_OUTPUT, source="snmpwalk-smoke", service_key="udp/161").evidence,
            )

            context = run_json(["--workspace", temp_dir, "context", target.name, "--playbooks", str(playbooks)])
            evidence = run_json(["--workspace", temp_dir, "evidence", target.name, "--json"])
            suggestions = run_json(
                ["--workspace", temp_dir, "suggest", target.name, "--playbooks", str(playbooks), "--json"]
            )

        self.assertEqual(context["schema"], "penpal-context-v1")
        self.assertEqual(
            [(item["protocol"], item["port"], item["name"]) for item in context["services"]],
            [("tcp", 143, "imap"), ("tcp", 3389, "ms-wbt-server"), ("udp", 161, "snmp")],
        )
        self.assertEqual(
            [(item["type"], item["value"]) for item in evidence["evidence"]],
            [
                ("domain", "example.local"),
                ("email", "daniel@example.local"),
                ("hostname", "mail01.example.local"),
                ("interesting_file", "/backup.zip"),
                ("username", "daniel"),
                ("web_path", "/backup.zip"),
            ],
        )
        self.assertEqual(
            [item["id"] for item in suggestions["suggestions"]],
            [
                "path_snmp_mail_remote",
                "usernames_to_mail",
                "review_web_paths",
                "review_interesting_files",
                "playbook_snmp-mail-remote",
            ],
        )

    def test_modules_plan_json_renders_source_backed_syntax(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="module-box")
            workspace.merge_services(target.name, [Service(port=161, protocol="udp", name="snmp")])
            workspace.set_parameter(target.name, "community", "public")

            listed = run_json(["--workspace", temp_dir, "modules", "list", "--json"])
            planned = run_json(["--workspace", temp_dir, "modules", "plan", target.name, "snmp", "--json"])

        self.assertIn("snmp", [module["name"] for module in listed["modules"]])
        self.assertEqual(planned["module"]["name"], "snmp")
        self.assertTrue(planned["matched_services"])
        self.assertEqual(
            [command["id"] for command in planned["commands"]],
            ["snmp-nmap-info", "snmp-community-check", "snmp-walk"],
        )
        walk = next(command for command in planned["commands"] if command["id"] == "snmp-walk")
        self.assertIn("public", walk["args"])
        self.assertEqual(walk["source_tier"], "internal")

    def test_suggest_explains_playbook_matches(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="chain")
            workspace.merge_services(
                target.name,
                [
                    Service(port=161, protocol="udp", name="snmp"),
                    Service(port=143, protocol="tcp", name="imap"),
                    Service(port=3389, protocol="tcp", name="ms-wbt-server"),
                ],
            )

            playbooks = Path(__file__).resolve().parents[1] / "playbooks"
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = main(["--workspace", temp_dir, "suggest", target.name, "--playbooks", str(playbooks)])

        output = stdout.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("Why this fired:", output)
        self.assertIn("- service: udp/161 snmp", output)
        self.assertIn("- service_any: tcp/143 imap", output)

    def test_evidence_masks_sensitive_values_unless_revealed(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="chain")
            workspace.append_evidence(
                target.name,
                extract_evidence("password=Winter2024!\n", source="note").evidence,
            )

            masked = run_json(["--workspace", temp_dir, "evidence", target.name, "--json"])
            revealed = run_json(["--workspace", temp_dir, "evidence", target.name, "--json", "--reveal-secrets"])

        self.assertEqual(masked["evidence"][0]["value"], "<sensitive>")
        self.assertEqual(revealed["evidence"][0]["value"], "Winter2024!")

    def test_sources_list_json(self) -> None:
        seeds = {
            "schema": "penpal-source-seeds-v1",
            "seeds": [
                {
                    "id": "nmap",
                    "name": "Nmap official documentation",
                    "tier": "official",
                    "status": "verified",
                    "areas": ["network-scanning"],
                    "seed_urls": ["https://nmap.org/docs.html"],
                    "allowed_domains": ["nmap.org"],
                    "extract": ["command_syntax"],
                }
            ],
        }
        with TemporaryDirectory() as temp_dir:
            seeds_path = Path(temp_dir) / "SOURCE_SEEDS.json"
            seeds_path.write_text(json.dumps(seeds), encoding="utf-8")

            data = run_json(["--workspace", temp_dir, "sources", "list", "--seeds", str(seeds_path), "--json"])

        self.assertEqual(data["sources"][0]["id"], "nmap")

    def test_sources_reviewed_json(self) -> None:
        facts = {
            "schema": "penpal-reviewed-source-facts-v1",
            "facts": [
                {
                    "id": "nmap-safe-fact",
                    "source_id": "nmap",
                    "source_tier": "official",
                    "source_url": "https://nmap.org/book/man.html",
                    "fact_type": "workflow",
                    "summary": "Reviewed facts are small cited units that can later feed evals or playbooks.",
                    "review_status": "reviewed",
                    "safety": "evidence_only",
                }
            ],
        }
        with TemporaryDirectory() as temp_dir:
            facts_path = Path(temp_dir) / "SOURCE_FACTS.json"
            facts_path.write_text(json.dumps(facts), encoding="utf-8")

            data = run_json(["--workspace", temp_dir, "sources", "reviewed", "--facts", str(facts_path), "--json"])

        self.assertEqual(data["facts"][0]["id"], "nmap-safe-fact")


def run_json(args: list[str]) -> dict:
    stdout = StringIO()
    with redirect_stdout(stdout):
        code = main(args)
    if code != 0:
        raise AssertionError(f"expected exit 0, got {code}: {stdout.getvalue()}")
    return json.loads(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
