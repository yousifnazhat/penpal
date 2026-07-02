import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from penpal.context import build_context
from penpal.ingest import extract_evidence
from penpal.models import Service
from penpal.nmap_parser import parse_nmap_xml
from penpal.workspace import Workspace


RAW_SNMP_OUTPUT = """SNMPv2-MIB::sysName.0 = STRING: mail01.example.local
User: daniel
email: daniel@example.local
/backup.zip Status: 200, Size: 9001
"""


class ContractFixtureTests(unittest.TestCase):
    def test_demo_context_contract_stays_stable(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="demo")
            root = Path(__file__).resolve().parents[1]
            workspace.merge_services(target.name, parse_nmap_xml(root / "examples" / "pi" / "demo-nmap.xml"))
            workspace.append_evidence(
                target.name,
                extract_evidence(RAW_SNMP_OUTPUT, source="snmpwalk-smoke", service_key="udp/161").evidence,
            )

            context = build_context(workspace, target.name, playbooks_path=str(root / "playbooks"))

        self.assertEqual(
            set(context),
            {"schema", "target", "services", "evidence", "parameters", "suggestions", "summary"},
        )
        self.assertEqual(context["schema"], "penpal-context-v1")
        self.assertEqual(set(context["target"]), {"name", "host", "created_at", "updated_at", "tags", "notes"})
        self.assertEqual(
            set(context["services"][0]),
            {"port", "protocol", "state", "name", "product", "version", "extrainfo", "tunnel", "scripts"},
        )
        self.assertEqual(
            set(context["evidence"][0]),
            {"id", "type", "value", "source", "created_at", "confidence", "service_key", "context", "tags", "metadata"},
        )
        self.assertEqual(
            set(context["suggestions"][0]),
            {"id", "title", "reason", "confidence", "value", "risk", "supporting_facts", "next_actions", "command_examples", "metadata"},
        )

        self.assertEqual(
            [(item["protocol"], item["port"], item["name"]) for item in context["services"]],
            [("tcp", 143, "imap"), ("tcp", 3389, "ms-wbt-server"), ("udp", 161, "snmp")],
        )
        self.assertEqual(
            [(item["type"], item["value"]) for item in context["evidence"]],
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
            [item["id"] for item in context["suggestions"]],
            [
                "path_snmp_mail_remote",
                "usernames_to_mail",
                "review_web_paths",
                "review_interesting_files",
                "playbook_snmp-mail-remote",
            ],
        )

    def test_masked_context_contract_never_leaks_sensitive_values(self) -> None:
        secret = "Winter2024!"
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="demo")
            workspace.merge_services(target.name, [Service(port=3389, protocol="tcp", name="ms-wbt-server")])
            workspace.append_evidence(
                target.name,
                extract_evidence(f"User: daniel\npassword={secret}\n", source="operator-note").evidence,
            )
            workspace.set_parameter(target.name, "known_user", "daniel")
            workspace.set_parameter(target.name, "known_password", secret, sensitive=True)

            context = build_context(workspace, target.name)

        body = json.dumps(context)
        credential = next(item for item in context["evidence"] if item["type"] == "credential_candidate")
        password_param = next(item for item in context["parameters"] if item["name"] == "known_password")
        remote = next(item for item in context["suggestions"] if item["id"] == "credentials_to_remote")

        self.assertNotIn(secret, body)
        self.assertEqual(credential["value"], "<sensitive>")
        self.assertEqual(credential["context"], "<sensitive>")
        self.assertEqual(password_param["value"], "<sensitive>")
        self.assertIn(
            "xfreerdp /v:10.10.10.5 /u:daniel /p:<known_password> /cert:ignore",
            remote["command_examples"],
        )


if __name__ == "__main__":
    unittest.main()
