import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from penpal.context import build_context
from penpal.ingest import extract_evidence
from penpal.models import Service
from penpal.workspace import Workspace


RAW_OUTPUT = """
User: daniel
password=Winter2024!
"""


class ContextTests(unittest.TestCase):
    def test_environment_parameter_context_masks_runtime_value_and_preserves_contract(self) -> None:
        secret = "Winter2024!"
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir, environment={"PENPAL_CONTEXT_SECRET": secret})
            target = workspace.create_target("10.10.10.5", name="chain")
            workspace.set_environment_parameter(target.name, "known_password", "PENPAL_CONTEXT_SECRET")

            masked = build_context(workspace, target.name)
            revealed = build_context(workspace, target.name, reveal_secrets=True)
            stored = workspace.parameters_path(target.name).read_text(encoding="utf-8")

        masked_password = next(item for item in masked["parameters"] if item["name"] == "known_password")
        revealed_password = next(item for item in revealed["parameters"] if item["name"] == "known_password")
        self.assertEqual(masked_password["value"], "<sensitive>")
        self.assertEqual(masked_password["source"], "env:PENPAL_CONTEXT_SECRET")
        self.assertEqual(revealed_password["value"], secret)
        self.assertNotIn(secret, json.dumps(masked))
        self.assertNotIn(secret, stored)

    def test_context_masks_sensitive_values_by_default(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="chain")
            workspace.merge_services(target.name, [Service(port=3389, protocol="tcp", name="ms-wbt-server")])
            workspace.append_evidence(target.name, extract_evidence(RAW_OUTPUT, source="note").evidence)
            workspace.set_parameter(target.name, "known_password", "Winter2024!", sensitive=True)

            context = build_context(workspace, target.name)

        parameters = {item["name"]: item["value"] for item in context["parameters"]}
        credential = next(item for item in context["evidence"] if item["type"] == "credential_candidate")
        remote = next(item for item in context["suggestions"] if item["id"] == "credentials_to_remote")

        self.assertEqual(context["schema"], "penpal-context-v1")
        self.assertEqual(parameters["known_password"], "<sensitive>")
        self.assertEqual(credential["value"], "<sensitive>")
        self.assertTrue(all("Winter2024!" not in fact for fact in remote["supporting_facts"]))

    def test_context_can_reveal_sensitive_values(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="chain")
            workspace.append_evidence(target.name, extract_evidence(RAW_OUTPUT, source="note").evidence)
            workspace.set_parameter(target.name, "known_password", "Winter2024!", sensitive=True)

            context = build_context(workspace, target.name, reveal_secrets=True)

        parameters = {item["name"]: item["value"] for item in context["parameters"]}
        credential = next(item for item in context["evidence"] if item["type"] == "credential_candidate")

        self.assertEqual(parameters["known_password"], "Winter2024!")
        self.assertEqual(credential["value"], "Winter2024!")

    def test_context_preserves_playbook_match_metadata(self) -> None:
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
            context = build_context(workspace, target.name, playbooks_path=str(playbooks))

        suggestion = next(item for item in context["suggestions"] if item["id"] == "playbook_snmp-mail-remote")
        metadata = suggestion["metadata"]

        self.assertEqual(metadata["source"], "playbook")
        self.assertEqual(metadata["playbook_id"], "snmp-mail-remote")
        self.assertEqual(metadata["matched_signals"][0]["facts"], ["udp/161 snmp"])
        self.assertIn("snmpwalk -v2c -c <community> 10.10.10.5", suggestion["command_examples"])


if __name__ == "__main__":
    unittest.main()
