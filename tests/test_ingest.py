from tempfile import TemporaryDirectory
import unittest

from penpal.advisor import build_suggestions
from penpal.ingest import extract_evidence
from penpal.models import Service
from penpal.workspace import Workspace


RAW_OUTPUT = """
SNMPv2-MIB::sysName.0 = STRING: mail01.example.local
User: daniel
email: daniel@example.local
password=Winter2024!
/admin                 Status: 200, Size: 1234
/backup.zip            Status: 200, Size: 9001
"""


class IngestTests(unittest.TestCase):
    def test_extract_evidence_from_raw_output(self) -> None:
        result = extract_evidence(RAW_OUTPUT, source="snmpwalk", service_key="udp/161")
        values = {(item.type, item.value) for item in result.evidence}

        self.assertIn(("hostname", "mail01.example.local"), values)
        self.assertIn(("username", "daniel"), values)
        self.assertIn(("email", "daniel@example.local"), values)
        self.assertIn(("credential_candidate", "Winter2024!"), values)
        self.assertIn(("web_path", "/admin"), values)
        self.assertIn(("interesting_file", "/backup.zip"), values)
        self.assertNotIn(("hostname", "backup.zip"), values)

    def test_workspace_ingest_and_suggest(self) -> None:
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
            extracted = extract_evidence(RAW_OUTPUT, source="snmpwalk", service_key="udp/161")
            evidence = workspace.append_evidence(target.name, extracted.evidence)
            workspace.set_parameter(target.name, "community", "public")
            workspace.set_parameter(target.name, "known_user", "daniel")
            workspace.set_parameter(target.name, "known_password", "Winter2024!", sensitive=True)
            suggestions = build_suggestions(
                workspace.load_services(target.name),
                evidence,
                target_host=target.host,
                target_name=target.name,
                parameters=workspace.load_parameters(target.name),
            )
            revealed_suggestions = build_suggestions(
                workspace.load_services(target.name),
                evidence,
                target_host=target.host,
                target_name=target.name,
                parameters=workspace.load_parameters(target.name),
                reveal_secrets=True,
            )

        self.assertTrue(any(suggestion.id == "path_snmp_mail_remote" for suggestion in suggestions))
        self.assertTrue(any(suggestion.id == "credentials_to_remote" for suggestion in suggestions))
        snmp_path = next(suggestion for suggestion in suggestions if suggestion.id == "path_snmp_mail_remote")
        self.assertIn("snmpwalk -v2c -c public 10.10.10.5", snmp_path.command_examples)
        masked_remote = next(suggestion for suggestion in suggestions if suggestion.id == "credentials_to_remote")
        self.assertTrue(all("Winter2024!" not in fact for fact in masked_remote.supporting_facts))
        self.assertIn(
            "xfreerdp /v:10.10.10.5 /u:daniel /p:<known_password> /cert:ignore", masked_remote.command_examples
        )
        revealed_remote = next(
            suggestion for suggestion in revealed_suggestions if suggestion.id == "credentials_to_remote"
        )
        self.assertTrue(any("Winter2024!" in fact for fact in revealed_remote.supporting_facts))
        self.assertIn("xfreerdp /v:10.10.10.5 /u:daniel /p:Winter2024! /cert:ignore", revealed_remote.command_examples)


if __name__ == "__main__":
    unittest.main()
