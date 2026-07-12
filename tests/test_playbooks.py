from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import json
import re

from penpal.advisor import build_suggestions
from penpal.models import Service
from penpal.playbooks import (
    extract_penpal_blocks,
    find_playbook,
    format_playbook,
    load_playbooks,
    scan_notes_vault,
    scan_playbooks,
    validate_playbook,
)


NOTE = """---
source: htb_academy
penpal:
  schema: penpal-note-v1
---

# HTB Academy - Example

<!-- penpal:methodology:start -->
```json
{
  "schema": "penpal-methodology-v1",
  "topic": "example",
  "commands": []
}
```
<!-- penpal:methodology:end -->

<!-- penpal:evidence_rules:start -->
```json
[
  {
    "schema": "penpal-evidence-rules-v1",
    "type": "hostname"
  }
]
```
<!-- penpal:evidence_rules:end -->
"""

PLAYBOOK = {
    "schema": "penpal-playbook-v1",
    "id": "snmp-mail-remote",
    "title": "SNMP to mail to remote access",
    "description": "Use SNMP output to guide authorized mail and remote access checks.",
    "tags": ["snmp", "mail", "remote-access"],
    "signals": [{"type": "service", "protocol": "udp", "port": 161}],
    "actions": [
        {
            "id": "snmpwalk",
            "description": "Collect SNMP output when a community string is known.",
            "risk": "normal",
            "commands": ["snmpwalk -v2c -c <community> <target_host>"],
        }
    ],
    "safety": {
        "authorized_use_only": True,
        "requires_operator_approval": True,
    },
}


class PlaybookNoteTests(unittest.TestCase):
    def test_extract_fenced_penpal_blocks(self) -> None:
        blocks = extract_penpal_blocks(NOTE, "example.md")

        self.assertEqual(len(blocks), 2)
        self.assertTrue(all(block.ok for block in blocks))
        self.assertEqual(blocks[0].kind, "methodology")
        self.assertEqual(blocks[0].data["topic"], "example")
        self.assertEqual(blocks[1].kind, "evidence_rules")

    def test_scan_notes_vault_counts_penpal_notes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            vault = Path(temp_dir)
            (vault / "Example.md").write_text(NOTE, encoding="utf-8")
            (vault / ".obsidian").mkdir()
            (vault / ".obsidian" / "Ignored.md").write_text(NOTE, encoding="utf-8")
            (vault / "Plain.md").write_text("# Plain\n", encoding="utf-8")

            report = scan_notes_vault(vault)

        self.assertEqual(report.markdown_files, 2)
        self.assertEqual(report.penpal_notes, 1)
        self.assertEqual(report.methodology_blocks, 1)
        self.assertEqual(report.evidence_rule_blocks, 1)
        self.assertEqual(report.errors, [])

    def test_invalid_json_is_reported(self) -> None:
        note = """<!-- penpal:methodology:start -->
```json
{"schema": "penpal-methodology-v1",
```
<!-- penpal:methodology:end -->
"""

        blocks = extract_penpal_blocks(note, "broken.md")

        self.assertEqual(len(blocks), 1)
        self.assertFalse(blocks[0].ok)
        self.assertIn("invalid JSON", blocks[0].error)

    def test_evidence_rule_arrays_do_not_need_repeated_schema(self) -> None:
        note = """<!-- penpal:evidence_rules:start -->
```json
[
  {
    "type": "web_path",
    "pattern": "/admin",
    "source": "robots_txt"
  }
]
```
<!-- penpal:evidence_rules:end -->
"""

        blocks = extract_penpal_blocks(note, "rules.md")

        self.assertEqual(len(blocks), 1)
        self.assertTrue(blocks[0].ok)
        self.assertEqual(blocks[0].data[0]["type"], "web_path")


class CommunityPlaybookTests(unittest.TestCase):
    def test_valid_playbook_schema(self) -> None:
        self.assertEqual(validate_playbook(PLAYBOOK), "")

    def test_playbook_requires_operator_approval(self) -> None:
        playbook = dict(PLAYBOOK)
        playbook["safety"] = {"authorized_use_only": True}

        self.assertIn("requires_operator_approval", validate_playbook(playbook))

    def test_playbook_rejects_unknown_signal_type(self) -> None:
        playbook = dict(PLAYBOOK)
        playbook["signals"] = [{"type": "magic"}]

        self.assertIn("type must be", validate_playbook(playbook))

    def test_scan_playbook_directory(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "snmp-mail-remote.json").write_text(json.dumps(PLAYBOOK), encoding="utf-8")
            (root / ".ignored").mkdir()
            (root / ".ignored" / "bad.json").write_text("{", encoding="utf-8")

            report = scan_playbooks(root)

        self.assertEqual(report.json_files, 1)
        self.assertEqual(report.valid_playbooks, 1)
        self.assertEqual(report.errors, [])

    def test_scan_playbook_errors_point_to_authoring_docs(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "bad.json").write_text(json.dumps({"schema": "wrong"}), encoding="utf-8")

            report = scan_playbooks(root)

        self.assertIn("expected schema", report.errors[0].error)
        self.assertIn("see playbooks/README.md", report.errors[0].error)

    def test_shipped_playbooks_validate(self) -> None:
        root = Path(__file__).resolve().parents[1] / "playbooks"
        report = scan_playbooks(root)

        self.assertGreaterEqual(report.valid_playbooks, 4)
        self.assertEqual(report.errors, [])
        self.assertNotIn("TEMPLATE.md", {playbook.path for playbook in report.playbooks})

    def test_template_markdown_contains_valid_playbook_json(self) -> None:
        path = Path(__file__).resolve().parents[1] / "playbooks" / "TEMPLATE.md"
        match = re.search(r"```json\s*(?P<body>[\s\S]*?)\s*```", path.read_text(encoding="utf-8"))

        self.assertIsNotNone(match)
        playbook = json.loads(match.group("body"))
        self.assertEqual(validate_playbook(playbook), "")

    def test_load_playbooks_rejects_invalid_playbook(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "bad.json").write_text(json.dumps({"schema": "wrong"}), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_playbooks(root)

    def test_default_playbooks_fall_back_to_installed_data(self) -> None:
        installed_entry = unittest.mock.Mock()
        installed_entry.parts = ("..", "share", "penpal", "playbooks", "snmp-mail-remote.json")
        installed_entry.locate.return_value = Path("/installed/share/penpal/playbooks/snmp-mail-remote.json")
        installed_distribution = unittest.mock.Mock(files=[installed_entry])

        with (
            patch("penpal.playbooks.Path.exists", return_value=False),
            patch("penpal.playbooks.distribution", return_value=installed_distribution) as distribution_lookup,
        ):
            from penpal.playbooks import _resolve_playbook_path

            resolved = _resolve_playbook_path("playbooks")

        self.assertEqual(resolved, Path("/installed/share/penpal/playbooks"))
        distribution_lookup.assert_called_once_with("penpal-enum")

    def test_find_and_format_playbook(self) -> None:
        playbook = find_playbook([PLAYBOOK], "snmp-mail-remote")
        rendered = format_playbook(playbook)

        self.assertIn("SNMP to mail to remote access (snmp-mail-remote)", rendered)
        self.assertIn("service udp 161", rendered)
        self.assertIn("authorized_use_only: true", rendered)

    def test_playbook_can_generate_suggestion(self) -> None:
        suggestions = build_suggestions(
            [
                Service(port=161, protocol="udp", name="snmp"),
                Service(port=143, protocol="tcp", name="imap"),
                Service(port=3389, protocol="tcp", name="ms-wbt-server"),
            ],
            [],
            target_host="10.10.10.5",
            target_name="chain",
            playbooks=[PLAYBOOK],
        )

        suggestion = next(item for item in suggestions if item.id == "playbook_snmp-mail-remote")
        self.assertEqual(suggestion.value, "high")
        self.assertIn("udp/161 snmp", suggestion.supporting_facts)
        self.assertIn("snmpwalk -v2c -c <community> 10.10.10.5", suggestion.command_examples)
        self.assertEqual(suggestion.metadata["source"], "playbook")
        self.assertEqual(suggestion.metadata["playbook_id"], "snmp-mail-remote")
        self.assertEqual(suggestion.metadata["matched_signals"][0]["facts"], ["udp/161 snmp"])

    def test_shipped_playbooks_generate_multiple_suggestions(self) -> None:
        root = Path(__file__).resolve().parents[1] / "playbooks"
        suggestions = build_suggestions(
            [
                Service(port=80, protocol="tcp", name="http"),
                Service(port=139, protocol="tcp", name="netbios-ssn"),
                Service(port=445, protocol="tcp", name="microsoft-ds"),
                Service(port=389, protocol="tcp", name="ldap"),
            ],
            [],
            target_host="10.10.10.5",
            target_name="chain",
            playbooks=load_playbooks(root),
        )

        ids = {suggestion.id for suggestion in suggestions}
        self.assertIn("playbook_http-vhosts-hidden-apps", ids)
        self.assertIn("playbook_smb-shares-configs-credentials", ids)
        self.assertIn("playbook_ldap-kerberos-ad-context", ids)


if __name__ == "__main__":
    unittest.main()
