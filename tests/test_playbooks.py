from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from penpal.playbooks import extract_penpal_blocks, scan_notes_vault


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


if __name__ == "__main__":
    unittest.main()
