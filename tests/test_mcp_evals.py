from pathlib import Path
import xml.etree.ElementTree as ET
import unittest


class McpEvaluationTests(unittest.TestCase):
    def test_evaluations_are_well_formed_and_complete(self) -> None:
        path = Path(__file__).parent / "fixtures" / "mcp" / "evaluations.xml"
        pairs = ET.parse(path).getroot().findall("qa_pair")

        self.assertEqual(len(pairs), 10)
        self.assertTrue(all((pair.findtext("question") or "").strip() for pair in pairs))
        self.assertTrue(all((pair.findtext("answer") or "").strip() for pair in pairs))


if __name__ == "__main__":
    unittest.main()
