import json
from pathlib import Path
import unittest

from penpal.ingest import extract_evidence


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "ingest"


class IngestFixtureTests(unittest.TestCase):
    def test_realistic_tool_output_preserves_expected_evidence_and_rejects_known_noise(self) -> None:
        corpus = json.loads((FIXTURES_DIR / "cases.json").read_text(encoding="utf-8"))
        self.assertEqual(corpus["schema"], "penpal-ingest-fixtures-v1")

        for case in corpus["cases"]:
            with self.subTest(case=case["id"]):
                text = (FIXTURES_DIR / case["fixture"]).read_text(encoding="utf-8")
                evidence = extract_evidence(
                    text,
                    source=case["source"],
                    service_key=case["service_key"],
                ).evidence
                values = {(item.type, item.value) for item in evidence}
                expected = set(map(tuple, case["expected"]))
                forbidden = set(map(tuple, case["forbidden"]))

                self.assertEqual(expected - values, set())
                self.assertEqual(forbidden & values, set())


if __name__ == "__main__":
    unittest.main()
