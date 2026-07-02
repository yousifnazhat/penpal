import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from penpal.advisor import build_suggestions
from penpal.ingest import extract_evidence
from penpal.nmap_parser import parse_nmap_xml
from penpal.playbooks import load_playbooks
from penpal.sources import DEFAULT_FACTS_PATH, load_reviewed_source_facts
from penpal.workspace import Workspace


ROOT = Path(__file__).resolve().parents[1]
EVALS_PATH = ROOT / "docs" / "EVAL_CASES.json"


class EvalCaseTests(unittest.TestCase):
    def test_source_backed_eval_cases_preserve_expected_suggestions(self) -> None:
        evals = json.loads(EVALS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(evals["schema"], "penpal-eval-cases-v1")
        source_fact_ids = {fact["id"] for fact in load_reviewed_source_facts(DEFAULT_FACTS_PATH)}

        for case in evals["cases"]:
            with self.subTest(case=case["id"]):
                missing = set(case["source_fact_ids"]) - source_fact_ids
                self.assertEqual(missing, set())
                suggestions = _run_case(case)
                suggestion_ids = [suggestion.id for suggestion in suggestions]

                self.assertEqual(
                    suggestion_ids[: len(case["expected_top_suggestion_ids"])],
                    case["expected_top_suggestion_ids"],
                )
                for suggestion_id in case["required_suggestion_ids"]:
                    self.assertIn(suggestion_id, suggestion_ids)

                commands = "\n".join(command for suggestion in suggestions for command in suggestion.command_examples)
                for fragment in case["forbidden_command_fragments"]:
                    self.assertNotIn(fragment, commands)


def _run_case(case: dict) -> list:
    with TemporaryDirectory() as temp_dir:
        workspace = Workspace(temp_dir)
        target = workspace.create_target(case["target"]["host"], name=case["target"]["name"])
        workspace.merge_services(target.name, parse_nmap_xml(ROOT / case["nmap_xml"]))
        evidence = case.get("evidence")
        if evidence:
            workspace.append_evidence(
                target.name,
                extract_evidence(
                    evidence["text"],
                    source=evidence["source"],
                    service_key=evidence["service"],
                ).evidence,
            )
        return build_suggestions(
            workspace.load_services(target.name),
            workspace.load_evidence(target.name),
            target_host=target.host,
            target_name=target.name,
            playbooks=load_playbooks(ROOT / "playbooks"),
        )


if __name__ == "__main__":
    unittest.main()
