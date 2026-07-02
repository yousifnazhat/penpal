from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest
from unittest.mock import patch

from penpal.sources import (
    DEFAULT_FACTS_PATH,
    fetch_source_seed,
    find_source_seed,
    load_reviewed_source_facts,
    load_source_seeds,
)


SEEDS = {
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
            "extract": ["command_syntax", "workflow"],
        }
    ],
}


class SourceTests(unittest.TestCase):
    def test_load_and_find_source_seed(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = _write_seeds(temp_dir)

            seeds = load_source_seeds(path)
            seed = find_source_seed("nmap", path)

        self.assertEqual(seeds[0]["id"], "nmap")
        self.assertEqual(seed["name"], "Nmap official documentation")

    def test_find_source_seed_rejects_unknown_id(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = _write_seeds(temp_dir)

            with self.assertRaisesRegex(ValueError, "source seed not found"):
                find_source_seed("missing", path)

    def test_shipped_reviewed_source_facts_are_reviewed_and_cited(self) -> None:
        facts = load_reviewed_source_facts(DEFAULT_FACTS_PATH, source_id="nmap")

        self.assertEqual([fact["source_id"] for fact in facts], ["nmap", "nmap", "nmap"])
        self.assertEqual({fact["review_status"] for fact in facts}, {"reviewed"})
        self.assertTrue(all(fact["source_url"].startswith("https://") for fact in facts))

    def test_reviewed_source_facts_reject_candidate_status(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "SOURCE_FACTS.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "penpal-reviewed-source-facts-v1",
                        "facts": [
                            {
                                "id": "candidate-fact",
                                "source_id": "nmap",
                                "source_tier": "official",
                                "source_url": "https://nmap.org/book/man.html",
                                "fact_type": "workflow",
                                "summary": "Candidate facts must not enter the reviewed fact set.",
                                "review_status": "candidate",
                                "safety": "evidence_only",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "not reviewed"):
                load_reviewed_source_facts(path)

    def test_fetch_source_seed_caches_raw_page_and_extracts_tiny_facts(self) -> None:
        html = b"""
        <html>
          <head><title>Nmap Docs</title></head>
          <body>
            <h1>Nmap Workflow</h1>
            <code>nmap -sV &lt;target&gt;</code>
            <code>echo not a command fact</code>
          </body>
        </html>
        """
        with TemporaryDirectory() as temp_dir:
            seeds_path = _write_seeds(temp_dir)
            cache_dir = Path(temp_dir) / "cache"
            with patch("penpal.sources.urlopen", return_value=FakeResponse(html)):
                result = fetch_source_seed("nmap", seeds_path=seeds_path, cache_dir=cache_dir)

            data = result.to_dict()
            cache_path = Path(data["cache_path"])
            cached = cache_path.read_bytes()

        self.assertEqual(data["schema"], "penpal-source-fetch-v1")
        self.assertEqual(data["source"]["id"], "nmap")
        self.assertEqual(data["final_url"], "https://nmap.org/docs.html")
        self.assertTrue(cache_path.name.endswith(".html"))
        self.assertEqual(cached, html)
        self.assertIn({"type": "page_title", "value": "Nmap Docs", "source_url": "https://nmap.org/docs.html"}, data["facts"])
        self.assertIn(
            {
                "type": "workflow_heading",
                "value": "Nmap Workflow",
                "source_url": "https://nmap.org/docs.html",
                "review_status": "candidate",
            },
            data["facts"],
        )
        self.assertIn(
            {
                "type": "command_syntax",
                "value": "nmap -sV <target>",
                "source_url": "https://nmap.org/docs.html",
                "review_status": "candidate",
            },
            data["facts"],
        )
        self.assertNotIn("echo not a command fact", {fact["value"] for fact in data["facts"]})

    def test_fetch_source_seed_rejects_unlisted_url(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = _write_seeds(temp_dir)

            with self.assertRaisesRegex(ValueError, "url is not listed"):
                fetch_source_seed("nmap", url="https://nmap.org/book/", seeds_path=path, cache_dir=Path(temp_dir) / "cache")

    def test_fetch_source_seed_rejects_redirect_outside_allowed_domain(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = _write_seeds(temp_dir)
            with patch(
                "penpal.sources.urlopen",
                return_value=FakeResponse(b"<title>Moved</title>", final_url="https://example.com/docs.html"),
            ):
                with self.assertRaisesRegex(ValueError, "not allowed"):
                    fetch_source_seed("nmap", seeds_path=path, cache_dir=Path(temp_dir) / "cache")


class FakeResponse:
    status = 200
    headers = {"Content-Type": "text/html; charset=utf-8"}

    def __init__(self, body: bytes, final_url: str = "https://nmap.org/docs.html") -> None:
        self.body = body
        self.final_url = final_url

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]

    def geturl(self) -> str:
        return self.final_url


def _write_seeds(temp_dir: str) -> Path:
    path = Path(temp_dir) / "SOURCE_SEEDS.json"
    path.write_text(json.dumps(SEEDS), encoding="utf-8")
    return path


if __name__ == "__main__":
    unittest.main()
