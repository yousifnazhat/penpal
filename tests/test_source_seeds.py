import json
import unittest

from penpal.sources import DEFAULT_SEEDS_PATH


class SourceSeedTests(unittest.TestCase):
    def test_source_seeds_are_well_formed(self) -> None:
        data = json.loads(DEFAULT_SEEDS_PATH.read_text(encoding="utf-8"))

        self.assertEqual(data["schema"], "penpal-source-seeds-v1")
        seen_ids: set[str] = set()
        for seed in data["seeds"]:
            self.assertNotIn(seed["id"], seen_ids)
            seen_ids.add(seed["id"])
            self.assertIn(seed["tier"], {"official", "methodology", "community", "internal"})
            self.assertTrue(seed["seed_urls"])
            self.assertTrue(seed["allowed_domains"])
            self.assertTrue(seed["extract"])
            for url in seed["seed_urls"]:
                self.assertTrue(url.startswith("https://"))


if __name__ == "__main__":
    unittest.main()
