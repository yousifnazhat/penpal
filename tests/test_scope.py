import unittest

from penpal.scope import EngagementScope, ScopeError, normalize_rule


class ScopeTests(unittest.TestCase):
    def test_unknown_storage_schema_is_rejected(self) -> None:
        with self.assertRaisesRegex(ScopeError, "unsupported engagement scope schema"):
            EngagementScope.from_dict(
                {
                    "schema": "penpal-scope-v99",
                    "includes": ["10.10.10.0/24"],
                    "excludes": [],
                }
            )

    def test_exact_cidr_wildcard_and_exclusion_rules(self) -> None:
        scope = EngagementScope.from_rules(
            ["10.10.10.5", "10.20.0.7/16", "2001:db8::/32", "portal.example.com", "*.lab.example.com"],
            ["10.20.0.9", "blocked.lab.example.com"],
        )

        self.assertTrue(scope.evaluate("10.10.10.5").allowed)
        self.assertTrue(scope.evaluate("10.20.44.8").allowed)
        self.assertTrue(scope.evaluate("2001:db8::12").allowed)
        self.assertTrue(scope.evaluate("PORTAL.EXAMPLE.COM.").allowed)
        self.assertTrue(scope.evaluate("web.lab.example.com").allowed)
        self.assertFalse(scope.evaluate("lab.example.com").allowed)
        self.assertFalse(scope.evaluate("10.20.0.9").allowed)
        self.assertFalse(scope.evaluate("blocked.lab.example.com").allowed)
        self.assertFalse(scope.evaluate("192.0.2.5").allowed)

    def test_rules_are_normalized_and_deduplicated(self) -> None:
        scope = EngagementScope.from_rules(["10.20.0.7/16", "10.20.0.0/16", "EXAMPLE.COM.", "example.com"])

        self.assertEqual(scope.includes, ("10.20.0.0/16", "example.com"))
        self.assertEqual(normalize_rule("2001:0db8::1"), "2001:db8::1")

    def test_invalid_scope_rules_are_rejected(self) -> None:
        invalid = ["", "*", "web.*.example.com", "https://example.com", "example.com/24", "*.10.10.10.5"]
        for rule in invalid:
            with self.subTest(rule=rule):
                with self.assertRaises(ScopeError):
                    EngagementScope.from_rules([rule])

        with self.assertRaisesRegex(ScopeError, "at least one include"):
            EngagementScope.from_rules([])


if __name__ == "__main__":
    unittest.main()
