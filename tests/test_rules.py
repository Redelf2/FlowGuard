"""The rule catalog is data. These tests do not claim detection works."""

from __future__ import annotations

import unittest

from flowguard.rules import RULES, get_rule


class RuleCatalogTests(unittest.TestCase):
    def test_initial_rules_have_stable_ids_and_severities(self) -> None:
        self.assertEqual([rule.rule_id for rule in RULES], ["FG001", "FG002"])
        self.assertEqual(get_rule("FG001").severity, "medium")
        self.assertEqual(get_rule("FG002").severity, "high")

    def test_exposure_rule_lists_configured_sources_and_sinks(self) -> None:
        rule = get_rule("FG001")

        self.assertIn("os.getenv", rule.sources)
        self.assertIn("os.environ.get", rule.sources)
        self.assertIn("print", rule.sinks)
        self.assertIn("logging.info", rule.sinks)
        self.assertIn("potential", rule.explanation.lower())

    def test_command_rule_lists_input_and_subprocess(self) -> None:
        rule = get_rule("FG002")

        self.assertIn("input", rule.sources)
        self.assertIn("subprocess.run", rule.sinks)
        self.assertIn("os.system", rule.sinks)
        self.assertIn("shell=True", rule.explanation)

    def test_every_rule_includes_a_fix_and_a_limit(self) -> None:
        for rule in RULES:
            self.assertTrue(rule.recommended_fix.strip())
            self.assertIn("does not prove", rule.limitation)

    def test_unknown_rule_id_is_rejected(self) -> None:
        with self.assertRaises(KeyError):
            get_rule("FG999")


if __name__ == "__main__":
    unittest.main()
