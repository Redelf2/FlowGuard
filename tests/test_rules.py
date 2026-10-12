"""Tests for the planned security rules.

The rule text is part of the project plan. Applying the rules is not
implemented, so these tests only check the plan and that boundary.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flowguard.rules import PLANNED_RULES, apply_rules


class PlannedRuleTests(unittest.TestCase):
    def test_initial_rules_are_documented(self) -> None:
        self.assertEqual(
            [(rule.rule_id, rule.title) for rule in PLANNED_RULES],
            [
                ("FG001", "Potential sensitive-data exposure"),
                ("FG002", "Potential command injection"),
            ],
        )
        summaries = " ".join(rule.summary for rule in PLANNED_RULES)
        self.assertIn("os.getenv", summaries)
        self.assertIn("subprocess.run", summaries)

    def test_rules_are_not_applied_yet(self) -> None:
        with self.assertRaises(NotImplementedError) as caught:
            apply_rules(None)

        self.assertIn("not implemented", str(caught.exception).lower())


if __name__ == "__main__":
    unittest.main()
