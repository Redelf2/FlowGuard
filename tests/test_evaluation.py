"""The labeled corpus measures detection and false positives.

Unsupported samples are excluded from both rates. Nothing in this file
executes the samples.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

from flowguard.evaluate import LABELED_CASES, evaluate_corpus, format_evaluation

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "flowguard.py"


class EvaluationTests(unittest.TestCase):
    def test_labeled_cases_use_only_the_three_scores(self) -> None:
        labels = {case.label for case in LABELED_CASES}

        self.assertEqual(labels, {"vulnerable", "safe", "unsupported"})
        for case in LABELED_CASES:
            file_path = ROOT / case.relative_path
            self.assertTrue(file_path.is_file(), case.relative_path)
            if case.label == "vulnerable":
                self.assertTrue(case.expected_rules)
            else:
                self.assertEqual(case.expected_rules, ())

    def test_corpus_detection_and_false_positive_rates(self) -> None:
        report = evaluate_corpus(ROOT)

        self.assertEqual(report.vulnerable_files, 13)
        self.assertEqual(report.safe_files, 12)
        self.assertEqual(report.unsupported_files, 6)
        self.assertEqual(report.missed, ())
        self.assertEqual(report.false_positives, ())
        self.assertEqual(report.unexpected_unsupported, ())
        self.assertEqual(report.detection_rate, 1.0)
        self.assertEqual(report.false_positive_rate, 0.0)
        self.assertGreaterEqual(report.elapsed_seconds, 0.0)

    def test_evaluation_does_not_execute_the_marker_sample(self) -> None:
        marker = ROOT / "flowguard_eval_marker.txt"
        if marker.exists():
            marker.unlink()

        evaluate_corpus(ROOT)

        self.assertFalse(marker.exists())

    def test_text_report_states_both_rates(self) -> None:
        text = format_evaluation(evaluate_corpus(ROOT))

        self.assertIn("Detection rate: 100.0%", text)
        self.assertIn("False-positive rate: 0.0%", text)
        self.assertIn("not scored", text)

    def test_evaluate_command_exits_successfully(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(CLI), "--evaluate"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Detection rate: 100.0%", completed.stdout)
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
