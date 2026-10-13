"""Rule definitions and the findings those rules can produce.

A finding means a tracked path matched a rule. It does not mean the program
was executed or that the flow is exploitable.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from flowguard.parser import parse_file, parse_source
from flowguard.rules import RULES, apply_rules, get_rule

SAMPLES = Path(__file__).resolve().parent / "samples"


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


class FindingTests(unittest.TestCase):
    def test_secret_sample_reaches_print(self) -> None:
        findings = apply_rules(parse_file(SAMPLES / "vulnerable_secret.py"))

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "FG001")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.source, "os.getenv")
        self.assertEqual(finding.source_line, 9)
        self.assertEqual(finding.sink, "print")
        self.assertEqual(finding.sink_line, 11)
        self.assertEqual(finding.path, ("secret", "backup", "print"))
        self.assertEqual(finding.confidence, "limited")
        self.assertIn("does not prove", finding.limitation)

    def test_command_sample_reaches_subprocess_with_shell(self) -> None:
        findings = apply_rules(parse_file(SAMPLES / "vulnerable_command.py"))

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "FG002")
        self.assertEqual(finding.path, ("user_input", "subprocess.run"))
        self.assertEqual(finding.confidence, "increased")
        self.assertIn("shell=True", finding.explanation)

    def test_safe_sample_does_not_treat_print_as_a_sink_for_secret(self) -> None:
        findings = apply_rules(parse_file(SAMPLES / "safe_example.py"))

        self.assertEqual(findings, ())

    def test_print_after_reassignment_is_not_a_finding(self) -> None:
        source = "\n".join(
            [
                "secret = os.getenv('API_KEY')",
                "secret = 'public'",
                "print(secret)",
            ]
        )
        self.assertEqual(apply_rules(parse_source(source)), ())

    def test_print_before_reassignment_is_still_a_finding(self) -> None:
        source = "\n".join(
            [
                "secret = os.getenv('API_KEY')",
                "print(secret)",
                "secret = 'public'",
            ]
        )
        findings = apply_rules(parse_source(source))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, ("secret", "print"))
        self.assertEqual(findings[0].sink_line, 2)

    def test_another_function_with_the_same_name_is_not_the_same_value(self) -> None:
        source = "\n".join(
            [
                "def load():",
                "    secret = os.getenv('API_KEY')",
                "def show():",
                "    secret = 'public'",
                "    print(secret)",
            ]
        )
        self.assertEqual(apply_rules(parse_source(source)), ())

    def test_imported_getenv_printed_directly_is_fg001(self) -> None:
        source = "from os import getenv as read_env\nprint(read_env('API_KEY'))\n"
        findings = apply_rules(parse_source(source))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "FG001")
        self.assertEqual(findings[0].source, "os.getenv")
        self.assertEqual(findings[0].path, ("os.getenv", "print"))

    def test_parameter_named_getenv_is_not_the_import(self) -> None:
        source = "\n".join(
            [
                "from os import getenv",
                "def show(getenv):",
                "    print(getenv())",
            ]
        )
        self.assertEqual(apply_rules(parse_source(source)), ())

    def test_direct_source_call_inside_print(self) -> None:
        findings = apply_rules(parse_source("print(os.getenv('API_KEY'))\n"))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, ("os.getenv", "print"))
        self.assertEqual(findings[0].source_line, 1)

    def test_input_printed_does_not_match_either_rule(self) -> None:
        # FG001 does not treat input as a secret. FG002 does not treat print as a command.
        findings = apply_rules(parse_source("print(input())\n"))
        self.assertEqual(findings, ())

    def test_getenv_passed_to_subprocess_does_not_match_fg002(self) -> None:
        source = "subprocess.run(os.getenv('API_KEY'), shell=True)\n"
        self.assertEqual(apply_rules(parse_source(source)), ())

    def test_logging_and_os_system_use_their_configured_names(self) -> None:
        source = "\n".join(
            [
                "secret = os.getenv('API_KEY')",
                "logging.info(secret)",
                "user_input = input()",
                "os.system(user_input)",
            ]
        )
        findings = apply_rules(parse_source(source))

        self.assertEqual([item.rule_id for item in findings], ["FG001", "FG002"])
        self.assertEqual(findings[0].sink, "logging.info")
        self.assertEqual(findings[1].sink, "os.system")
        self.assertEqual(findings[1].confidence, "increased")

    def test_subprocess_without_shell_stays_a_limited_finding(self) -> None:
        source = "user_input = input()\nsubprocess.run(user_input)\n"
        findings = apply_rules(parse_source(source))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "limited")
        self.assertIn("shell=True was not seen", findings[0].explanation)

    def test_wrapper_call_is_not_reported_as_a_clean_or_tainted_sink(self) -> None:
        source = "secret = os.getenv('API_KEY')\nprint(str(secret))\n"
        self.assertEqual(apply_rules(parse_source(source)), ())

    def test_method_name_that_only_looks_like_logging_is_not_a_sink(self) -> None:
        source = "secret = os.getenv('API_KEY')\nlogger.info(secret)\n"
        self.assertEqual(apply_rules(parse_source(source)), ())


if __name__ == "__main__":
    unittest.main()
