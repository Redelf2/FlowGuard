"""Tests for the Milestone 1 parser and the parse-only command line.

These tests check that FlowGuard can see assignments, calls, and line
numbers. They do not check taint tracking or vulnerability findings.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flowguard import __version__
from flowguard.parser import (
    InvalidPythonSyntaxError,
    SourceFileNotFoundError,
    SourceReadError,
    parse_file,
    parse_source,
)
from flowguard.reporter import NOT_IMPLEMENTED_MESSAGE, format_parse_report

SAMPLES = ROOT / "tests" / "samples"


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the FlowGuard script. This does not execute the file being parsed."""
    return subprocess.run(
        [sys.executable, str(ROOT / "flowguard.py"), *arguments],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )


class ParserTests(unittest.TestCase):
    def test_extracts_assignment_target_value_and_line(self) -> None:
        result = parse_source('secret = os.getenv("API_KEY")\n', filename="example.py")

        self.assertEqual(result.path, "example.py")
        self.assertEqual(len(result.assignments), 1)
        assignment = result.assignments[0]
        self.assertEqual(assignment.target, "secret")
        self.assertEqual(assignment.line, 1)
        self.assertIn("os.getenv", assignment.value)
        self.assertIn("API_KEY", assignment.value)

    def test_extracts_dotted_call_arguments_and_keywords(self) -> None:
        source = "subprocess.run(user_input, shell=True)\n"
        result = parse_source(source)

        self.assertEqual(len(result.function_calls), 1)
        call = result.function_calls[0]
        self.assertEqual(call.name, "subprocess.run")
        self.assertEqual(call.line, 1)
        self.assertEqual(call.arguments, ("user_input",))
        self.assertEqual(len(call.keywords), 1)
        self.assertEqual(call.keywords[0].name, "shell")
        self.assertEqual(call.keywords[0].value, "True")
        self.assertEqual(call.display(), "subprocess.run(user_input, shell=True)")

    def test_records_nested_calls(self) -> None:
        result = parse_source('print(os.getenv("API_KEY"))\n')
        names = [call.name for call in result.function_calls]

        self.assertEqual(names, ["print", "os.getenv"])

    def test_reassignment_is_two_assignments(self) -> None:
        source = 'user_input = input()\nuser_input = "fixed"\n'
        result = parse_source(source)

        self.assertEqual(
            [(item.target, item.line) for item in result.assignments],
            [("user_input", 1), ("user_input", 2)],
        )
        self.assertEqual([call.name for call in result.function_calls], ["input"])

    def test_alias_is_an_assignment_from_another_name(self) -> None:
        result = parse_source("backup = secret\n")

        self.assertEqual(result.assignments[0].target, "backup")
        self.assertEqual(result.assignments[0].value, "secret")

    def test_chained_assignment_records_each_name(self) -> None:
        result = parse_source('first = second = os.getenv("API_KEY")\n')
        targets = [item.target for item in result.assignments]

        self.assertEqual(targets, ["first", "second"])
        self.assertEqual([call.name for call in result.function_calls], ["os.getenv"])

    def test_unpacking_records_each_name_with_the_whole_value(self) -> None:
        result = parse_source("left, right = pair\n")

        self.assertEqual(
            [(item.target, item.value) for item in result.assignments],
            [("left", "pair"), ("right", "pair")],
        )

    def test_annotated_assignment_is_recorded(self) -> None:
        result = parse_source("secret: str = input()\n")

        self.assertEqual(result.assignments[0].target, "secret")
        self.assertEqual(result.assignments[0].value, "input()")
        self.assertEqual(result.function_calls[0].name, "input")

    def test_annotation_without_a_value_is_not_an_assignment(self) -> None:
        result = parse_source("secret: str\n")

        self.assertEqual(result.assignments, ())
        self.assertEqual(result.function_calls, ())

    def test_import_alias_is_not_resolved(self) -> None:
        source = "from os import getenv\nsecret = getenv('API_KEY')\n"
        result = parse_source(source)

        self.assertEqual(result.function_calls[0].name, "getenv")

    def test_multiline_call_uses_the_first_line(self) -> None:
        source = 'secret = os.getenv(\n    "API_KEY"\n)\n'
        result = parse_source(source)

        self.assertEqual(result.function_calls[0].line, 1)
        self.assertEqual(result.assignments[0].line, 1)

    def test_augmented_assignment_keeps_the_call_only(self) -> None:
        # `+=` is a documented limitation: the call is visible, the store is not.
        result = parse_source("count += input()\n")

        self.assertEqual(result.assignments, ())
        self.assertEqual(result.function_calls[0].name, "input")

    def test_named_expression_keeps_the_call_only(self) -> None:
        # `:=` is a documented limitation of this version.
        source = "if (secret := os.getenv('API_KEY')):\n    pass\n"
        result = parse_source(source)

        self.assertEqual(result.assignments, ())
        self.assertEqual(result.function_calls[0].name, "os.getenv")

    def test_invalid_syntax_includes_the_line_number(self) -> None:
        with self.assertRaises(InvalidPythonSyntaxError) as caught:
            parse_source("x = 1\ndef (\n", filename="example.py")

        self.assertEqual(caught.exception.line, 2)
        self.assertIn("example.py:2", str(caught.exception))

    def test_missing_file_raises_a_clear_error(self) -> None:
        missing = SAMPLES / "does_not_exist.py"
        with self.assertRaises(SourceFileNotFoundError) as caught:
            parse_file(missing)

        self.assertIn("does_not_exist.py", str(caught.exception))

    def test_directory_is_rejected(self) -> None:
        with self.assertRaises(SourceFileNotFoundError):
            parse_file(SAMPLES)

    def test_invalid_utf8_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.py"
            path.write_bytes(b"secret = '\xff'\n")
            with self.assertRaises(SourceReadError) as caught:
                parse_file(path)

        self.assertIn("UTF-8", str(caught.exception))

    def test_parse_does_not_execute_the_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "marker.txt"
            source = f"open({str(marker)!r}, 'w').write('executed')\n"
            result = parse_source(source)

            self.assertFalse(marker.exists())
            self.assertIn("open", [call.name for call in result.function_calls])

    def test_empty_file_has_no_assignments_or_calls(self) -> None:
        result = parse_source("")

        self.assertEqual(result.assignments, ())
        self.assertEqual(result.function_calls, ())

    def test_vulnerable_secret_sample(self) -> None:
        result = parse_file(SAMPLES / "vulnerable_secret.py")
        secret, backup = result.assignments

        self.assertEqual((secret.target, secret.line), ("secret", 5))
        self.assertIn("os.getenv", secret.value)
        self.assertEqual((backup.target, backup.line, backup.value), ("backup", 6, "secret"))
        self.assertEqual(
            [(call.name, call.line) for call in result.function_calls],
            [("os.getenv", 5), ("print", 7)],
        )
        self.assertEqual(result.function_calls[1].arguments, ("backup",))

    def test_vulnerable_command_sample(self) -> None:
        result = parse_file(SAMPLES / "vulnerable_command.py")

        self.assertEqual(result.assignments[0].target, "user_input")
        self.assertEqual(result.assignments[0].line, 5)
        run_call = result.function_calls[1]
        self.assertEqual(run_call.name, "subprocess.run")
        self.assertEqual(run_call.line, 6)
        self.assertEqual(run_call.arguments, ("user_input",))
        self.assertEqual(run_call.keywords[0].name, "shell")
        self.assertEqual(run_call.keywords[0].value, "True")

    def test_safe_sample_parses_without_claiming_it_is_safe(self) -> None:
        # Parsing success is not a safety verdict. This only checks the syntax listing.
        result = parse_file(SAMPLES / "safe_example.py")
        names = [call.name for call in result.function_calls]

        self.assertEqual(result.assignments[0].target, "status")
        self.assertIn("print", names)
        self.assertIn("subprocess.run", names)


class ReportTests(unittest.TestCase):
    def test_text_report_lists_facts_and_says_analysis_is_not_implemented(self) -> None:
        result = parse_source("backup = secret\nprint(backup)\n", filename="example.py")
        report = format_parse_report(result, "text")

        self.assertIn("FlowGuard 0.1.0 parse report", report)
        self.assertIn(NOT_IMPLEMENTED_MESSAGE, report)
        self.assertIn("line 1: backup = secret", report)
        self.assertIn("line 2: print(backup)", report)

    def test_json_report_marks_analysis_as_not_implemented(self) -> None:
        result = parse_source("print(backup)\n", filename="example.py")
        payload = json.loads(format_parse_report(result, "json"))

        self.assertEqual(payload["flowguard_version"], __version__)
        self.assertEqual(payload["status"], "parsed")
        self.assertEqual(payload["analysis"], "not_implemented")
        self.assertEqual(payload["function_calls"][0]["name"], "print")
        self.assertNotIn("findings", payload)

    def test_unknown_format_is_rejected(self) -> None:
        result = parse_source("x = 1\n")
        with self.assertRaises(ValueError):
            format_parse_report(result, "html")


class CommandLineTests(unittest.TestCase):
    def test_text_report_for_a_sample_file(self) -> None:
        completed = _run_cli("tests/samples/vulnerable_secret.py")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("os.getenv", completed.stdout)
        self.assertIn("print(backup)", completed.stdout)
        self.assertIn("not implemented", completed.stdout.lower())
        self.assertNotIn("FG001", completed.stdout)
        self.assertEqual(completed.stderr, "")

    def test_json_report_for_a_sample_file(self) -> None:
        completed = _run_cli("tests/samples/vulnerable_command.py", "--format", "json")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["analysis"], "not_implemented")
        self.assertEqual(payload["file"], "tests/samples/vulnerable_command.py")
        names = [call["name"] for call in payload["function_calls"]]
        self.assertEqual(names, ["input", "subprocess.run"])
        run_call = payload["function_calls"][1]
        self.assertEqual(run_call["keywords"], [{"name": "shell", "value": "True"}])

    def test_missing_file_exits_with_an_error(self) -> None:
        completed = _run_cli("tests/samples/missing.py")

        self.assertEqual(completed.returncode, 2)
        self.assertIn("missing.py", completed.stderr)
        self.assertEqual(completed.stdout, "")

    def test_invalid_syntax_exits_with_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.py"
            path.write_text("x = 1\ndef (\n", encoding="utf-8")
            completed = _run_cli(str(path))

        self.assertEqual(completed.returncode, 2)
        self.assertIn("Invalid Python syntax", completed.stderr)
        self.assertIn(":2:", completed.stderr)


if __name__ == "__main__":
    unittest.main()
