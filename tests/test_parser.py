"""Tests for milestone 1: parsing without executing the target file."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from flowguard.parser import (
    FlowGuardSyntaxError,
    KeywordArgument,
    parse_file,
    parse_source,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = Path(__file__).resolve().parent / "samples"
CLI = ROOT / "flowguard.py"


class ParseSourceTests(unittest.TestCase):
    def test_direct_assignment_records_call_and_line(self) -> None:
        source = "\n".join(
            [
                "import os",
                "secret = os.getenv('API_KEY')",
                "print(secret)",
            ]
        )

        result = parse_source(source, path="example.py")

        self.assertEqual(result.path, "example.py")
        self.assertEqual(len(result.assignments), 1)
        assignment = result.assignments[0]
        self.assertEqual(assignment.target, "secret")
        self.assertEqual(assignment.line, 2)
        self.assertEqual(assignment.value_kind, "call")
        self.assertEqual(assignment.value_repr, "os.getenv")

        getenv_call = next(call for call in result.calls if call.name == "os.getenv")
        self.assertEqual(getenv_call.line, 2)
        self.assertEqual(getenv_call.arguments, ("'API_KEY'",))

    def test_chained_assignment_records_each_name(self) -> None:
        result = parse_source("backup = secret = os.getenv('API_KEY')\n")

        self.assertEqual(
            [item.target for item in result.assignments],
            ["backup", "secret"],
        )
        self.assertTrue(all(item.value_kind == "call" for item in result.assignments))
        self.assertTrue(all(item.value_repr == "os.getenv" for item in result.assignments))

    def test_augmented_assignment_is_labeled_separately(self) -> None:
        result = parse_source("secret += extra\n")

        self.assertEqual(result.assignments[0].target, "secret")
        self.assertEqual(result.assignments[0].value_kind, "augassign")
        self.assertEqual(result.assignments[0].value_repr, "extra")
        self.assertEqual(result.assignments[0].operand_kind, "name")

    def test_alias_is_recorded_as_a_name_copy(self) -> None:
        result = parse_source("backup = secret\n")

        self.assertEqual(result.assignments[0].target, "backup")
        self.assertEqual(result.assignments[0].value_kind, "name")
        self.assertEqual(result.assignments[0].value_repr, "secret")
        self.assertEqual(result.calls, ())

    def test_reassignment_keeps_both_writes(self) -> None:
        # The parser must not drop the first write. Choosing which value is
        # current is the taint engine's job.
        source = "secret = os.getenv('API_KEY')\nsecret = 'public'\n"
        result = parse_source(source)

        self.assertEqual(
            [item.value_kind for item in result.assignments],
            ["call", "constant"],
        )
        self.assertEqual(result.assignments[1].value_repr, "'public'")

    def test_same_name_in_two_functions_stays_two_assignments(self) -> None:
        source = "\n".join(
            [
                "def one():",
                "    secret = os.getenv('API_KEY')",
                "def two():",
                "    secret = 'safe'",
            ]
        )
        result = parse_source(source)

        secret_writes = [item for item in result.assignments if item.target == "secret"]
        self.assertEqual(len(secret_writes), 2)
        self.assertNotEqual(secret_writes[0].line, secret_writes[1].line)

    def test_nested_calls_are_recorded_outer_call_first(self) -> None:
        result = parse_source("print(os.getenv('API_KEY'))\n")

        self.assertEqual([call.name for call in result.calls], ["print", "os.getenv"])
        self.assertEqual(result.calls[0].arguments, ("os.getenv()",))

    def test_keyword_argument_is_recorded_without_evaluating_it(self) -> None:
        result = parse_source("subprocess.run(user_input, shell=True)\n")

        self.assertEqual(len(result.calls), 1)
        call = result.calls[0]
        self.assertEqual(call.name, "subprocess.run")
        self.assertEqual(call.arguments, ("user_input",))
        self.assertEqual(call.keywords, (KeywordArgument(name="shell", value="True"),))

    def test_annotated_assignment_is_recorded(self) -> None:
        result = parse_source("secret: str = os.getenv('API_KEY')\n")

        self.assertEqual(result.assignments[0].target, "secret")
        self.assertEqual(result.assignments[0].value_kind, "call")

    def test_annotation_without_a_value_is_not_an_assignment(self) -> None:
        result = parse_source("secret: str\n")

        self.assertEqual(result.assignments, ())
        self.assertEqual(result.calls, ())

    def test_unpacking_is_not_treated_as_simple_names(self) -> None:
        result = parse_source("first, second = os.getenv('API_KEY'), input()\n")

        self.assertEqual(result.assignments, ())
        self.assertEqual([call.name for call in result.calls], ["os.getenv", "input"])

    def test_attribute_target_is_not_a_simple_variable(self) -> None:
        result = parse_source("self.secret = os.getenv('API_KEY')\n")

        self.assertEqual(result.assignments, ())
        self.assertEqual(result.calls[0].name, "os.getenv")

    def test_empty_file_has_no_facts(self) -> None:
        result = parse_source("")

        self.assertEqual(result.assignments, ())
        self.assertEqual(result.calls, ())

    def test_function_scopes_stay_separate_from_the_module(self) -> None:
        source = "\n".join(
            [
                "secret = os.getenv('API_KEY')",
                "def load(token=os.getenv('TOKEN')):",
                "    secret = input()",
            ]
        )
        result = parse_source(source)

        self.assertEqual(result.assignments[0].scope, "<module>")
        self.assertEqual(result.assignments[1].scope, "load:2")
        default_call = next(
            call for call in result.calls if call.arguments == ("'TOKEN'",)
        )
        self.assertEqual(default_call.scope, "<module>")
        body_call = next(call for call in result.calls if call.name == "input")
        self.assertEqual(body_call.scope, "load:2")

    def test_augmented_call_keeps_the_operand_kind(self) -> None:
        result = parse_source("secret += input()\n")

        self.assertEqual(result.assignments[0].value_kind, "augassign")
        self.assertEqual(result.assignments[0].operand_kind, "call")
        self.assertEqual(result.assignments[0].value_repr, "input")

    def test_syntax_error_includes_the_line_number(self) -> None:
        with self.assertRaises(FlowGuardSyntaxError) as caught:
            parse_source("x = 1\ny = (\n", path="bad.py")

        self.assertEqual(caught.exception.path, "bad.py")
        self.assertEqual(caught.exception.line, 2)
        self.assertIn("bad.py:2:", str(caught.exception))


class ParseFileTests(unittest.TestCase):
    def test_secret_sample_shows_copy_then_print(self) -> None:
        result = parse_file(SAMPLES / "vulnerable_secret.py")

        secret = next(item for item in result.assignments if item.target == "secret")
        backup = next(item for item in result.assignments if item.target == "backup")
        printed = next(call for call in result.calls if call.name == "print")

        self.assertEqual(secret.value_repr, "os.getenv")
        self.assertEqual(backup.value_kind, "name")
        self.assertEqual(backup.value_repr, "secret")
        self.assertEqual(printed.arguments, ("backup",))
        self.assertLess(secret.line, backup.line)
        self.assertLess(backup.line, printed.line)

    def test_command_sample_records_input_and_shell_flag(self) -> None:
        result = parse_file(SAMPLES / "vulnerable_command.py")

        captured = next(item for item in result.assignments if item.target == "user_input")
        launched = next(call for call in result.calls if call.name == "subprocess.run")

        self.assertEqual(captured.value_repr, "input")
        self.assertEqual(launched.arguments, ("user_input",))
        self.assertEqual(
            launched.keywords,
            (KeywordArgument(name="shell", value="True"),),
        )

    def test_safe_sample_prints_message_not_secret(self) -> None:
        # This checks the parsed facts only. It does not call the file safe.
        result = parse_file(SAMPLES / "safe_example.py")
        printed = next(call for call in result.calls if call.name == "print")
        message = next(item for item in result.assignments if item.target == "message")

        self.assertEqual(printed.arguments, ("message",))
        self.assertEqual(message.value_kind, "constant")
        self.assertEqual(message.value_repr, "'hello'")

    def test_missing_file_raises_file_not_found(self) -> None:
        missing = SAMPLES / "does_not_exist.py"

        with self.assertRaises(FileNotFoundError) as caught:
            parse_file(missing)

        self.assertIn("does_not_exist.py", str(caught.exception))

    def test_directory_is_rejected(self) -> None:
        with self.assertRaises(IsADirectoryError):
            parse_file(SAMPLES)

    def test_parser_does_not_execute_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            marker = folder / "executed.txt"
            source_path = folder / "sample.py"
            source_path.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n",
                encoding="utf-8",
            )

            result = parse_file(source_path)

            self.assertFalse(marker.exists())
            self.assertTrue(result.calls)


class CommandLineTests(unittest.TestCase):
    def test_text_report_says_analysis_is_not_implemented(self) -> None:
        completed = _run_cli(SAMPLES / "vulnerable_secret.py")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Security findings: not checked yet.", completed.stdout)
        self.assertNotIn("Taint analysis is not implemented yet.", completed.stdout)
        self.assertIn("backup = secret (name)", completed.stdout)
        self.assertEqual(completed.stderr, "")

    def test_json_report_has_no_findings_list(self) -> None:
        completed = _run_cli(SAMPLES / "vulnerable_command.py", "--format", "json")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["analysis"], "not_implemented")
        self.assertNotIn("findings", payload)
        self.assertEqual(payload["calls"][1]["name"], "subprocess.run")
        self.assertEqual(payload["calls"][1]["keywords"][0]["name"], "shell")

    def test_missing_file_exits_with_code_2(self) -> None:
        completed = _run_cli(SAMPLES / "does_not_exist.py")

        self.assertEqual(completed.returncode, 2)
        self.assertIn("does_not_exist.py", completed.stderr)
        self.assertEqual(completed.stdout, "")

    def test_invalid_syntax_exits_with_code_2(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bad_file = Path(directory) / "bad.py"
            bad_file.write_text("x = (\n", encoding="utf-8")
            completed = _run_cli(bad_file)

        self.assertEqual(completed.returncode, 2)
        self.assertIn("bad.py:1:", completed.stderr)

    def test_help_exits_successfully(self) -> None:
        completed = _run_cli("--help")

        self.assertEqual(completed.returncode, 0)
        self.assertIn("does not run", completed.stdout)


def _run_cli(*arguments: str | Path) -> subprocess.CompletedProcess[str]:
    """Run the real entry script. This does not execute the analyzed file."""

    return subprocess.run(
        [sys.executable, str(CLI), *[str(argument) for argument in arguments]],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


if __name__ == "__main__":
    unittest.main()
