"""Taint tracking inside one module, function, or class body.

These tests check where a value moves. They do not check vulnerability
findings. A tainted name is not, by itself, a reported security issue.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from flowguard.parser import parse_file, parse_source
from flowguard.rules import RULES
from flowguard.taint_engine import TaintedName, TaintResult, configured_sources, trace_assignments

SAMPLES = Path(__file__).resolve().parent / "samples"
MODULE = "<module>"


class SourceCatalogTests(unittest.TestCase):
    def test_sources_match_the_rule_catalog(self) -> None:
        from_rules: set[str] = set()
        for rule in RULES:
            from_rules.update(rule.sources)

        self.assertEqual(configured_sources(), frozenset(from_rules))
        self.assertEqual(
            configured_sources(),
            frozenset({"os.getenv", "os.environ.get", "input"}),
        )


class DirectSourceTests(unittest.TestCase):
    def test_os_getenv_taints_the_assigned_name(self) -> None:
        result = _trace("secret = os.getenv('API_KEY')\n")
        binding = result.tainted_binding(MODULE, "secret")

        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(binding.source, "os.getenv")
        self.assertEqual(binding.source_line, 1)
        self.assertEqual(binding.path, ("secret",))
        self.assertEqual(result.unsupported, ())

    def test_os_environ_get_is_a_source(self) -> None:
        result = _trace('token = os.environ.get("API_KEY")\n')

        self.assertEqual(_must_bind(result, MODULE, "token").source, "os.environ.get")

    def test_input_is_a_source(self) -> None:
        result = _trace('user_input = input("cmd: ")\n')

        self.assertEqual(_must_bind(result, MODULE, "user_input").source, "input")

    def test_import_alias_is_not_treated_as_os_getenv(self) -> None:
        source = "from os import getenv\nsecret = getenv('API_KEY')\n"
        result = _trace(source)

        self.assertFalse(result.is_tainted(MODULE, "secret"))
        reason = result.unsupported_reason(MODULE, "secret")
        self.assertIsNotNone(reason)
        assert reason is not None
        self.assertIn("getenv", reason)


class AliasTests(unittest.TestCase):
    def test_taint_copies_through_several_names(self) -> None:
        source = "\n".join(
            [
                "secret = os.getenv('API_KEY')",
                "backup = secret",
                "copy = backup",
            ]
        )
        result = _trace(source)

        backup = result.tainted_binding(MODULE, "backup")
        copy = result.tainted_binding(MODULE, "copy")
        self.assertIsNotNone(backup)
        self.assertIsNotNone(copy)
        assert backup is not None and copy is not None
        self.assertEqual(backup.path, ("secret", "backup"))
        self.assertEqual(copy.path, ("secret", "backup", "copy"))
        self.assertEqual(copy.source, "os.getenv")
        self.assertEqual(copy.source_line, 1)
        self.assertEqual(copy.line, 3)

    def test_chained_assignment_from_a_source_taints_each_name(self) -> None:
        result = _trace("backup = secret = os.getenv('API_KEY')\n")

        self.assertEqual(_must_bind(result, MODULE, "backup").path, ("backup",))
        self.assertEqual(_must_bind(result, MODULE, "secret").path, ("secret",))

    def test_unrelated_name_stays_clean(self) -> None:
        source = "\n".join(
            [
                "secret = os.getenv('API_KEY')",
                "message = 'hello'",
                "shown = message",
            ]
        )
        result = _trace(source)

        self.assertTrue(result.is_tainted(MODULE, "secret"))
        self.assertFalse(result.is_tainted(MODULE, "message"))
        self.assertFalse(result.is_tainted(MODULE, "shown"))
        self.assertIsNone(result.unsupported_reason(MODULE, "message"))
        self.assertIsNone(result.unsupported_reason(MODULE, "shown"))


class ReassignmentTests(unittest.TestCase):
    def test_later_constant_clears_only_that_name(self) -> None:
        source = "\n".join(
            [
                "secret = os.getenv('API_KEY')",
                "backup = secret",
                "secret = 'public'",
            ]
        )
        result = _trace(source)

        self.assertFalse(result.is_tainted(MODULE, "secret"))
        self.assertIsNone(result.unsupported_reason(MODULE, "secret"))
        backup = result.tainted_binding(MODULE, "backup")
        self.assertIsNotNone(backup)
        assert backup is not None
        self.assertEqual(backup.path, ("secret", "backup"))
        self.assertEqual(backup.source_line, 1)

    def test_later_source_replaces_the_old_source(self) -> None:
        source = "secret = os.getenv('API_KEY')\nsecret = input()\n"
        result = _trace(source)
        binding = result.tainted_binding(MODULE, "secret")

        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(binding.source, "input")
        self.assertEqual(binding.source_line, 2)
        self.assertEqual(binding.path, ("secret",))

    def test_augmented_constant_keeps_existing_taint(self) -> None:
        source = "secret = os.getenv('API_KEY')\nsecret += ' tail'\n"
        result = _trace(source)
        binding = result.tainted_binding(MODULE, "secret")

        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(binding.source, "os.getenv")
        self.assertEqual(binding.source_line, 1)
        self.assertEqual(binding.line, 2)

    def test_augmented_source_taints_a_clean_name(self) -> None:
        source = "secret = 'public'\nsecret += os.getenv('API_KEY')\n"
        result = _trace(source)
        binding = result.tainted_binding(MODULE, "secret")

        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(binding.source, "os.getenv")
        self.assertEqual(binding.line, 2)

    def test_augmented_constants_stay_clean(self) -> None:
        result = _trace("count = 1\ncount += 2\n")

        self.assertFalse(result.is_tainted(MODULE, "count"))
        self.assertIsNone(result.unsupported_reason(MODULE, "count"))


class ScopeTests(unittest.TestCase):
    def test_functions_do_not_share_a_name(self) -> None:
        source = "\n".join(
            [
                "def one():",
                "    secret = os.getenv('API_KEY')",
                "    backup = secret",
                "def two():",
                "    secret = 'public'",
                "    backup = secret",
            ]
        )
        result = _trace(source)
        tainted_scopes = {item.scope for item in result.tainted}

        self.assertEqual(tainted_scopes, {"one:1"})
        self.assertTrue(result.is_tainted("one:1", "secret"))
        self.assertTrue(result.is_tainted("one:1", "backup"))
        self.assertFalse(result.is_tainted("two:4", "secret"))
        self.assertFalse(result.is_tainted("two:4", "backup"))
        self.assertIsNone(result.unsupported_reason("two:4", "backup"))

    def test_function_assignment_does_not_clear_the_module_name(self) -> None:
        source = "\n".join(
            [
                "secret = os.getenv('API_KEY')",
                "def hide():",
                "    secret = 'public'",
            ]
        )
        result = _trace(source)

        self.assertTrue(result.is_tainted(MODULE, "secret"))
        self.assertFalse(result.is_tainted("hide:2", "secret"))

    def test_nested_function_does_not_see_the_outer_assignment(self) -> None:
        source = "\n".join(
            [
                "def outer():",
                "    secret = os.getenv('API_KEY')",
                "    def inner():",
                "        backup = secret",
            ]
        )
        result = _trace(source)

        self.assertTrue(result.is_tainted("outer:1", "secret"))
        self.assertFalse(result.is_tainted("outer:1.inner:3", "backup"))
        reason = result.unsupported_reason("outer:1.inner:3", "backup")
        self.assertIsNotNone(reason)
        assert reason is not None
        self.assertIn("no assignment in this scope", reason)

    def test_class_body_is_separate_from_a_method(self) -> None:
        source = "\n".join(
            [
                "class Box:",
                "    secret = os.getenv('API_KEY')",
                "    def read(self):",
                "        backup = secret",
            ]
        )
        result = _trace(source)

        self.assertTrue(result.is_tainted("Box:1", "secret"))
        self.assertFalse(result.is_tainted(MODULE, "secret"))
        self.assertIsNotNone(result.unsupported_reason("Box:1.read:3", "backup"))


class UnsupportedTests(unittest.TestCase):
    def test_call_that_is_not_a_source_is_not_called_clean(self) -> None:
        source = "secret = os.getenv('API_KEY')\nwrapped = str(secret)\n"
        result = _trace(source)

        self.assertTrue(result.is_tainted(MODULE, "secret"))
        self.assertFalse(result.is_tainted(MODULE, "wrapped"))
        reason = result.unsupported_reason(MODULE, "wrapped")
        self.assertIsNotNone(reason)
        assert reason is not None
        self.assertIn("str", reason)

    def test_expression_around_a_source_is_not_a_confirmed_flow(self) -> None:
        result = _trace("secret = os.getenv('API_KEY') or 'missing'\n")

        self.assertFalse(result.is_tainted(MODULE, "secret"))
        reason = result.unsupported_reason(MODULE, "secret")
        self.assertIsNotNone(reason)
        assert reason is not None
        self.assertIn("not a simple name", reason)

    def test_parameter_copy_is_not_tainted(self) -> None:
        source = "def run(user_input):\n    command = user_input\n"
        result = _trace(source)

        self.assertFalse(result.is_tainted("run:1", "command"))
        reason = result.unsupported_reason("run:1", "command")
        self.assertIsNotNone(reason)
        assert reason is not None
        self.assertIn("user_input", reason)

    def test_global_assignment_does_not_change_the_module_name(self) -> None:
        source = "\n".join(
            [
                "secret = 'public'",
                "def leak():",
                "    global secret",
                "    secret = os.getenv('API_KEY')",
            ]
        )
        result = _trace(source)

        self.assertFalse(result.is_tainted(MODULE, "secret"))
        self.assertFalse(result.is_tainted("leak:2", "secret"))
        reason = result.unsupported_reason("leak:2", "secret")
        self.assertIsNotNone(reason)
        assert reason is not None
        self.assertIn("global", reason)

    def test_closure_read_at_module_level_is_not_silently_clean(self) -> None:
        source = "secret = os.getenv('API_KEY')\ndef inner():\n    backup = secret\n"
        result = _trace(source)

        self.assertTrue(result.is_tainted(MODULE, "secret"))
        self.assertFalse(result.is_tainted("inner:2", "backup"))
        self.assertIsNotNone(result.unsupported_reason("inner:2", "backup"))


class SampleTests(unittest.TestCase):
    def test_secret_sample_links_backup_without_a_finding(self) -> None:
        result = trace_assignments(parse_file(SAMPLES / "vulnerable_secret.py"))
        backup = result.tainted_binding(MODULE, "backup")

        self.assertTrue(result.is_tainted(MODULE, "secret"))
        self.assertIsNotNone(backup)
        assert backup is not None
        self.assertEqual(backup.path, ("secret", "backup"))
        self.assertEqual(backup.source, "os.getenv")
        self.assertFalse(hasattr(result, "findings"))

    def test_command_sample_taints_user_input_only(self) -> None:
        result = trace_assignments(parse_file(SAMPLES / "vulnerable_command.py"))

        self.assertEqual(_must_bind(result, MODULE, "user_input").source, "input")
        self.assertEqual(len(result.tainted), 1)

    def test_safe_sample_taints_secret_and_not_message(self) -> None:
        result = trace_assignments(parse_file(SAMPLES / "safe_example.py"))

        self.assertTrue(result.is_tainted(MODULE, "secret"))
        self.assertFalse(result.is_tainted(MODULE, "message"))
        self.assertIsNone(result.unsupported_reason(MODULE, "message"))


def _trace(source: str) -> TaintResult:
    return trace_assignments(parse_source(source, path="example.py"))


def _must_bind(result: TaintResult, scope: str, name: str) -> TaintedName:
    binding = result.tainted_binding(scope, name)
    if binding is None:
        raise AssertionError(f"{name} in {scope} is not tainted")
    return binding


if __name__ == "__main__":
    unittest.main()
