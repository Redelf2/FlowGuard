"""Score FlowGuard on a labeled set of small Python files.

The files are parsed and never executed. Three labels are kept separate:

- ``vulnerable``: the named rules should all be reported.
- ``safe``: the implemented rules justify no finding.
- ``unsupported``: a limit we already document. These files are shown in the
  report and are not counted as detections or false positives.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from flowguard.parser import parse_file
from flowguard.rules import apply_rules

_PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class LabeledCase:
    """One sample and the result the current rules should produce."""

    relative_path: str
    label: str
    expected_rules: tuple[str, ...]
    why: str


@dataclass(frozen=True)
class EvaluationReport:
    """Counts from one pass over the labeled cases."""

    vulnerable_files: int
    detected_files: int
    safe_files: int
    false_positive_files: int
    unsupported_files: int
    unexpected_unsupported_files: int
    elapsed_seconds: float
    missed: tuple[str, ...]
    false_positives: tuple[str, ...]
    unexpected_unsupported: tuple[str, ...]

    @property
    def detection_rate(self) -> float:
        if self.vulnerable_files == 0:
            return 0.0
        return self.detected_files / self.vulnerable_files

    @property
    def false_positive_rate(self) -> float:
        if self.safe_files == 0:
            return 0.0
        return self.false_positive_files / self.safe_files


# The why text is the rule reason, not a guess from how harmless the file looks.
LABELED_CASES: tuple[LabeledCase, ...] = (
    LabeledCase(
        "tests/samples/vulnerable_secret.py",
        "vulnerable",
        ("FG001",),
        "os.getenv is copied to backup and printed.",
    ),
    LabeledCase(
        "tests/samples/vulnerable_command.py",
        "vulnerable",
        ("FG002",),
        "input() reaches subprocess.run with shell=True.",
    ),
    LabeledCase(
        "tests/samples/eval/vulnerable/direct_getenv_print.py",
        "vulnerable",
        ("FG001",),
        "os.getenv is an argument of print.",
    ),
    LabeledCase(
        "tests/samples/eval/vulnerable/environ_logging.py",
        "vulnerable",
        ("FG001",),
        "os.environ.get reaches logging.info.",
    ),
    LabeledCase(
        "tests/samples/eval/vulnerable/input_os_system.py",
        "vulnerable",
        ("FG002",),
        "input() reaches os.system.",
    ),
    LabeledCase(
        "tests/samples/eval/vulnerable/input_subprocess.py",
        "vulnerable",
        ("FG002",),
        "input() reaches subprocess.run without shell=True.",
    ),
    LabeledCase(
        "tests/samples/eval/vulnerable/inside_function.py",
        "vulnerable",
        ("FG001",),
        "The source and print are in the same function.",
    ),
    LabeledCase(
        "tests/samples/eval/vulnerable/three_aliases.py",
        "vulnerable",
        ("FG001",),
        "The secret is copied through two names before print.",
    ),
    LabeledCase(
        "tests/samples/eval/vulnerable/two_findings.py",
        "vulnerable",
        ("FG001", "FG002"),
        "One file has both a print of getenv and a shell command from input.",
    ),
    LabeledCase(
        "tests/samples/eval/vulnerable/print_then_clear.py",
        "vulnerable",
        ("FG001",),
        "print happens before the secret is replaced.",
    ),
    LabeledCase(
        "tests/samples/safe_example.py",
        "safe",
        (),
        "print receives a literal. The getenv value is a different name.",
    ),
    LabeledCase(
        "tests/samples/eval/safe/cleared_before_print.py",
        "safe",
        (),
        "The tainted name is replaced with a literal before print.",
    ),
    LabeledCase(
        "tests/samples/eval/safe/separate_functions.py",
        "safe",
        (),
        "The tainted secret and the printed secret are in different functions.",
    ),
    LabeledCase(
        "tests/samples/eval/safe/fixed_command.py",
        "safe",
        (),
        "subprocess.run receives a fixed list and no input() value.",
    ),
    LabeledCase(
        "tests/samples/eval/safe/print_constant.py",
        "safe",
        (),
        "print receives a literal and there is no configured source.",
    ),
    LabeledCase(
        "tests/samples/eval/safe/print_input.py",
        "safe",
        (),
        "input is not an FG001 source, and print is not an FG002 sink.",
    ),
    LabeledCase(
        "tests/samples/eval/safe/getenv_to_command.py",
        "safe",
        (),
        "os.getenv is not an FG002 source, and subprocess.run is not an FG001 sink.",
    ),
    LabeledCase(
        "tests/samples/eval/safe/log_constant.py",
        "safe",
        (),
        "logging.info receives a literal.",
    ),
    LabeledCase(
        "tests/samples/eval/safe/would_write_if_run.py",
        "safe",
        (),
        "print receives a literal. The file is only parsed, so it must not create a marker.",
    ),
    LabeledCase(
        "tests/samples/eval/vulnerable/import_alias.py",
        "vulnerable",
        ("FG001",),
        "from os import getenv makes getenv() the os.getenv source.",
    ),
    LabeledCase(
        "tests/samples/eval/vulnerable/read_env_alias.py",
        "vulnerable",
        ("FG001",),
        "from os import getenv as read_env is a clear alias of os.getenv.",
    ),
    LabeledCase(
        "tests/samples/eval/vulnerable/os_module_alias.py",
        "vulnerable",
        ("FG001",),
        "import os as os_module makes os_module.getenv the os.getenv source.",
    ),
    LabeledCase(
        "tests/samples/eval/safe/local_getenv.py",
        "safe",
        (),
        "A function defined in this file is named getenv and is not os.getenv.",
    ),
    LabeledCase(
        "tests/samples/eval/safe/other_module_getenv.py",
        "safe",
        (),
        "from helpers import getenv does not mean os.getenv.",
    ),
    LabeledCase(
        "tests/samples/eval/safe/shadowed_getenv.py",
        "safe",
        (),
        "The parameter getenv hides the imported os.getenv inside that function.",
    ),
    LabeledCase(
        "tests/samples/eval/unsupported/star_import.py",
        "unsupported",
        (),
        "from os import * does not name getenv, so the call is not resolved.",
    ),
    LabeledCase(
        "tests/samples/eval/unsupported/wrapped_print.py",
        "unsupported",
        (),
        "print(str(secret)) hides the name inside a call.",
    ),
    LabeledCase(
        "tests/samples/eval/unsupported/logger_attribute.py",
        "unsupported",
        (),
        "logger.info is not the configured name logging.info.",
    ),
    LabeledCase(
        "tests/samples/eval/unsupported/or_default.py",
        "unsupported",
        (),
        "os.getenv(...) or 'missing' is not a direct assignment from the call.",
    ),
    LabeledCase(
        "tests/samples/eval/unsupported/parameter.py",
        "unsupported",
        (),
        "A function parameter is not tracked into the function body.",
    ),
    LabeledCase(
        "tests/samples/eval/unsupported/attribute_store.py",
        "unsupported",
        (),
        "self.secret is not a simple variable assignment.",
    ),
)


def evaluate_corpus(root: Path | None = None) -> EvaluationReport:
    """Parse every labeled file and compare findings with the labels.

    This reads source text. It does not import or run the samples.
    """

    project_root = root or _PROJECT_ROOT
    missed: list[str] = []
    false_positives: list[str] = []
    unexpected_unsupported: list[str] = []
    vulnerable_files = 0
    detected_files = 0
    safe_files = 0
    unsupported_files = 0

    # Step 1: Score each file from its label. Parsing is the only file operation.
    started = time.perf_counter()
    for case in LABELED_CASES:
        _require_consistent_label(case)
        parsed = parse_file(project_root / case.relative_path)
        found_rules = {finding.rule_id for finding in apply_rules(parsed)}
        if case.label == "vulnerable":
            vulnerable_files += 1
            if found_rules == set(case.expected_rules):
                detected_files += 1
            else:
                missed.append(case.relative_path)
        elif case.label == "safe":
            safe_files += 1
            if found_rules:
                false_positives.append(case.relative_path)
        else:
            unsupported_files += 1
            if found_rules:
                unexpected_unsupported.append(case.relative_path)
    elapsed_seconds = time.perf_counter() - started

    # Step 2: Return counts. Rates are derived from these counts by the caller.
    return EvaluationReport(
        vulnerable_files=vulnerable_files,
        detected_files=detected_files,
        safe_files=safe_files,
        false_positive_files=len(false_positives),
        unsupported_files=unsupported_files,
        unexpected_unsupported_files=len(unexpected_unsupported),
        elapsed_seconds=elapsed_seconds,
        missed=tuple(missed),
        false_positives=tuple(false_positives),
        unexpected_unsupported=tuple(unexpected_unsupported),
    )


def format_evaluation(report: EvaluationReport) -> str:
    """Return the text report used by ``python flowguard.py --evaluate``."""

    lines = [
        "FlowGuard evaluation",
        f"Vulnerable files: {report.vulnerable_files}",
        f"Detected: {report.detected_files}",
        f"Detection rate: {_percent(report.detection_rate)}",
        f"Safe files: {report.safe_files}",
        f"False positives: {report.false_positive_files}",
        f"False-positive rate: {_percent(report.false_positive_rate)}",
        f"Unsupported files, not scored: {report.unsupported_files}",
        f"Unexpected findings in unsupported files: {report.unexpected_unsupported_files}",
        f"Elapsed: {report.elapsed_seconds:.3f} seconds",
        "",
        "Detection rate is the share of vulnerable files whose expected rules were reported.",
        "False-positive rate is the share of safe files that produced any finding.",
        "Unsupported files are known limits and are excluded from both rates.",
    ]
    if report.missed:
        lines.extend(["", "Missed:"])
        lines.extend(f"  {path}" for path in report.missed)
    if report.false_positives:
        lines.extend(["", "False positives:"])
        lines.extend(f"  {path}" for path in report.false_positives)
    if report.unexpected_unsupported:
        lines.extend(["", "Unexpected unsupported findings:"])
        lines.extend(f"  {path}" for path in report.unexpected_unsupported)
    lines.append("")
    return "\n".join(lines)


def _require_consistent_label(case: LabeledCase) -> None:
    if case.label not in {"vulnerable", "safe", "unsupported"}:
        raise ValueError(f"Unknown label {case.label!r} for {case.relative_path}")
    if case.label == "vulnerable" and not case.expected_rules:
        raise ValueError(f"Vulnerable case has no expected rules: {case.relative_path}")
    if case.label != "vulnerable" and case.expected_rules:
        raise ValueError(f"{case.label} case should not expect rules: {case.relative_path}")


def _percent(rate: float) -> str:
    return f"{rate * 100:.1f}%"
