"""Command-line entry point for FlowGuard.

Run it as a script, for example:

    python flowguard.py tests/samples/vulnerable_secret.py

Python loads this file as ``__main__``. The ``import flowguard`` statement
below still loads the ``flowguard`` package directory, not this script.
The package and this filename can therefore share a name.

The command parses one Python file. It does not run that file, and it does
not report vulnerabilities yet.
"""

from __future__ import annotations

import argparse
import sys

from flowguard.parser import FlowGuardParseError, parse_file
from flowguard.reporter import format_parse_report


def build_argument_parser() -> argparse.ArgumentParser:
    """Describe the command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="flowguard",
        description=(
            "Parse a Python file and list assignments and function calls. "
            "The file is not executed. Security analysis is not implemented yet."
        ),
    )
    parser.add_argument(
        "path",
        help="Path to the Python file to read. The file is parsed, not executed.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format. Default: text. json is a parse report, not a finding list.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse one file and print a parse report.

    Returns 0 when the file was parsed. That does not mean the file is safe.
    Returns 2 when the file is missing, unreadable, or not valid Python.
    """
    arguments = build_argument_parser().parse_args(argv)

    # Step 1: Parse the requested file. Parser errors are explained on stderr.
    try:
        parsed = parse_file(arguments.path)
    except FlowGuardParseError as error:
        print(str(error), file=sys.stderr)
        return 2

    # Step 2: Show the assignments and calls. Rules are not applied yet.
    print(format_parse_report(parsed, arguments.format))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
