"""Command-line entry point for FlowGuard.

Examples, from the project root:

    python flowguard.py tests/samples/vulnerable_secret.py
    python flowguard.py tests/samples/vulnerable_command.py --format json

The path is parsed and is not executed. This version prints the assignments
and calls it found. It does not report security findings yet.
"""

from __future__ import annotations

import argparse
import sys

from flowguard.parser import FlowGuardSyntaxError, SourceReadError, parse_file
from flowguard.reporter import format_parse_report


def build_argument_parser() -> argparse.ArgumentParser:
    """Describe the milestone 1 command line."""

    return argparse.ArgumentParser(
        prog="flowguard",
        description=(
            "Parse a Python file and list assignments and function calls. "
            "The file is not executed. Taint analysis is not implemented yet."
        ),
        epilog=(
            "examples:\n"
            "  python flowguard.py tests/samples/vulnerable_secret.py\n"
            "  python flowguard.py tests/samples/vulnerable_command.py --format json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def main(argv: list[str] | None = None) -> int:
    """Parse one file and print a summary.

    Returns 0 when the file parsed, and 2 when the path or the source is
    unusable. A successful parse is not a claim that the file is safe.
    """

    # Step 1: Read the path and the output format.
    argument_parser = build_argument_parser()
    argument_parser.add_argument(
        "path",
        help="Python file to parse. FlowGuard reads this file and does not run it.",
    )
    argument_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Print a text summary or JSON (default: text).",
    )
    arguments = argument_parser.parse_args(argv)

    # Step 2: Parse the file. Parser errors stay short; they are expected
    # input problems, not internal crashes.
    try:
        parsed = parse_file(arguments.path)
    except FileNotFoundError as error:
        print(error, file=sys.stderr)
        return 2
    except IsADirectoryError as error:
        print(error, file=sys.stderr)
        return 2
    except SourceReadError as error:
        print(error, file=sys.stderr)
        return 2
    except FlowGuardSyntaxError as error:
        print(error, file=sys.stderr)
        return 2

    # Step 3: Show the parse summary. Findings are intentionally absent.
    print(format_parse_report(parsed, arguments.format), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
