"""Command-line entry point for FlowGuard.

Examples, from the project root:

    python flowguard.py tests/samples/vulnerable_secret.py
    python flowguard.py tests/samples/vulnerable_command.py --format json
    python flowguard.py --evaluate

The path is parsed and is not executed. Findings are potential risks on
tracked paths, not proof that the file is exploitable.
"""

from __future__ import annotations

import argparse
import sys

from flowguard.evaluate import evaluate_corpus, format_evaluation
from flowguard.parser import FlowGuardSyntaxError, SourceReadError, parse_file
from flowguard.reporter import format_parse_report


def build_argument_parser() -> argparse.ArgumentParser:
    """Describe the command line."""

    return argparse.ArgumentParser(
        prog="flowguard",
        description=(
            "Report potential risky data flows in a Python file. "
            "The file is not executed."
        ),
        epilog=(
            "examples:\n"
            "  python flowguard.py tests/samples/vulnerable_secret.py\n"
            "  python flowguard.py tests/samples/vulnerable_command.py --format json\n"
            "  python flowguard.py --evaluate"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def main(argv: list[str] | None = None) -> int:
    """Parse one file and print a summary.

    Returns 0 when the file was analyzed, and 2 when the path or the source
    is unusable. Exit code 0 is not a claim that the file is safe.
    """

    # Step 1: Read the path and the output format.
    argument_parser = build_argument_parser()
    argument_parser.add_argument(
        "path",
        nargs="?",
        help="Python file to parse. FlowGuard reads this file and does not run it.",
    )
    argument_parser.add_argument(
        "--evaluate",
        action="store_true",
        help="Score the labeled samples. This does not run those files.",
    )
    argument_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Print a text summary or JSON (default: text).",
    )
    arguments = argument_parser.parse_args(argv)

    # Step 2: Score the labeled corpus, or parse the one requested file.
    if arguments.evaluate:
        if arguments.path:
            print("Give either a file path or --evaluate, not both.", file=sys.stderr)
            return 2
        print(format_evaluation(evaluate_corpus()), end="")
        return 0
    if not arguments.path:
        argument_parser.error("pass a Python file, or use --evaluate")

    # Step 3: Parse the file. Parser errors stay short; they are expected
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

    # Step 4: Show parser facts and any potential findings.
    print(format_parse_report(parsed, arguments.format), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
