"""Format parser output for the terminal or for another program.

This version formats a parse report: the assignments and calls that were
found. It is not a vulnerability report. Findings with severity and
remediation advice will be added when the rules exist.
"""

from __future__ import annotations

import json

from flowguard import __version__
from flowguard.parser import ParseResult

NOT_IMPLEMENTED_MESSAGE = (
    "Security analysis is not implemented yet. "
    "This report lists assignments and function calls only. "
    "It is not a vulnerability finding."
)


def format_parse_report(result: ParseResult, output_format: str) -> str:
    """Return a text or JSON parse report.

    ``output_format`` is ``text`` or ``json``. A successful report means the
    file was parsed. It does not mean the file is safe.
    """
    if output_format == "json":
        return _format_json(result)
    if output_format == "text":
        return _format_text(result)
    raise ValueError(f"Unsupported format: {output_format}. Use 'text' or 'json'.")


def _format_text(result: ParseResult) -> str:
    lines = [
        f"FlowGuard {__version__} parse report",
        f"File: {result.path}",
        "",
        NOT_IMPLEMENTED_MESSAGE,
        "",
        "Assignments:",
    ]
    if result.assignments:
        for assignment in result.assignments:
            lines.append(
                f"  line {assignment.line}: {assignment.target} = {assignment.value}"
            )
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Function calls:")
    if result.function_calls:
        for call in result.function_calls:
            lines.append(f"  line {call.line}: {call.display()}")
    else:
        lines.append("  (none)")

    lines.append("")
    return "\n".join(lines)


def _format_json(result: ParseResult) -> str:
    payload = {
        "flowguard_version": __version__,
        "file": result.path,
        "status": "parsed",
        "analysis": "not_implemented",
        "message": NOT_IMPLEMENTED_MESSAGE,
        "assignments": [assignment.to_dict() for assignment in result.assignments],
        "function_calls": [call.to_dict() for call in result.function_calls],
    }
    return json.dumps(payload, indent=2)
