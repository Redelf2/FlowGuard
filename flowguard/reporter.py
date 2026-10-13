"""Format the facts produced by the parser.

Milestone 1 reports what was parsed. It deliberately does not include an
empty findings list. An empty list would look like "this file is safe", and
this version does not make that decision.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from flowguard import __version__
from flowguard.parser import FunctionCall, ParseResult

_NOT_IMPLEMENTED = "Taint analysis is not implemented yet."


def format_parse_report(result: ParseResult, output_format: str = "text") -> str:
    """Return a text or JSON summary of one parse result."""

    # Step 1: Reject a format the command line should never pass through.
    if output_format not in {"text", "json"}:
        raise ValueError("format must be 'text' or 'json'")

    # Step 2: JSON is for later scripts. It repeats the parser facts and
    # states that security analysis did not run.
    if output_format == "json":
        payload = {
            "tool": "flowguard",
            "version": __version__,
            "file": result.path,
            "analysis": "not_implemented",
            "message": _NOT_IMPLEMENTED,
            "assignments": [asdict(item) for item in result.assignments],
            "calls": [_call_payload(call) for call in result.calls],
        }
        return json.dumps(payload, indent=2) + "\n"

    # Step 3: Text is the form a person reads in the terminal.
    lines = [
        "FlowGuard",
        f"File: {result.path}",
        f"Parsed assignments: {len(result.assignments)}",
        f"Parsed function calls: {len(result.calls)}",
        _NOT_IMPLEMENTED,
        "Security findings: not checked yet.",
        "",
        "Assignments:",
    ]
    if result.assignments:
        for assignment in result.assignments:
            lines.append(
                f"  line {assignment.line}: {assignment.target} = "
                f"{assignment.value_repr} ({assignment.value_kind})"
            )
    else:
        lines.append("  (none)")

    lines.extend(["", "Function calls:"])
    if result.calls:
        for call in result.calls:
            lines.append(f"  line {call.line}: {_render_call(call)}")
    else:
        lines.append("  (none)")

    return "\n".join(lines) + "\n"


def _call_payload(call: FunctionCall) -> dict[str, object]:
    return {
        "name": call.name,
        "line": call.line,
        "arguments": list(call.arguments),
        "keywords": [asdict(keyword) for keyword in call.keywords],
    }


def _render_call(call: FunctionCall) -> str:
    parts = list(call.arguments)
    parts.extend(f"{keyword.name}={keyword.value}" for keyword in call.keywords)
    return f"{call.name}({', '.join(parts)})"
