"""Format parser facts and potential security findings.

An empty findings list means no tracked tainted value reached a configured
sink. It does not mean the file is safe. Unsupported values are omitted.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from flowguard import __version__
from flowguard.parser import Assignment, FunctionCall, ParseResult
from flowguard.rules import Finding, apply_rules

_NOT_A_PROOF = (
    "A finding is a potential risk on a tracked path. "
    "Unsupported values are omitted. "
    "This is not proof that the file is safe or that a finding is exploitable."
)


def format_parse_report(result: ParseResult, output_format: str = "text") -> str:
    """Return a text or JSON summary of one parse result."""

    # Step 1: Reject a format the command line should never pass through.
    if output_format not in {"text", "json"}:
        raise ValueError("format must be 'text' or 'json'")

    # Step 2: Apply the configured rules. An empty tuple is a real result.
    findings = apply_rules(result)

    # Step 3: JSON is for later scripts. It repeats the parser facts and findings.
    if output_format == "json":
        payload = {
            "tool": "flowguard",
            "version": __version__,
            "file": result.path,
            "analysis": "completed",
            "message": _NOT_A_PROOF,
            "assignments": [_assignment_payload(item) for item in result.assignments],
            "calls": [_call_payload(call) for call in result.calls],
            "findings": [finding.to_dict() for finding in findings],
        }
        return json.dumps(payload, indent=2) + "\n"

    # Step 4: Text is the form a person reads in the terminal.
    lines = [
        "FlowGuard",
        f"File: {result.path}",
        f"Parsed assignments: {len(result.assignments)}",
        f"Parsed function calls: {len(result.calls)}",
        f"Security findings: {len(findings)}",
        _NOT_A_PROOF,
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

    lines.extend(["", _format_findings(findings)])
    return "\n".join(lines) + "\n"


def _format_findings(findings: tuple[Finding, ...]) -> str:
    if not findings:
        return (
            "Findings:\n"
            "  (none)\n"
            "  No configured sink received a tracked tainted value."
        )
    blocks = ["Findings:"]
    for finding in findings:
        blocks.append(
            "\n".join(
                [
                    "",
                    f"[{finding.severity.upper()}] {finding.rule_id} {finding.title}",
                    f"File: {finding.file}",
                    f"Source: {finding.source} at line {finding.source_line}",
                    f"Data flow: {finding.flow_text()}",
                    f"Destination: {finding.sink} at line {finding.sink_line}",
                    f"Confidence: {finding.confidence}",
                    "",
                    "Reason:",
                    finding.explanation,
                    "",
                    "Recommendation:",
                    finding.recommended_fix,
                    "",
                    "Limitation:",
                    finding.limitation,
                ]
            )
        )
    return "\n".join(blocks)


def _assignment_payload(assignment: Assignment) -> dict[str, object]:
    """Return the milestone 1 assignment fields.

    Scope and operand kind stay on the Python object for the taint engine.
    The parse report does not grow new fields.
    """

    return {
        "target": assignment.target,
        "line": assignment.line,
        "value_kind": assignment.value_kind,
        "value_repr": assignment.value_repr,
    }


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
