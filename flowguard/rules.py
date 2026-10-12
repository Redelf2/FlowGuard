"""Security rules for FlowGuard.

A rule describes one kind of risky data flow: where data may come from,
and where it becomes dangerous if it arrives there. A match is a potential
risk. Static evidence alone does not prove that the program is exploitable.

The rules below are the plan. Nothing in this module detects a flow yet.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class PlannedRule:
    """A rule we intend to implement. It does not detect anything yet."""

    rule_id: str
    title: str
    summary: str


# Rule ids stay stable so later reports and tests can refer to them.
PLANNED_RULES: tuple[PlannedRule, ...] = (
    PlannedRule(
        rule_id="FG001",
        title="Potential sensitive-data exposure",
        summary=(
            "Track configured secret sources such as os.getenv() "
            "through assignments to print() or selected logging calls."
        ),
    ),
    PlannedRule(
        rule_id="FG002",
        title="Potential command injection",
        summary=(
            "Track untrusted input such as input() through assignments "
            "to command execution such as subprocess.run(), "
            "especially when shell=True."
        ),
    ),
)


def apply_rules(parsed_program: object) -> list[object]:
    """Check parsed code against the security rules.

    Raises:
        NotImplementedError: rule checking is a later milestone.
            An empty list would look like a clean scan, which would be misleading.
    """
    del parsed_program
    raise NotImplementedError(
        "Security rules are not implemented yet. "
        "FlowGuard does not yet decide whether a flow is risky, "
        "and it does not report vulnerabilities."
    )
