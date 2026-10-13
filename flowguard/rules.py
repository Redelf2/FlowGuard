"""The security checks FlowGuard plans to apply.

A rule here is a written definition: which call names count as sources,
which call names count as destinations, and how a later report should
describe the risk. Nothing in this module searches a file. The taint engine
has to build a path from a source to a destination before a rule can fire.

Severities chosen for the first version:

- ``medium`` for potential exposure. An environment read is not automatically
  a secret, and printing it is not proof that an attacker can see it.
- ``high`` for potential command injection. Untrusted input reaching a
  command call is the more serious of the two checks, especially if a later
  version sees ``shell=True``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """One configured check. Defining a rule does not run it."""

    rule_id: str
    title: str
    severity: str
    sources: tuple[str, ...]
    sinks: tuple[str, ...]
    explanation: str
    recommended_fix: str
    limitation: str


_NOT_PROVEN = (
    "A match is a potential risk based on the configured names and a tracked "
    "path. FlowGuard does not execute the program and does not prove that "
    "the flow is exploitable."
)


RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="FG001",
        title="Potential sensitive-data exposure",
        severity="medium",
        sources=("os.getenv", "os.environ.get"),
        sinks=(
            "print",
            "logging.debug",
            "logging.info",
            "logging.warning",
            "logging.error",
            "logging.critical",
        ),
        explanation=(
            "A value read by a configured secret source may reach a print "
            "or logging call. This is a potential exposure: not every "
            "environment variable is a secret."
        ),
        recommended_fix=(
            "Avoid sending secret values to logs or standard output. "
            "Redact them, or log only the fact that a value was loaded."
        ),
        limitation=_NOT_PROVEN,
    ),
    Rule(
        rule_id="FG002",
        title="Potential command injection",
        severity="high",
        sources=("input",),
        sinks=(
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_output",
            "subprocess.Popen",
            "os.system",
        ),
        explanation=(
            "A value from a configured untrusted-input source may reach a "
            "command-execution call. shell=True makes that pattern more "
            "dangerous when it is present, but the rule still describes a "
            "potential risk rather than a confirmed exploit."
        ),
        recommended_fix=(
            "Do not build a shell command from untrusted input. Pass a "
            "fixed program and a list of arguments to subprocess, and avoid "
            "shell=True."
        ),
        limitation=_NOT_PROVEN,
    ),
)


def get_rule(rule_id: str) -> Rule:
    """Return one configured rule by its id, such as ``FG001``."""

    for rule in RULES:
        if rule.rule_id == rule_id:
            return rule
    known_ids = ", ".join(rule.rule_id for rule in RULES)
    raise KeyError(f"Unknown rule {rule_id!r}. Known rules: {known_ids}")
