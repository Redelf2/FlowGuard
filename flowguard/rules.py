"""The security checks FlowGuard applies.

A rule pairs source calls with destination calls. ``apply_rules`` reports a
finding only when a tracked value from that rule's sources reaches one of
that rule's destinations in the same scope. A finding is a potential risk,
not proof that the program can be exploited.

Severities chosen for the first version:

- ``medium`` for potential exposure. An environment read is not automatically
  a secret, and printing it is not proof that an attacker can see it.
- ``high`` for potential command injection. Untrusted input reaching a
  command call is the more serious of the two checks. ``shell=True`` raises
  confidence; it does not prove the program can be exploited.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from flowguard.parser import FunctionCall, ParseResult


@dataclass(frozen=True)
class Rule:
    """One configured check. The rule describes a flow; ``apply_rules`` looks for it."""

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


@dataclass(frozen=True)
class Finding:
    """One potential risk. The path was tracked; the program was not run."""

    rule_id: str
    title: str
    severity: str
    file: str
    source: str
    source_line: int
    sink: str
    sink_line: int
    path: tuple[str, ...]
    confidence: str
    explanation: str
    recommended_fix: str
    limitation: str

    def flow_text(self) -> str:
        return " -> ".join(self.path)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["path"] = list(self.path)
        return payload


@dataclass(frozen=True)
class _ReachedValue:
    """A tainted value that appears in a sink's arguments."""

    source: str
    source_line: int
    path: tuple[str, ...]


def apply_rules(parse_result: ParseResult) -> tuple[Finding, ...]:
    """Return potential findings for tracked source-to-sink paths.

    The import is inside the function so ``rules`` and the taint engine can
    refer to each other without a cycle while either module is loading.
    """

    # Step 1: Ask the taint engine which names are tainted at each call.
    from flowguard.taint_engine import configured_sources, tainted_names_at_calls

    sources = configured_sources()
    findings: list[Finding] = []
    seen: set[tuple[str, int, str, tuple[str, ...]]] = set()
    for call, tainted_names in tainted_names_at_calls(parse_result):
        tainted_by_name = {item.name: item for item in tainted_names}

        # Step 2: Keep only sinks, and only values that came from that rule's sources.
        for rule in RULES:
            if call.name not in rule.sinks:
                continue
            for reached in _reached_values(
                call, tainted_by_name, sources, parse_result
            ):
                if reached.source not in rule.sources:
                    continue
                path = reached.path + (call.name,)
                key = (rule.rule_id, call.line, call.name, path)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    _make_finding(parse_result.path, rule, call, reached, path)
                )
    return tuple(findings)


def _reached_values(
    call: FunctionCall,
    tainted_by_name: dict[str, object],
    sources: frozenset[str],
    parsed: ParseResult,
) -> list[_ReachedValue]:
    """Find tainted names and direct source calls used as arguments."""

    from flowguard.taint_engine import TaintedName

    reached: list[_ReachedValue] = []
    for text in _argument_texts(call):
        name = _simple_name(text)
        if name is not None:
            binding = tainted_by_name.get(name)
            if isinstance(binding, TaintedName):
                reached.append(
                    _ReachedValue(binding.source, binding.source_line, binding.path)
                )
            continue
        written_name, source_name = _direct_source_name(text, sources, call, parsed)
        if source_name is None or written_name is None:
            continue
        reached.append(
            _ReachedValue(
                source=source_name,
                source_line=_direct_source_line(call, written_name, parsed.calls),
                path=(source_name,),
            )
        )
    return reached


def _argument_texts(call: FunctionCall) -> list[str]:
    texts = list(call.arguments)
    texts.extend(keyword.value for keyword in call.keywords)
    return texts


def _simple_name(text: str) -> str | None:
    if text.isidentifier():
        return text
    if text.startswith("*") and text[1:].isidentifier():
        return text[1:]
    return None


def _direct_source_name(
    text: str,
    sources: frozenset[str],
    call: FunctionCall,
    parsed: ParseResult,
) -> tuple[str | None, str | None]:
    """Return the written call name and the source it resolves to."""

    from flowguard.aliases import resolve_alias

    if not text.endswith("()"):
        return None, None
    written_name = text[:-2]
    source_name = resolve_alias(parsed, call.scope, written_name)
    if source_name in sources:
        return written_name, source_name
    return None, None


def _direct_source_line(
    call: FunctionCall,
    source_name: str,
    calls: tuple[FunctionCall, ...],
) -> int:
    """Use the inner call's line when ``print(os.getenv(...))`` spans lines."""

    for other in calls:
        if (
            other.scope == call.scope
            and other.sequence > call.sequence
            and other.name == source_name
        ):
            return other.line
    return call.line


def _make_finding(
    file_path: str,
    rule: Rule,
    call: FunctionCall,
    reached: _ReachedValue,
    path: tuple[str, ...],
) -> Finding:
    confidence, extra = _sink_note(rule, call)
    explanation = rule.explanation
    if extra:
        explanation = f"{explanation} {extra}"
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        file=file_path,
        source=reached.source,
        source_line=reached.source_line,
        sink=call.name,
        sink_line=call.line,
        path=path,
        confidence=confidence,
        explanation=explanation,
        recommended_fix=rule.recommended_fix,
        limitation=rule.limitation,
    )


def _sink_note(rule: Rule, call: FunctionCall) -> tuple[str, str]:
    """Describe shell use without treating it as proof of exploitability."""

    if rule.rule_id != "FG002":
        return "limited", ""
    if call.name == "os.system":
        return (
            "increased",
            "os.system passes its string to a shell.",
        )
    shell_value = next(
        (keyword.value for keyword in call.keywords if keyword.name == "shell"),
        None,
    )
    if shell_value == "True":
        return (
            "increased",
            "The call passes shell=True, so a string may be read as a shell command.",
        )
    if call.name.startswith("subprocess."):
        return (
            "limited",
            "shell=True was not seen on this call. A tainted value can still be risky, "
            "but this is not proof that a shell runs it.",
        )
    return "limited", ""
