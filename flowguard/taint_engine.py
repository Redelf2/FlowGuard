"""Track tainted values through simple assignments.

Taint means a label on a value that came from a configured source. The
sources are the call names listed on the rules in ``rules.py``: ``os.getenv``,
``os.environ.get``, and ``input``.

Inside one scope, the engine walks assignments from top to bottom:

- ``secret = os.getenv("API_KEY")`` marks ``secret`` tainted.
- ``backup = secret`` copies that mark onto ``backup``.
- ``secret = "public"`` removes the mark from ``secret`` only.

A scope is the module body, one function body, or one class body. A name
assigned in one function is not the same name in another function.

``apply_rules`` in ``rules.py`` uses the tainted names that are current
when each call is reached. This module still does not decide that a
flow is a vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass

from flowguard.aliases import resolve_alias
from flowguard.parser import Assignment, FunctionCall, ParseResult
from flowguard.rules import RULES

_CLEAN = "clean"
_TAINTED = "tainted"
_UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class TaintedName:
    """The current value of one name in one scope came from a source call."""

    scope: str
    name: str
    source: str
    source_line: int
    line: int
    path: tuple[str, ...]


@dataclass(frozen=True)
class UnsupportedName:
    """The current value of one name is outside the rules this engine follows."""

    scope: str
    name: str
    line: int
    reason: str


@dataclass(frozen=True)
class TaintResult:
    """Final bindings after every assignment in the file has been applied.

    Only tainted and unsupported names are listed. A name that was tainted
    and later assigned a constant is absent from both lists.
    """

    tainted: tuple[TaintedName, ...]
    unsupported: tuple[UnsupportedName, ...]

    def is_tainted(self, scope: str, name: str) -> bool:
        return any(item.scope == scope and item.name == name for item in self.tainted)

    def tainted_binding(self, scope: str, name: str) -> TaintedName | None:
        for item in self.tainted:
            if item.scope == scope and item.name == name:
                return item
        return None

    def unsupported_reason(self, scope: str, name: str) -> str | None:
        for item in self.unsupported:
            if item.scope == scope and item.name == name:
                return item.reason
        return None


@dataclass
class _Binding:
    """The current status of one name while a scope is being walked."""

    status: str
    source: str = ""
    source_line: int = 0
    line: int = 0
    path: tuple[str, ...] = ()
    reason: str = ""


def configured_sources() -> frozenset[str]:
    """Return the source call names declared by the current rules."""

    names: set[str] = set()
    for rule in RULES:
        names.update(rule.sources)
    return frozenset(names)


def trace_assignments(parse_result: ParseResult) -> TaintResult:
    """Follow direct assignments and aliases inside each scope.

    The result is the state after the last assignment to each name. It is
    not a vulnerability report.
    """

    # The final names ignore calls. Call order is handled in the same walk.
    bindings_by_scope, _calls = _walk(parse_result)
    return _result_from_bindings(bindings_by_scope)


def tainted_names_at_calls(
    parse_result: ParseResult,
) -> tuple[tuple[FunctionCall, tuple[TaintedName, ...]], ...]:
    """Return each call with the tainted names in its scope at that moment.

    Assignments after the call do not affect it. A name cleared on a later
    line can still have reached an earlier sink.
    """

    _bindings, calls = _walk(parse_result)
    return tuple(calls)


def _walk(
    parse_result: ParseResult,
) -> tuple[
    dict[str, dict[str, _Binding]],
    list[tuple[FunctionCall, tuple[TaintedName, ...]]],
]:
    """Replay assignments and calls in source order, one scope at a time."""

    # Step 1: Read sources and whole-scope declarations such as global.
    sources = configured_sources()
    declared: dict[str, dict[str, str]] = {}
    for declaration in parse_result.declarations:
        declared.setdefault(declaration.scope, {})[declaration.name] = declaration.kind

    # Step 2: Interleave assignments and calls by the parser's sequence number.
    events: list[tuple[int, str, Assignment | FunctionCall]] = []
    for assignment in parse_result.assignments:
        events.append((assignment.sequence, "assignment", assignment))
    for call in parse_result.calls:
        events.append((call.sequence, "call", call))
    events.sort(key=lambda item: item[0])

    # Step 3: Update only the scope that owns each event.
    bindings_by_scope: dict[str, dict[str, _Binding]] = {}
    calls: list[tuple[FunctionCall, tuple[TaintedName, ...]]] = []
    for _sequence, kind, event in events:
        scope_bindings = bindings_by_scope.setdefault(event.scope, {})
        if kind == "assignment" and isinstance(event, Assignment):
            _apply_assignment(
                scope_bindings,
                event,
                sources,
                declared.get(event.scope, {}),
                parse_result,
            )
            continue
        if isinstance(event, FunctionCall):
            calls.append((event, _tainted_snapshot(event.scope, scope_bindings)))
    return bindings_by_scope, calls


def _result_from_bindings(
    bindings_by_scope: dict[str, dict[str, _Binding]],
) -> TaintResult:
    """Keep the final tainted and unsupported names. Omit clean names."""

    tainted: list[TaintedName] = []
    unsupported: list[UnsupportedName] = []
    for scope, bindings in bindings_by_scope.items():
        for name, binding in bindings.items():
            if binding.status == _TAINTED:
                tainted.append(_tainted_name(scope, name, binding))
            elif binding.status == _UNSUPPORTED:
                unsupported.append(
                    UnsupportedName(
                        scope=scope,
                        name=name,
                        line=binding.line,
                        reason=binding.reason,
                    )
                )
    return TaintResult(tainted=tuple(tainted), unsupported=tuple(unsupported))


def _tainted_snapshot(
    scope: str,
    bindings: dict[str, _Binding],
) -> tuple[TaintedName, ...]:
    names = [
        _tainted_name(scope, name, binding)
        for name, binding in bindings.items()
        if binding.status == _TAINTED
    ]
    return tuple(names)


def _tainted_name(scope: str, name: str, binding: _Binding) -> TaintedName:
    return TaintedName(
        scope=scope,
        name=name,
        source=binding.source,
        source_line=binding.source_line,
        line=binding.line,
        path=binding.path,
    )


def _apply_assignment(
    bindings: dict[str, _Binding],
    assignment: Assignment,
    sources: frozenset[str],
    declared_names: dict[str, str],
    parsed: ParseResult,
) -> None:
    """Replace or update one name from a single assignment."""

    # Step 1: global and nonlocal cross scopes. Do not invent that link.
    kind = declared_names.get(assignment.target)
    if kind is not None:
        bindings[assignment.target] = _Binding(
            status=_UNSUPPORTED,
            line=assignment.line,
            reason=(
                f"{kind} does not link this assignment to another scope"
            ),
        )
        return

    # Step 2: += keeps the old value and mixes in the right-hand side.
    if assignment.value_kind == "augassign":
        bindings[assignment.target] = _apply_augmented(
            bindings, assignment, sources, parsed
        )
        return

    # Step 3: A normal assignment replaces whatever the name held before.
    bindings[assignment.target] = _binding_from_value(
        bindings,
        target=assignment.target,
        line=assignment.line,
        value_kind=assignment.value_kind,
        value_repr=assignment.value_repr,
        sources=sources,
        scope=assignment.scope,
        parsed=parsed,
    )


def _apply_augmented(
    bindings: dict[str, _Binding],
    assignment: Assignment,
    sources: frozenset[str],
    parsed: ParseResult,
) -> _Binding:
    """Combine ``name += value`` with the name's current binding."""

    current = bindings.get(assignment.target)
    added = _binding_from_value(
        bindings,
        target=assignment.target,
        line=assignment.line,
        value_kind=assignment.operand_kind or "other",
        value_repr=assignment.value_repr,
        sources=sources,
        scope=assignment.scope,
        parsed=parsed,
    )

    # An earlier source still wins when both sides are tainted.
    if current is not None and current.status == _TAINTED:
        return _retarget(current, assignment.target, assignment.line)
    if added.status == _TAINTED:
        return added
    if added.status == _UNSUPPORTED:
        return _Binding(
            status=_UNSUPPORTED,
            line=assignment.line,
            reason=added.reason,
        )
    if current is not None and current.status == _UNSUPPORTED:
        return _Binding(
            status=_UNSUPPORTED,
            line=assignment.line,
            reason=current.reason,
        )
    return _Binding(status=_CLEAN, line=assignment.line)


def _binding_from_value(
    bindings: dict[str, _Binding],
    target: str,
    line: int,
    value_kind: str,
    value_repr: str,
    sources: frozenset[str],
    scope: str,
    parsed: ParseResult,
) -> _Binding:
    """Classify one right-hand side. Callers store the result on ``target``."""

    # An import alias such as getenv can mean os.getenv. The written name stays
    # in the parser output; only this check uses the resolved source.
    called_name = value_repr
    if value_kind == "call":
        called_name = resolve_alias(parsed, scope, value_repr)
    if value_kind == "call" and called_name in sources:
        return _Binding(
            status=_TAINTED,
            source=called_name,
            source_line=line,
            line=line,
            path=(target,),
        )
    if value_kind == "call":
        return _Binding(
            status=_UNSUPPORTED,
            line=line,
            reason=(
                f"call to {value_repr} is not a configured source, "
                "and a call is not treated as removing taint"
            ),
        )
    if value_kind == "constant":
        return _Binding(status=_CLEAN, line=line)
    if value_kind == "name":
        return _copy_name(bindings, target, line, value_repr)
    return _Binding(
        status=_UNSUPPORTED,
        line=line,
        reason="right-hand side is not a simple name, constant, or direct call",
    )


def _copy_name(
    bindings: dict[str, _Binding],
    target: str,
    line: int,
    source_name: str,
) -> _Binding:
    """Copy the current binding of ``source_name`` onto ``target``."""

    current = bindings.get(source_name)
    if current is None:
        return _Binding(
            status=_UNSUPPORTED,
            line=line,
            reason=(
                f"{source_name} has no assignment in this scope. "
                "Parameters, closures, and names from other scopes are not tracked"
            ),
        )
    if current.status == _CLEAN:
        return _Binding(status=_CLEAN, line=line)
    if current.status == _TAINTED:
        return _retarget(current, target, line)
    return _Binding(
        status=_UNSUPPORTED,
        line=line,
        reason=current.reason or f"{source_name} is not a tracked value",
    )


def _retarget(binding: _Binding, target: str, line: int) -> _Binding:
    """Point an existing tainted binding at a new name without changing its source."""

    path = binding.path
    if not path or path[-1] != target:
        path = path + (target,)
    return _Binding(
        status=_TAINTED,
        source=binding.source,
        source_line=binding.source_line,
        line=line,
        path=path,
        reason=binding.reason,
    )


def _is(binding: _Binding | None, status: str) -> bool:
    return binding is not None and binding.status == status
