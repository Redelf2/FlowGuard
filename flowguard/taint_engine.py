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

This module does not report vulnerabilities. A tainted name reaching
``print`` or ``subprocess.run`` is left for the next milestone.
"""

from __future__ import annotations

from dataclasses import dataclass

from flowguard.parser import Assignment, ParseResult
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

    # Step 1: Read the configured source calls. Do not keep a second copy.
    sources = configured_sources()

    # Step 2: Remember global and nonlocal names. Assignments to those names
    # stay in the scope where they are written, and are marked unsupported.
    declared: dict[str, dict[str, str]] = {}
    for declaration in parse_result.declarations:
        declared.setdefault(declaration.scope, {})[declaration.name] = declaration.kind

    # Step 3: Walk each scope on its own, in source order.
    grouped: dict[str, list[Assignment]] = {}
    for assignment in parse_result.assignments:
        grouped.setdefault(assignment.scope, []).append(assignment)

    tainted: list[TaintedName] = []
    unsupported: list[UnsupportedName] = []
    for scope, assignments in grouped.items():
        bindings: dict[str, _Binding] = {}
        for assignment in assignments:
            _apply_assignment(bindings, assignment, sources, declared.get(scope, {}))
        for name, binding in bindings.items():
            if binding.status == _TAINTED:
                tainted.append(
                    TaintedName(
                        scope=scope,
                        name=name,
                        source=binding.source,
                        source_line=binding.source_line,
                        line=binding.line,
                        path=binding.path,
                    )
                )
            elif binding.status == _UNSUPPORTED:
                unsupported.append(
                    UnsupportedName(
                        scope=scope,
                        name=name,
                        line=binding.line,
                        reason=binding.reason,
                    )
                )

    # Step 4: Return the final names. Clean names are omitted on purpose.
    return TaintResult(tainted=tuple(tainted), unsupported=tuple(unsupported))


def _apply_assignment(
    bindings: dict[str, _Binding],
    assignment: Assignment,
    sources: frozenset[str],
    declared_names: dict[str, str],
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
            bindings, assignment, sources
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
    )


def _apply_augmented(
    bindings: dict[str, _Binding],
    assignment: Assignment,
    sources: frozenset[str],
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
) -> _Binding:
    """Classify one right-hand side. Callers store the result on ``target``."""

    if value_kind == "call" and value_repr in sources:
        return _Binding(
            status=_TAINTED,
            source=value_repr,
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
