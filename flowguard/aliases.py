"""Resolve a written call name to a known source, when an import says so.

The parser keeps the name that appears in the file. ``getenv()`` stays
``getenv`` in the call list. This module answers a separate question: does
that written name mean ``os.getenv`` in this scope?

Only a direct import of a known function is trusted. A local function,
parameter, or assignment with the same name hides the import. Two different
imports of the same local name are ignored.
"""

from __future__ import annotations

from flowguard.parser import ParseResult

# Suffixes that complete a known source after ``import os as name``.
_OS_SOURCE_TAILS = frozenset({"getenv", "environ.get"})


def resolve_alias(parsed: ParseResult, scope: str, written_name: str) -> str:
    """Return a known source name, or ``written_name`` when it should stay as written."""

    # Step 1: A name introduced in this scope is not the imported function.
    root_name = written_name.split(".", 1)[0]
    if _name_is_defined_here(parsed, scope, root_name):
        return written_name
    if scope in parsed.star_import_scopes:
        return written_name

    # Step 2: Trust an import written in this same scope when it is unambiguous.
    # A different import of the same local name blocks the module-level import.
    local_decision = _function_decision(parsed, scope, written_name)
    if local_decision == "blocked":
        return written_name
    if local_decision is not None:
        return local_decision
    module_source = _module_alias_source(parsed, scope, written_name)
    if module_source is not None:
        return module_source

    # Step 3: A module import applies inside a function that does not hide the name.
    if scope == "<module>":
        return written_name
    for parent_scope in _enclosing_scopes(scope):
        if _name_is_defined_here(parsed, parent_scope, root_name):
            return written_name
    module_decision = _function_decision(parsed, "<module>", written_name)
    if module_decision == "blocked":
        return written_name
    if module_decision is not None:
        return module_decision
    if "<module>" in parsed.star_import_scopes and "." not in written_name:
        return written_name
    module_dotted = _module_alias_source(parsed, "<module>", written_name)
    if module_dotted is not None:
        return module_dotted
    return written_name


def _function_decision(parsed: ParseResult, scope: str, written_name: str) -> str | None:
    """Return a source name, ``blocked`` when the import is not trusted, or None."""

    canonical_names = {
        binding.canonical_name
        for binding in parsed.imports
        if binding.scope == scope
        and binding.local_name == written_name
        and binding.kind == "function"
    }
    if not canonical_names:
        return None
    if len(canonical_names) != 1:
        return "blocked"
    canonical_name = next(iter(canonical_names))
    if not canonical_name:
        return "blocked"
    return canonical_name


def _module_alias_source(parsed: ParseResult, scope: str, written_name: str) -> str | None:
    if "." not in written_name:
        return None
    local_module, tail = written_name.split(".", 1)
    modules = {
        binding.canonical_name
        for binding in parsed.imports
        if binding.scope == scope
        and binding.local_name == local_module
        and binding.kind == "module"
    }
    if len(modules) != 1:
        return None
    module_name = next(iter(modules))
    if module_name == "os" and tail in _OS_SOURCE_TAILS:
        return f"os.{tail}"
    if module_name == "os.environ" and tail == "get":
        return "os.environ.get"
    return None


def _name_is_defined_here(parsed: ParseResult, scope: str, name: str) -> bool:
    if any(
        assignment.scope == scope and assignment.target == name
        for assignment in parsed.assignments
    ):
        return True
    return any(item.scope == scope and item.name == name for item in parsed.defined_names)


def _enclosing_scopes(scope: str) -> list[str]:
    scopes: list[str] = []
    current = scope
    while current != "<module>":
        if "." in current:
            current = current.rsplit(".", 1)[0]
        else:
            current = "<module>"
        scopes.append(current)
    return scopes
