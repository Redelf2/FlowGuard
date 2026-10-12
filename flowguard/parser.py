"""Turn Python source into assignments and function calls.

This module uses ``ast``, the standard-library parser. Parsing builds a
tree of syntax nodes. It does not run the file. For example, parsing can
see that a line calls ``os.getenv`` without reading an environment variable.

The result is a list of facts later stages can use:

* an assignment such as ``backup = secret``
* a call such as ``print(backup)`` or ``subprocess.run(user_input, shell=True)``

Facts keep the line number from the source file. The same variable name in
two places is listed twice. This module does not decide whether those names
refer to the same value. That is taint tracking, and it is not implemented yet.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


class FlowGuardParseError(Exception):
    """A file could not be parsed. The target program was not run."""


class SourceFileNotFoundError(FlowGuardParseError):
    """The path is missing or is not a file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(
            f"Cannot read Python file. Path does not exist or is not a file: {path}"
        )


class SourceReadError(FlowGuardParseError):
    """The path exists, but its text could not be read."""

    def __init__(self, path: Path, reason: str) -> None:
        self.path = path
        super().__init__(f"Could not read {path}: {reason}")


class InvalidPythonSyntaxError(FlowGuardParseError):
    """The file is not valid Python, so there is no syntax tree to inspect."""

    def __init__(self, filename: str, message: str, line: int | None) -> None:
        self.filename = filename
        self.line = line
        location = f"{filename}:{line}" if line is not None else filename
        super().__init__(f"Invalid Python syntax in {location}: {message}")


@dataclass(frozen=True)
class Assignment:
    """One name being stored, and the source text of the value stored in it.

    ``frozen`` means later code can pass these facts around without changing them.
    """

    line: int
    target: str
    value: str

    def to_dict(self) -> dict[str, object]:
        return {"line": self.line, "target": self.target, "value": self.value}


@dataclass(frozen=True)
class KeywordArgument:
    """One keyword argument, such as ``shell=True``."""

    name: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "value": self.value}


@dataclass(frozen=True)
class FunctionCall:
    """One function or method call, including arguments and the line it starts on."""

    line: int
    name: str
    arguments: tuple[str, ...]
    keywords: tuple[KeywordArgument, ...]

    def display(self) -> str:
        """Return source-like text such as ``subprocess.run(user_input, shell=True)``."""
        parts = list(self.arguments)
        for keyword in self.keywords:
            if keyword.name == "**":
                parts.append(f"**{keyword.value}")
            else:
                parts.append(f"{keyword.name}={keyword.value}")
        return f"{self.name}({', '.join(parts)})"

    def to_dict(self) -> dict[str, object]:
        return {
            "line": self.line,
            "name": self.name,
            "arguments": list(self.arguments),
            "keywords": [keyword.to_dict() for keyword in self.keywords],
        }


@dataclass(frozen=True)
class ParseResult:
    """Assignments and calls found in one Python file or source string."""

    path: str
    assignments: tuple[Assignment, ...]
    function_calls: tuple[FunctionCall, ...]


def parse_file(path: str | Path) -> ParseResult:
    """Read a Python file and list its assignments and calls.

    The file is read as text and parsed. It is never imported or executed.
    """
    source_path = Path(path)
    # Keep the caller's spelling. Path() on Windows would rewrite "/" as "\".
    filename = path if isinstance(path, str) else str(source_path)

    # Step 1: Reject missing paths and directories before trying to parse.
    if not source_path.is_file():
        raise SourceFileNotFoundError(source_path)

    # Step 2: Read source text only. Reading a file does not run it.
    try:
        source = source_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise SourceReadError(
            source_path,
            "file is not valid UTF-8 text. FlowGuard only reads UTF-8 Python source.",
        ) from exc
    except OSError as exc:
        raise SourceReadError(source_path, str(exc)) from exc

    # Step 3: Turn the text into assignments and calls.
    return parse_source(source, filename=filename)


def parse_source(source: str, filename: str = "<string>") -> ParseResult:
    """Parse Python source text that is already in memory."""
    # Step 1: Build a syntax tree. ast.parse does not execute statements.
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        raise InvalidPythonSyntaxError(
            filename=filename,
            message=exc.msg or "invalid syntax",
            line=exc.lineno,
        ) from exc

    # Step 2: Walk the tree and collect assignments and calls in visit order.
    collector = _SyntaxCollector()
    collector.visit(tree)
    return ParseResult(
        path=filename,
        assignments=tuple(collector.assignments),
        function_calls=tuple(collector.function_calls),
    )


class _SyntaxCollector(ast.NodeVisitor):
    """Walk an AST and record assignment and call nodes.

    A NodeVisitor visits every syntax node. We only record two kinds.
    Nested calls are still recorded, because visiting a call also visits
    its arguments. For example, ``print(os.getenv("API_KEY"))`` records
    both ``print`` and ``os.getenv``.
    """

    def __init__(self) -> None:
        self.assignments: list[Assignment] = []
        self.function_calls: list[FunctionCall] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        # `a = b = value` has two targets. Record both with the same value.
        for target in node.targets:
            self._record_assignment(node.lineno, target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        # `secret: str = ...` stores a value. `secret: str` does not.
        if node.value is not None:
            self._record_assignment(node.lineno, node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Step 1: Record this call, including keyword arguments such as shell=True.
        keywords = tuple(
            KeywordArgument(
                name=keyword.arg if keyword.arg is not None else "**",
                value=ast.unparse(keyword.value),
            )
            for keyword in node.keywords
        )
        self.function_calls.append(
            FunctionCall(
                line=node.lineno,
                name=_callable_name(node.func),
                arguments=tuple(ast.unparse(argument) for argument in node.args),
                keywords=keywords,
            )
        )

        # Step 2: Visit arguments so calls nested inside this call are recorded too.
        self.generic_visit(node)

    def _record_assignment(self, line: int, target: ast.AST, value: ast.AST) -> None:
        value_text = ast.unparse(value)
        for name in _names_being_assigned(target):
            self.assignments.append(Assignment(line=line, target=name, value=value_text))


def _names_being_assigned(target: ast.AST) -> list[str]:
    """Return the names written by an assignment target.

    Unpacking such as ``a, b = pair`` yields both ``a`` and ``b``.
    Each name is paired with the whole right-hand side. FlowGuard does
    not yet split that value into separate parts.
    """
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in target.elts:
            names.extend(_names_being_assigned(element))
        return names
    if isinstance(target, ast.Starred):
        return _names_being_assigned(target.value)
    return [ast.unparse(target)]


def _callable_name(func: ast.expr) -> str:
    """Return a readable call name such as ``print`` or ``os.getenv``.

    Import aliases are not resolved. ``from os import getenv`` followed by
    ``getenv(...)`` is recorded as ``getenv``, because that is the name
    written in the call.
    """
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return f"{_callable_name(func.value)}.{func.attr}"
    return ast.unparse(func)
