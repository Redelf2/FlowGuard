"""Turn Python source into assignments and function calls.

An abstract syntax tree (AST) is a structured form of the source. For example,
``backup = secret`` becomes an assignment node whose target is ``backup`` and
whose value is the name ``secret``. Walking that tree lets FlowGuard see
names, calls, and line numbers without running the file.

``ast.parse`` only reads the text. It does not import the target module and
does not call any function defined in it.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


class FlowGuardSyntaxError(Exception):
    """The file exists, but it is not valid Python."""

    def __init__(self, path: str, detail: str, line: int | None = None) -> None:
        self.path = path
        self.line = line
        if line is None:
            message = f"{path}: {detail}"
        else:
            message = f"{path}:{line}: {detail}"
        super().__init__(message)


class SourceReadError(Exception):
    """The path could not be read as UTF-8 source text."""


@dataclass(frozen=True)
class Assignment:
    """A value stored in a simple variable name.

    ``value_kind`` says what the right-hand side is:

    - ``name``: another variable, as in ``backup = secret``
    - ``call``: a direct function call, as in ``secret = os.getenv("API_KEY")``
    - ``constant``: a literal such as ``"public"`` or ``1``
    - ``augassign``: an update such as ``secret += extra``
    - ``other``: a shape this version only labels, such as a list or lambda
    """

    target: str
    line: int
    value_kind: str
    value_repr: str


@dataclass(frozen=True)
class KeywordArgument:
    """One keyword at a call, such as ``shell=True``."""

    name: str
    value: str


@dataclass(frozen=True)
class FunctionCall:
    """One call found in the file, including calls nested inside other calls."""

    name: str
    line: int
    arguments: tuple[str, ...]
    keywords: tuple[KeywordArgument, ...]


@dataclass(frozen=True)
class ParseResult:
    """Facts collected from one source file.

    The same variable name can appear more than once. This object does not
    decide which assignment is the current value, and it does not decide
    whether two functions share a variable. That is taint tracking, which is
    not done here.
    """

    path: str
    assignments: tuple[Assignment, ...]
    calls: tuple[FunctionCall, ...]


def parse_file(path: str | Path) -> ParseResult:
    """Read a source file and parse it. The file is not executed."""

    # Step 1: Accept a file path and reject directories or missing paths.
    file_path = Path(path)
    if file_path.is_dir():
        raise IsADirectoryError(
            f"Expected a Python file, but this path is a directory: {file_path}"
        )
    if not file_path.is_file():
        raise FileNotFoundError(f"Python file not found: {file_path}")

    # Step 2: Read the bytes as UTF-8 text. Opening a file for reading does
    # not run it.
    try:
        source = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise SourceReadError(f"Could not read {file_path} as UTF-8 text.") from exc
    except OSError as exc:
        detail = exc.strerror or str(exc)
        raise SourceReadError(f"Could not read {file_path}: {detail}") from exc

    # Step 3: Parse the text into assignments and calls.
    return parse_source(source, path=str(file_path))


def parse_source(source: str, path: str = "<string>") -> ParseResult:
    """Parse Python source text that is already in memory."""

    # Step 1: Build an AST. A syntax error becomes our own exception so the
    # command line can print a short message instead of a traceback.
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        detail = exc.msg or "invalid syntax"
        raise FlowGuardSyntaxError(path, detail, line=exc.lineno) from exc

    # Step 2: Walk the tree in source order and keep the facts we need.
    collector = _StructureCollector()
    collector.visit(tree)
    return ParseResult(
        path=path,
        assignments=tuple(collector.assignments),
        calls=tuple(collector.calls),
    )


def _dotted_name(node: ast.expr) -> str | None:
    """Return ``os.getenv`` for a name or attribute chain, or None if the
    expression is more complicated than a dotted name.
    """

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        if prefix is None:
            return None
        return f"{prefix}.{node.attr}"
    return None


def _describe_expression(node: ast.expr) -> tuple[str, str]:
    """Return a short kind and text label for an expression."""

    if isinstance(node, ast.Name):
        return "name", node.id
    if isinstance(node, ast.Constant):
        return "constant", repr(node.value)
    if isinstance(node, ast.Call):
        return "call", _dotted_name(node.func) or "<complex>"
    return "other", type(node).__name__


def _argument_text(node: ast.expr) -> str:
    """Describe one argument without trying to evaluate it."""

    if isinstance(node, ast.Starred):
        return "*" + _argument_text(node.value)
    kind, text = _describe_expression(node)
    if kind == "call":
        return f"{text}()"
    return text


class _StructureCollector(ast.NodeVisitor):
    """Collect simple assignments and every function call.

    ``NodeVisitor`` starts at the top of the file and walks inward. Overriding
    a visit method lets us record a node, then ``generic_visit`` continues
    into the nodes inside it.
    """

    def __init__(self) -> None:
        self.assignments: list[Assignment] = []
        self.calls: list[FunctionCall] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        # Step 1: Record each plain name on the left. ``a = b = value`` has
        # two targets. Unpacking such as ``a, b = pair`` is left for later.
        value_kind, value_repr = _describe_expression(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assignments.append(
                    Assignment(
                        target=target.id,
                        line=node.lineno,
                        value_kind=value_kind,
                        value_repr=value_repr,
                    )
                )

        # Step 2: Walk the right-hand side so a call used as the value is
        # recorded too.
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        # Step 1: ``secret: str = os.getenv("API_KEY")`` stores a value.
        # ``secret: str`` does not, so there is no assignment to record.
        if isinstance(node.target, ast.Name) and node.value is not None:
            value_kind, value_repr = _describe_expression(node.value)
            self.assignments.append(
                Assignment(
                    target=node.target.id,
                    line=node.lineno,
                    value_kind=value_kind,
                    value_repr=value_repr,
                )
            )

        # Step 2: Visit the value so its calls are still collected.
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # Step 1: ``secret += extra`` changes an existing name. Keep it
        # distinct from a normal assignment so later tracking can treat it
        # carefully instead of pretending the value was replaced outright.
        if isinstance(node.target, ast.Name):
            _value_kind, value_repr = _describe_expression(node.value)
            self.assignments.append(
                Assignment(
                    target=node.target.id,
                    line=node.lineno,
                    value_kind="augassign",
                    value_repr=value_repr,
                )
            )

        # Step 2: Visit the added value in case it contains a call.
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Step 1: Record this call. Nested calls are separate records.
        keywords: list[KeywordArgument] = []
        for keyword in node.keywords:
            if keyword.arg is None:
                keywords.append(
                    KeywordArgument(name="**", value=_argument_text(keyword.value))
                )
            else:
                keywords.append(
                    KeywordArgument(
                        name=keyword.arg,
                        value=_argument_text(keyword.value),
                    )
                )

        self.calls.append(
            FunctionCall(
                name=_dotted_name(node.func) or "<complex>",
                line=node.lineno,
                arguments=tuple(_argument_text(arg) for arg in node.args),
                keywords=tuple(keywords),
            )
        )

        # Step 2: Visit arguments and the callee so inner calls are recorded
        # after the outer call.
        self.generic_visit(node)
