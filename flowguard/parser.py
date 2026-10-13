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

    ``scope`` says where the assignment is written. ``<module>`` is the file
    body. A function or class adds its name and line, such as ``load:4``.
    ``operand_kind`` is set for ``+=`` so ``secret += extra`` (a name) stays
    distinct from ``secret += input()`` (a call).
    """

    target: str
    line: int
    value_kind: str
    value_repr: str
    scope: str = "<module>"
    operand_kind: str = ""


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
    scope: str = "<module>"


@dataclass(frozen=True)
class NameDeclaration:
    """A ``global`` or ``nonlocal`` name.

    These statements tell Python that a name belongs to another scope.
    FlowGuard records them so taint tracking does not pretend the name is local.
    """

    scope: str
    name: str
    kind: str
    line: int


@dataclass(frozen=True)
class ParseResult:
    """Facts collected from one source file.

    The same variable name can appear more than once. This object does not
    decide which assignment is the current value. ``scope`` keeps one
    function separate from another. The taint engine makes that decision.
    """

    path: str
    assignments: tuple[Assignment, ...]
    calls: tuple[FunctionCall, ...]
    declarations: tuple[NameDeclaration, ...] = ()


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
        declarations=tuple(collector.declarations),
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
        self.declarations: list[NameDeclaration] = []
        self._scopes: list[str] = ["<module>"]

    def _scope(self) -> str:
        return self._scopes[-1]

    def _push_scope(self, name: str, line: int) -> None:
        label = f"{name}:{line}"
        parent = self._scopes[-1]
        if parent == "<module>":
            self._scopes.append(label)
        else:
            self._scopes.append(f"{parent}.{label}")

    def _pop_scope(self) -> None:
        self._scopes.pop()

    def _record_assignment(
        self,
        line: int,
        target: str,
        value_kind: str,
        value_repr: str,
        operand_kind: str = "",
    ) -> None:
        self.assignments.append(
            Assignment(
                target=target,
                line=line,
                value_kind=value_kind,
                value_repr=value_repr,
                scope=self._scope(),
                operand_kind=operand_kind,
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Step 1: Decorators and default values run outside the function.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for type_param in getattr(node, "type_params", ()):
            self.visit(type_param)
        self.visit(node.args)
        if node.returns is not None:
            self.visit(node.returns)

        # Step 2: The body is a separate scope from the surrounding code.
        self._push_scope(node.name, node.lineno)
        for statement in node.body:
            self.visit(statement)
        self._pop_scope()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Step 1: Decorators and base classes belong to the enclosing scope.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword)
        for type_param in getattr(node, "type_params", ()):
            self.visit(type_param)

        # Step 2: The class body is its own scope. A method pushes another one.
        self._push_scope(node.name, node.lineno)
        for statement in node.body:
            self.visit(statement)
        self._pop_scope()

    def visit_Global(self, node: ast.Global) -> None:
        for name in node.names:
            self.declarations.append(
                NameDeclaration(self._scope(), name, "global", node.lineno)
            )

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        for name in node.names:
            self.declarations.append(
                NameDeclaration(self._scope(), name, "nonlocal", node.lineno)
            )

    def visit_Assign(self, node: ast.Assign) -> None:
        # Step 1: Record each plain name on the left. ``a = b = value`` has
        # two targets. Unpacking such as ``a, b = pair`` is left for later.
        value_kind, value_repr = _describe_expression(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._record_assignment(node.lineno, target.id, value_kind, value_repr)

        # Step 2: Walk the right-hand side so a call used as the value is
        # recorded too.
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        # Step 1: ``secret: str = os.getenv("API_KEY")`` stores a value.
        # ``secret: str`` does not, so there is no assignment to record.
        if isinstance(node.target, ast.Name) and node.value is not None:
            value_kind, value_repr = _describe_expression(node.value)
            self._record_assignment(node.lineno, node.target.id, value_kind, value_repr)

        # Step 2: Visit the value so its calls are still collected.
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # Step 1: ``secret += extra`` changes an existing name. Keep it
        # distinct from a normal assignment so later tracking can treat it
        # carefully instead of pretending the value was replaced outright.
        if isinstance(node.target, ast.Name):
            operand_kind, value_repr = _describe_expression(node.value)
            self._record_assignment(
                node.lineno,
                node.target.id,
                "augassign",
                value_repr,
                operand_kind=operand_kind,
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
                scope=self._scope(),
            )
        )

        # Step 2: Visit arguments and the callee so inner calls are recorded
        # after the outer call.
        self.generic_visit(node)
