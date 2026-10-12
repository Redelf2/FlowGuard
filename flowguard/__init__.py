"""FlowGuard: a static analyzer for selected risky data flows in Python.

Version 0.1 reads Python files and lists assignments and function calls.
It does not track data flow or report vulnerabilities yet.
"""

__version__ = "0.1.0"

from flowguard.parser import (
    InvalidPythonSyntaxError,
    SourceFileNotFoundError,
    SourceReadError,
    parse_file,
    parse_source,
)

__all__ = [
    "InvalidPythonSyntaxError",
    "SourceFileNotFoundError",
    "SourceReadError",
    "__version__",
    "parse_file",
    "parse_source",
]
