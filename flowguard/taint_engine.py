"""Track tainted values from a source to later uses.

Taint tracking means labeling a value that came from a chosen source, then
following that label when the value is copied. In ``backup = secret``, the
label on ``secret`` should also be placed on ``backup``.

This module is only a placeholder in milestone 1. The parser can list
assignments, but it does not yet decide which later names still hold a
tainted value.
"""

from __future__ import annotations

from typing import NoReturn

from flowguard.parser import ParseResult


def trace_assignments(parse_result: ParseResult) -> NoReturn:
    """Follow direct assignments and aliases.

    Not implemented yet. Milestone 2 will use ``parse_result.assignments``
    to track copies such as ``backup = secret`` and to respect later
    reassignment inside the chosen scope.
    """

    raise NotImplementedError(
        "Taint tracking is not implemented yet for "
        f"{parse_result.path}. The next milestone will follow values "
        "through direct assignments and aliases."
    )
