"""Taint tracking for FlowGuard.

Taint tracking means labeling data that comes from a sensitive or untrusted
source and following that label as the data is copied between variables.

Example the next milestone will handle:

    secret = os.getenv("API_KEY")
    backup = secret

After ``backup = secret``, both names refer to data that started at ``os.getenv``.
If ``secret`` is later assigned a new value, the old label should not stick
to that new value.

This module does not do that yet. Calling it fails on purpose so a missing
implementation cannot be mistaken for "no risk found".
"""


def track_taint(parsed_program: object) -> list[object]:
    """Follow tainted values through assignments.

    Raises:
        NotImplementedError: taint tracking is the next milestone.
    """
    del parsed_program
    raise NotImplementedError(
        "Taint tracking is not implemented yet. "
        "FlowGuard can list assignments and calls, but it does not yet follow "
        "values from one variable to another."
    )
