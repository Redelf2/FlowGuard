"""The taint engine is intentionally not implemented in milestone 1."""

from __future__ import annotations

import unittest

from flowguard.parser import parse_source
from flowguard.taint_engine import trace_assignments


class TaintEngineTests(unittest.TestCase):
    def test_tracing_assignments_is_not_implemented_yet(self) -> None:
        parsed = parse_source(
            "secret = os.getenv('API_KEY')\nbackup = secret\n",
            path="example.py",
        )

        with self.assertRaises(NotImplementedError) as caught:
            trace_assignments(parsed)

        message = str(caught.exception)
        self.assertIn("not implemented", message.lower())
        self.assertIn("example.py", message)


if __name__ == "__main__":
    unittest.main()
