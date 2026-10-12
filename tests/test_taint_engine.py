"""Tests for the taint-tracking boundary in Milestone 1.

Taint tracking is intentionally not implemented. These tests lock that
behavior so an empty result cannot be mistaken for a finished analysis.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flowguard.taint_engine import track_taint


class TaintEngineTests(unittest.TestCase):
    def test_tracking_is_not_implemented(self) -> None:
        with self.assertRaises(NotImplementedError) as caught:
            track_taint(None)

        self.assertIn("not implemented", str(caught.exception).lower())


if __name__ == "__main__":
    unittest.main()
