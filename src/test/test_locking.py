"""Tests: lockfile behavior."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.locking import acquire_single_instance_lock


class TestLocking(unittest.TestCase):
    def test_lock_blocks_second_instance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lp = Path(tmp) / "iptablesman.lock"
            with acquire_single_instance_lock(lp):
                with self.assertRaises(RuntimeError):
                    with acquire_single_instance_lock(lp):
                        pass


if __name__ == "__main__":
    unittest.main()

