"""Tests: logging_util setup (no crash)."""

from __future__ import annotations

import logging
import unittest

from src.logging_util import setup_logging


class TestSetupLogging(unittest.TestCase):
    def test_stderr_only(self) -> None:
        log = setup_logging("info", debug=False, no_syslog=True)
        self.assertIsInstance(log, logging.Logger)
        self.assertEqual(log.name, "iptablesman")


if __name__ == "__main__":
    unittest.main()
