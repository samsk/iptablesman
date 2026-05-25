"""Tests: logging_util setup (no crash)."""

from __future__ import annotations

import logging
import logging.handlers
import unittest
from unittest.mock import patch

from src.logging_util import setup_logging


class TestSetupLogging(unittest.TestCase):
    def test_stderr_only(self) -> None:
        log = setup_logging("info", debug=False, no_syslog=True)
        self.assertEqual(log.name, "iptablesman")
        self.assertEqual(len(log.handlers), 1)
        self.assertIsInstance(log.handlers[0], logging.StreamHandler)

    @patch("src.logging_util.logging.handlers.SysLogHandler")
    def test_syslog_only_by_default(self, m_syslog_cls: object) -> None:
        m_syslog_cls.return_value = logging.handlers.SysLogHandler()
        log = setup_logging("info", debug=False, no_syslog=False)
        self.assertEqual(len(log.handlers), 1)
        self.assertIs(log.handlers[0], m_syslog_cls.return_value)

    @patch("src.logging_util.logging.handlers.SysLogHandler", side_effect=OSError)
    def test_syslog_fail_falls_back_stderr(self, _m_syslog_cls: object) -> None:
        log = setup_logging("info", debug=False, no_syslog=False)
        self.assertEqual(len(log.handlers), 1)
        self.assertIsInstance(log.handlers[0], logging.StreamHandler)


if __name__ == "__main__":
    unittest.main()
