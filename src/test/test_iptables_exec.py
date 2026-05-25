"""Tests: iptables_exec subprocess wrappers."""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from src.iptables_exec import ensure_chain, iptables_list_chain, run_iptables


def _ok(stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["iptables"], 0, stdout, "")


def _fail() -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["iptables"], 1, "", "nope")


class TestRunIptables(unittest.TestCase):
    @patch("src.iptables_exec.subprocess.run")
    def test_passes_shell_false(self, m_run: MagicMock) -> None:
        m_run.return_value = _ok()
        run_iptables(["/sbin/iptables", "-L"], capture=True)
        m_run.assert_called_once()
        kw = m_run.call_args[1]
        self.assertFalse(kw["shell"])


class TestIptablesListChain(unittest.TestCase):
    @patch("src.iptables_exec.run_iptables")
    def test_empty_on_failure(self, m_run: MagicMock) -> None:
        m_run.return_value = _fail()
        self.assertEqual(iptables_list_chain("/sbin/iptables", "nat", "X"), "")

    @patch("src.iptables_exec.run_iptables")
    def test_returns_stdout(self, m_run: MagicMock) -> None:
        m_run.return_value = _ok("-A X -j RETURN\n")
        self.assertEqual(iptables_list_chain("/sbin/iptables", "nat", "X"), "-A X -j RETURN\n")


class TestEnsureChain(unittest.TestCase):
    @patch("src.iptables_exec.run_iptables")
    def test_skips_when_no_create(self, m_run: MagicMock) -> None:
        ensure_chain("/sbin/iptables", "nat", "NEW", no_create=True)
        m_run.assert_not_called()

    @patch("src.iptables_exec.run_iptables")
    def test_creates_chain(self, m_run: MagicMock) -> None:
        m_run.return_value = _ok()
        ensure_chain("/sbin/iptables", "nat", "NEW", no_create=False)
        m_run.assert_called_once()
        self.assertEqual(
            m_run.call_args[0][0],
            ["/sbin/iptables", "-t", "nat", "-N", "NEW"],
        )


if __name__ == "__main__":
    unittest.main()
