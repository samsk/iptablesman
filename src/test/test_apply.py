"""Tests: apply.sync_file with mocked iptables and resolve."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.apply import sync_file
from src.host_resolve import HostIpv4Detail


def _ok(rc: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["iptables"], rc, "", "")


class TestSyncFileFailures(unittest.TestCase):
    def test_bad_basename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "bad name"
            fp.write_text("-j RETURN\n", encoding="utf-8")
            ok = sync_file("/sbin/iptables", "nat", "C", fp, no_create_chain=True)
        self.assertFalse(ok)

    def test_read_error(self) -> None:
        fp = Path("/nonexistent/iptablesman-apply-readtest/okname")
        self.assertFalse(sync_file("/sbin/iptables", "nat", "C", fp, no_create_chain=True))


class TestSyncFileHappyPath(unittest.TestCase):
    @patch("src.apply.chain_snapshot_owned")
    @patch("src.apply.run_iptables")
    @patch("src.apply.ensure_chain")
    def test_append_new_rule(
        self,
        m_ensure: MagicMock,
        m_run: MagicMock,
        m_snap: MagicMock,
    ) -> None:
        m_run.return_value = _ok()
        m_snap.return_value = {}
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "r1"
            fp.write_text("-j RETURN\n", encoding="utf-8")
            ok = sync_file("/sbin/iptables", "nat", "MYCHAIN", fp, no_create_chain=True)
        self.assertTrue(ok)
        append_calls = [c for c in m_run.call_args_list if "-A" in c[0][0]]
        self.assertEqual(len(append_calls), 1)
        argv = append_calls[0][0][0]
        self.assertIn("MYCHAIN", argv)
        self.assertIn("--comment", argv)
        self.assertIn("r1", argv)

    @patch("src.apply.chain_snapshot_owned")
    @patch("src.apply.run_iptables")
    @patch("src.apply.ensure_chain")
    def test_noop_when_identical(
        self,
        m_ensure: MagicMock,
        m_run: MagicMock,
        m_snap: MagicMock,
    ) -> None:
        m_run.return_value = _ok()
        live_toks = ["-j", "RETURN", "-m", "comment", "--comment", "r1"]
        m_snap.side_effect = [
            {"r1": (1, live_toks)},
            {"r1": (1, live_toks)},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "r1"
            fp.write_text("-j RETURN\n", encoding="utf-8")
            ok = sync_file("/sbin/iptables", "nat", "MYCHAIN", fp, no_create_chain=True)
        self.assertTrue(ok)
        append_calls = [c for c in m_run.call_args_list if "-A" in c[0][0]]
        self.assertEqual(append_calls, [])

    @patch("src.apply.chain_snapshot_owned")
    @patch("src.apply.run_iptables")
    @patch("src.apply.ensure_chain")
    def test_noop_when_check_confirms_match(
        self,
        m_ensure: MagicMock,
        m_run: MagicMock,
        m_snap: MagicMock,
    ) -> None:
        """Token mismatch but -C returns 0: no -R (counter preservation)."""
        # live tokens differ from desired (kernel reordering simulation)
        live_toks = ["-j", "RETURN", "-m", "comment", "--comment", "r1", "--extra"]
        m_snap.side_effect = [
            {"r1": (1, live_toks)},
            {"r1": (1, live_toks)},
        ]
        # -C returns 0 (kernel confirms match)
        m_run.return_value = _ok(0)
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "r1"
            fp.write_text("-j RETURN\n", encoding="utf-8")
            ok = sync_file("/sbin/iptables", "nat", "MYCHAIN", fp, no_create_chain=True)
        self.assertTrue(ok)
        replace_calls = [c for c in m_run.call_args_list if "-R" in c[0][0]]
        self.assertEqual(replace_calls, [])
        check_calls = [c for c in m_run.call_args_list if "-C" in c[0][0]]
        self.assertEqual(len(check_calls), 1)

    @patch("src.apply.chain_snapshot_owned")
    @patch("src.apply.run_iptables")
    @patch("src.apply.ensure_chain")
    def test_replaces_when_check_fails(
        self,
        m_ensure: MagicMock,
        m_run: MagicMock,
        m_snap: MagicMock,
    ) -> None:
        """Token mismatch and -C non-zero: -R runs."""
        live_toks = ["-j", "DROP", "-m", "comment", "--comment", "r1"]
        m_snap.side_effect = [
            {"r1": (1, live_toks)},
            {"r1": (1, live_toks)},
        ]
        # -C returns non-zero (rule not in kernel as desired), -R succeeds
        m_run.side_effect = [_ok(1), _ok(0)]
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "r1"
            fp.write_text("-j RETURN\n", encoding="utf-8")
            ok = sync_file("/sbin/iptables", "nat", "MYCHAIN", fp, no_create_chain=True)
        self.assertTrue(ok)
        replace_calls = [c for c in m_run.call_args_list if "-R" in c[0][0]]
        self.assertEqual(len(replace_calls), 1)


class TestSyncFileUnresolvedNoState(unittest.TestCase):
    @patch("src.apply.chain_snapshot_owned")
    @patch("src.apply.run_iptables")
    @patch("src.apply.ensure_chain")
    @patch("src.apply.hosts_resolve_ipv4")
    @patch("src.apply.emit_host_syslog_alert")
    def test_alert_when_no_state(
        self,
        m_emit: MagicMock,
        m_res: MagicMock,
        m_ensure: MagicMock,
        m_run: MagicMock,
        m_snap: MagicMock,
    ) -> None:
        m_res.return_value = (
            False,
            [HostIpv4Detail("h", False, [], dns_error="boom")],
        )
        m_snap.return_value = {}
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "r1"
            fp.write_text("# @host=h\n-d h -j RETURN\n", encoding="utf-8")
            sync_file("/sbin/iptables", "filter", "C", fp, no_create_chain=True)
        m_emit.assert_called_once()
        self.assertIn("no IPv4 resolved", m_emit.call_args[0][0])


class TestSyncFileHostSubstitution(unittest.TestCase):
    @patch("src.apply.chain_snapshot_owned")
    @patch("src.apply.run_iptables")
    @patch("src.apply.ensure_chain")
    @patch("src.apply.hosts_resolve_ipv4")
    def test_substitutes_host_token_on_append(
        self,
        m_res: MagicMock,
        m_ensure: MagicMock,
        m_run: MagicMock,
        m_snap: MagicMock,
    ) -> None:
        m_res.return_value = (
            True,
            [HostIpv4Detail("h.example", True, ["10.0.0.1"])],
        )
        m_run.return_value = _ok()
        m_snap.return_value = {}
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "r1"
            fp.write_text("# @host=h.example\n-d h.example -j RETURN\n", encoding="utf-8")
            ok = sync_file("/sbin/iptables", "filter", "C", fp, no_create_chain=True)
        self.assertTrue(ok)
        append_calls = [c for c in m_run.call_args_list if "-A" in c[0][0]]
        self.assertEqual(len(append_calls), 1)
        argv = append_calls[0][0][0]
        self.assertIn("10.0.0.1", argv)
        self.assertNotIn("h.example", argv)

    @patch("src.apply.chain_snapshot_owned")
    @patch("src.apply.run_iptables")
    @patch("src.apply.ensure_chain")
    @patch("src.apply.hosts_resolve_ipv4")
    def test_noop_when_effective_matches_live(
        self,
        m_res: MagicMock,
        m_ensure: MagicMock,
        m_run: MagicMock,
        m_snap: MagicMock,
    ) -> None:
        m_res.return_value = (
            True,
            [HostIpv4Detail("h.example", True, ["10.0.0.1", "10.0.0.9"])],
        )
        m_run.return_value = _ok()
        live_body = ["-d", "10.0.0.1", "-j", "RETURN", "-m", "comment", "--comment", "r1"]
        m_snap.side_effect = [
            {"r1": (1, live_body)},
            {"r1": (1, live_body)},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "r1"
            fp.write_text("# @host=h.example\n-d h.example -j RETURN\n", encoding="utf-8")
            ok = sync_file("/sbin/iptables", "filter", "C", fp, no_create_chain=True)
        self.assertTrue(ok)
        replace_calls = [c for c in m_run.call_args_list if "-R" in c[0][0]]
        self.assertEqual(replace_calls, [])

    @patch("src.apply.chain_snapshot_owned")
    @patch("src.apply.run_iptables")
    @patch("src.apply.ensure_chain")
    @patch("src.apply.hosts_resolve_ipv4")
    def test_replace_when_chosen_ip_changes(
        self,
        m_res: MagicMock,
        m_ensure: MagicMock,
        m_run: MagicMock,
        m_snap: MagicMock,
    ) -> None:
        m_res.return_value = (
            True,
            [HostIpv4Detail("h.example", True, ["10.0.0.2", "10.0.0.3"])],
        )
        # -C returns 1 (desired rule not live), -R returns 0
        m_run.side_effect = [_ok(1), _ok(0)]
        live_body = ["-d", "10.0.0.3", "-j", "RETURN", "-m", "comment", "--comment", "r1"]
        m_snap.side_effect = [
            {"r1": (1, live_body)},
            {"r1": (1, live_body)},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "r1"
            fp.write_text("# @host=h.example\n-d h.example -j RETURN\n", encoding="utf-8")
            ok = sync_file("/sbin/iptables", "filter", "C", fp, no_create_chain=True)
        self.assertTrue(ok)
        replace_calls = [c for c in m_run.call_args_list if "-R" in c[0][0]]
        self.assertEqual(len(replace_calls), 1)
        self.assertIn("10.0.0.2", replace_calls[0][0][0])


class TestSyncFileTestMode(unittest.TestCase):
    @patch("src.apply.chain_snapshot_owned")
    @patch("src.apply.run_iptables")
    @patch("src.apply.ensure_chain")
    def test_test_mode_uses_check_only(
        self,
        m_ensure: MagicMock,
        m_run: MagicMock,
        m_snap: MagicMock,
    ) -> None:
        m_run.return_value = _ok(1)
        m_snap.return_value = {}
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "r1"
            fp.write_text("-j RETURN\n", encoding="utf-8")
            ok = sync_file(
                "/sbin/iptables",
                "nat",
                "MYCHAIN",
                fp,
                no_create_chain=True,
                test_mode=True,
            )
        self.assertTrue(ok)
        m_ensure.assert_not_called()
        c_calls = [c for c in m_run.call_args_list if "-C" in c[0][0]]
        self.assertEqual(len(c_calls), 1)
        self.assertEqual([c for c in m_run.call_args_list if "-A" in c[0][0]], [])
        self.assertEqual([c for c in m_run.call_args_list if "-R" in c[0][0]], [])
        self.assertEqual([c for c in m_run.call_args_list if "-D" in c[0][0]], [])

if __name__ == "__main__":
    unittest.main()
