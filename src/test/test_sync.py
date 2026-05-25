"""Integration: sync_target_cycle dir-gone and apply-failure backoff."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.public_api import SyncState, Target, sync_target_cycle


class TestDirGoneRateLimit(unittest.TestCase):
    def test_first_alert_then_rate_limit(self) -> None:
        st = SyncState()
        st.dir_ever_seen = True
        tgt = Target(table="nat", chain="X", path=Path("/nonexistent/iptablesman-test-path"))
        times = iter([0.0, 10.0, 400.0])

        def nt() -> float:
            return next(times)

        sync_target_cycle(tgt, "/usr/sbin/iptables", no_create_chain=True, state=st, now=nt)
        self.assertEqual(st.last_dir_gone_log, 0.0)
        sync_target_cycle(tgt, "/usr/sbin/iptables", no_create_chain=True, state=st, now=nt)
        self.assertEqual(st.last_dir_gone_log, 0.0)
        sync_target_cycle(tgt, "/usr/sbin/iptables", no_create_chain=True, state=st, now=nt)
        self.assertEqual(st.last_dir_gone_log, 400.0)


class TestApplyFailureBackoff(unittest.TestCase):
    @patch("src.targets.sync_file")
    def test_skips_retry_until_interval(self, m_sync: object) -> None:
        m_sync.return_value = False
        st = SyncState()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            fp = path / "r1"
            fp.write_text("-j RETURN\n", encoding="utf-8")
            tgt = Target(table="nat", chain="C", path=path)
            retry_sec = 60.0
            times = iter([0.0, 10.0, retry_sec + 1.0])

            def nt() -> float:
                return next(times)

            kw = {
                "no_create_chain": True,
                "state": st,
                "now": nt,
                "apply_failure_retry_interval": retry_sec,
            }
            sync_target_cycle(tgt, "/sbin/iptables", **kw)
            self.assertEqual(m_sync.call_count, 1)
            sync_target_cycle(tgt, "/sbin/iptables", **kw)
            self.assertEqual(m_sync.call_count, 1)
            sync_target_cycle(tgt, "/sbin/iptables", **kw)
            self.assertEqual(m_sync.call_count, 2)


if __name__ == "__main__":
    unittest.main()
