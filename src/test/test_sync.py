"""Integration: sync_target_cycle dir-gone rate limit."""

from __future__ import annotations

import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
