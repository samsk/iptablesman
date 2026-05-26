"""Tests: daemon loop timers and watch cooldown."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.config_watch import ConfigWatchResult
from src.daemon import DaemonConfig, _compute_wait_timeout, run_daemon_loop
from src.metrics import MetricsState
from src.targets import Target


class TestComputeWaitTimeout(unittest.TestCase):
    def test_min_of_timers(self) -> None:
        w = _compute_wait_timeout(
            now=100.0,
            interval=60.0,
            dns_interval=15.0,
            metrics_interval=60.0,
            last_interval_at=50.0,
            last_dns_at=90.0,
            last_metrics_at=50.0,
            prom_enabled=True,
        )
        self.assertEqual(w, 5.0)


class TestDaemonLoopTimers(unittest.TestCase):
    @patch("src.daemon.run_dns_pass")
    @patch("src.daemon.time.sleep")
    def test_dns_called_on_timer(
        self,
        m_sleep: MagicMock,
        m_dns: MagicMock,
    ) -> None:
        clock = [0.0]

        def now_fn() -> float:
            return clock[0]

        def sleep_fn(sec: float) -> None:
            clock[0] += sec
            if clock[0] >= 20.0:
                raise SystemExit(0)

        m_sleep.side_effect = sleep_fn

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "nat" / "C").mkdir(parents=True)
            cfg = DaemonConfig(
                config_dir=root,
                table=None,
                chain=None,
                interval=60.0,
                dns_interval=15.0,
                metrics_interval=120.0,
                apply_failure_retry_interval=300.0,
                no_create_chain=True,
                no_syslog=True,
                debug=False,
                config_watch=False,
                config_watch_scope="target",
                config_watch_min_interval=5.0,
                full_sync_on_interval=True,
            )
            prom = MagicMock()
            with self.assertRaises(SystemExit):
                run_daemon_loop(
                    cfg=cfg,
                    iptables_bin="/sbin/iptables",
                    resolve_targets=lambda *_: [],
                    host_log_state=MagicMock(),
                    metrics_state=MetricsState(),
                    prom=prom,
                    collect_counters=MagicMock(return_value=({}, {})),
                    count_rules=lambda _t: 0,
                    forced={"now": False},
                    now=now_fn,
                )
        self.assertGreaterEqual(m_dns.call_count, 1)


class TestDnsOnlyApply(unittest.TestCase):
    @patch("src.targets.sync_file")
    @patch("src.targets.dropin_has_hosts")
    def test_hosts_only_skips_static_file(
        self,
        m_has: MagicMock,
        m_sync: MagicMock,
    ) -> None:
        from src.targets import SyncState, sync_target_cycle

        m_has.side_effect = lambda fp: fp.name == "with-host"
        m_sync.return_value = True
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "static").write_text("-j RETURN\n", encoding="utf-8")
            (path / "with-host").write_text("# @host=h\n-d h -j RETURN\n", encoding="utf-8")
            tgt = Target("nat", "C", path)
            st = SyncState()
            sync_target_cycle(
                tgt,
                "/sbin/iptables",
                no_create_chain=True,
                state=st,
                hosts_only=True,
                resolve_hosts=True,
            )
        called = [c[0][3].name for c in m_sync.call_args_list]
        self.assertEqual(called, ["with-host"])


if __name__ == "__main__":
    unittest.main()
