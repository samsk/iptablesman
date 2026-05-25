"""Tests: main CLI errors and early exits."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.main import main


class TestMainCli(unittest.TestCase):
    @patch("src.main.os.kill")
    def test_resync_without_config_dir(self, m_kill: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lp = Path(tmp) / "lck"
            lp.write_text("1234", encoding="utf-8")
            rc = main(["--resync", "--lock-file", str(lp)])
        self.assertEqual(rc, 0)
        m_kill.assert_called_once()

    def test_new_cli_options_parse(self) -> None:
        from src.main import build_parser

        p = build_parser()
        args = p.parse_args(
            [
                "--config-dir",
                "/tmp/x",
                "--prometheus-metrics",
                "--prometheus-host",
                "127.0.0.1",
                "--prometheus-port",
                "9109",
                "--prometheus-metrics-last-activity",
                "--lock-file",
                "/run/iptablesman.lock",
                "--resync",
                "--test",
            ]
        )
        self.assertTrue(args.prometheus_metrics)
        self.assertTrue(args.prometheus_metrics_last_activity)
        self.assertEqual(args.prometheus_host, "127.0.0.1")
        self.assertEqual(args.prometheus_port, 9109)
        self.assertEqual(args.lock_file, "/run/iptablesman.lock")
        self.assertTrue(args.resync)
        self.assertTrue(args.test)

    def test_missing_config_dir(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            main(["--list"])
        self.assertEqual(ctx.exception.code, 2)

    def test_table_without_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = main(
                ["--config-dir", str(tmp), "--table", "nat", "--no-syslog"],
            )
        self.assertEqual(rc, 2)

    def test_list_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "nat" / "C").mkdir(parents=True)
            rc = main(["--config-dir", str(root), "--list", "--no-syslog"])
        self.assertEqual(rc, 0)

    @patch("src.main.time.sleep", side_effect=[None, None, SystemExit(0)])
    @patch(
        "src.main.sync_target_cycle",
        side_effect=RuntimeError("boom"),
    )
    @patch("src.main.time.time", return_value=0.0)
    @patch("src.main.setup_logging")
    def test_daemon_exception_rate_limited(
        self,
        m_setup_log: MagicMock,
        _m_time: object,
        _m_sync: object,
        _m_sleep: object,
    ) -> None:
        mlog = MagicMock()
        m_setup_log.return_value = mlog
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "nat" / "C").mkdir(parents=True)
            lock_file = root / "daemon.lock"
            with self.assertRaises(SystemExit):
                main(
                    [
                        "--config-dir",
                        str(root),
                        "--no-syslog",
                        "--interval",
                        "1",
                        "--lock-file",
                        str(lock_file),
                    ]
                )
        self.assertEqual(mlog.exception.call_count, 1)
        self.assertEqual(mlog.error.call_count, 2)


if __name__ == "__main__":
    unittest.main()
