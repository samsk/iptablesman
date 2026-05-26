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

    def test_apply_failure_retry_interval_default(self) -> None:
        from src.constants import DEFAULT_APPLY_FAILURE_RETRY_INTERVAL_SEC
        from src.main import build_parser

        args = build_parser().parse_args(["--config-dir", "/tmp/x"])
        self.assertEqual(
            args.apply_failure_retry_interval,
            DEFAULT_APPLY_FAILURE_RETRY_INTERVAL_SEC,
        )

    def test_apply_failure_retry_interval_custom(self) -> None:
        from src.main import build_parser

        args = build_parser().parse_args(
            ["--config-dir", "/tmp/x", "--apply-failure-retry-interval", "120"]
        )
        self.assertEqual(args.apply_failure_retry_interval, 120.0)

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

    @patch("src.main.run_daemon_loop")
    def test_daemon_invokes_run_loop(self, m_run: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "nat" / "C").mkdir(parents=True)
            lock_file = root / "daemon.lock"
            rc = main(
                [
                    "--config-dir",
                    str(root),
                    "--no-syslog",
                    "--no-config-watch",
                    "--lock-file",
                    str(lock_file),
                ]
            )
        self.assertEqual(rc, 0)
        m_run.assert_called_once()

    def test_dns_and_metrics_interval_parse(self) -> None:
        from src.main import build_parser

        args = build_parser().parse_args(
            [
                "--config-dir",
                "/tmp/x",
                "--dns-interval",
                "15",
                "--metrics-interval",
                "30",
            ]
        )
        self.assertEqual(args.dns_interval, 15.0)
        self.assertEqual(args.metrics_interval, 30.0)


if __name__ == "__main__":
    unittest.main()
