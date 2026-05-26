"""Tests: config_watch path mapping, cooldown, wait contract."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.config_watch import (
    ConfigWatchCooldown,
    ConfigWatchResult,
    ConfigWatcher,
    map_event_path,
)


class TestMapEventPath(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Path(self.tmp.name) / "cfg"
        self.cfg.mkdir()
        (self.cfg / "nat" / "POSTROUTING").mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_file_under_chain(self) -> None:
        p = self.cfg / "nat" / "POSTROUTING" / "rule-a"
        dirty, rediscover = map_event_path(self.cfg, p)
        self.assertEqual(dirty, {("nat", "POSTROUTING")})
        self.assertFalse(rediscover)

    def test_chain_dir(self) -> None:
        p = self.cfg / "nat" / "POSTROUTING"
        dirty, rediscover = map_event_path(self.cfg, p)
        self.assertEqual(dirty, set())
        self.assertTrue(rediscover)

    def test_outside_config(self) -> None:
        dirty, rediscover = map_event_path(self.cfg, Path("/tmp/other"))
        self.assertEqual(dirty, set())
        self.assertFalse(rediscover)


class TestWatchMinInterval(unittest.TestCase):
    def test_at_most_two_syncs_in_five_seconds(self) -> None:
        cd = ConfigWatchCooldown(min_interval_sec=5.0)
        sync_times: list[float] = []
        for t in [0.0, 1.0, 2.0, 3.0, 5.0]:
            if cd.should_sync(t):
                sync_times.append(t)
                cd.note_sync(t)
            else:
                cd.merge_pending({("nat", "C")}, False)
        self.assertEqual(sync_times, [0.0, 5.0])
        pending_d, pending_r = cd.take_pending()
        self.assertEqual(pending_d, set())

    def test_pending_flushed_on_allowed_sync(self) -> None:
        cd = ConfigWatchCooldown(min_interval_sec=5.0)
        cd.note_sync(0.0)
        cd.merge_pending({("filter", "INPUT")}, False)
        self.assertFalse(cd.should_sync(2.0))
        self.assertTrue(cd.should_sync(5.0))
        d, r = cd.take_pending()
        self.assertEqual(d, {("filter", "INPUT")})


def _fake_watcher(tmp: str) -> ConfigWatcher:
    w = ConfigWatcher.__new__(ConfigWatcher)
    w._config_dir = Path(tmp).resolve()
    w._root = w._config_dir
    w._fd = -1
    w._wd_map = {1: w._config_dir}
    return w


class TestWaitContract(unittest.TestCase):
    @patch.object(ConfigWatcher, "_read_events")
    @patch("src.config_watch.select.poll")
    def test_timeout(self, m_poll: MagicMock, m_read: MagicMock) -> None:
        m_poll.return_value.poll.return_value = []
        with tempfile.TemporaryDirectory() as tmp:
            w = _fake_watcher(tmp)
            try:
                r = w.wait(1.0, now=lambda: 0.0)
            finally:
                w.close()
        self.assertTrue(r.timed_out)
        m_read.assert_not_called()

    @patch.object(ConfigWatcher, "_read_events")
    @patch("src.config_watch.select.poll")
    def test_events(self, m_poll: MagicMock, m_read: MagicMock) -> None:
        m_poll.return_value.poll.side_effect = [[(1, 1)], []]
        m_read.return_value = ({("nat", "X")}, False, False)
        with tempfile.TemporaryDirectory() as tmp:
            w = _fake_watcher(tmp)
            try:
                r = w.wait(10.0, now=lambda: 0.0)
            finally:
                w.close()
        self.assertFalse(r.timed_out)
        self.assertTrue(r.has_events)
        self.assertIn(("nat", "X"), r.dirty_targets)


@unittest.skipUnless(sys.platform == "linux", "inotify")
class TestConfigWatcherLinux(unittest.TestCase):
    def test_write_triggers_dirty_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp)
            chain = cfg / "nat" / "POSTROUTING"
            chain.mkdir(parents=True)
            try:
                w = ConfigWatcher(cfg)
            except OSError:
                self.skipTest("inotify unavailable")
            try:
                fp = chain / "r1"
                fp.write_text("-j RETURN\n", encoding="utf-8")
                r = w.wait(2.0)
            finally:
                w.close()
        self.assertTrue(r.has_events or r.dirty_targets or r.needs_rediscover)


if __name__ == "__main__":
    unittest.main()
