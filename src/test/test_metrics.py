"""Tests: metrics state bookkeeping."""

from __future__ import annotations

import unittest

from src.metrics import MetricsState


class TestMetrics(unittest.TestCase):
    def test_snapshot_contains_expected_values(self) -> None:
        st = MetricsState()
        st.update_cycle(
            monitored_chains=2,
            monitored_rules=7,
            cycle_duration_seconds=0.5,
            errors_in_cycle=1,
            now_ts=123.0,
        )
        snap = st.snapshot()
        self.assertEqual(snap["monitored_chains"], 2.0)
        self.assertEqual(snap["monitored_rules"], 7.0)
        self.assertEqual(snap["sync_cycles_total"], 1.0)
        self.assertEqual(snap["sync_errors_total"], 1.0)
        self.assertEqual(snap["last_cycle_unixtime"], 123.0)


if __name__ == "__main__":
    unittest.main()

