"""Prometheus metrics state and exporter."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

log = logging.getLogger("iptablesman")


@dataclass
class MetricsState:
    """In-memory metrics for daemon lifecycle.

    Attributes:
        sync_cycles_total: Completed daemon cycles.
        sync_errors_total: Per-target sync errors.
        monitored_chains: Number of discovered targets.
        monitored_rules: Number of parsed rules in config.
        cycle_duration_seconds: Last cycle runtime.
        last_cycle_unixtime: Last cycle end time.
    """

    sync_cycles_total: int = 0
    sync_errors_total: int = 0
    monitored_chains: int = 0
    monitored_rules: int = 0
    cycle_duration_seconds: float = 0.0
    last_cycle_unixtime: float = 0.0
    _lock: Lock = field(default_factory=Lock)

    def snapshot(self) -> dict[str, float]:
        """Return thread-safe metrics snapshot."""
        with self._lock:
            return {
                "sync_cycles_total": float(self.sync_cycles_total),
                "sync_errors_total": float(self.sync_errors_total),
                "monitored_chains": float(self.monitored_chains),
                "monitored_rules": float(self.monitored_rules),
                "cycle_duration_seconds": float(self.cycle_duration_seconds),
                "last_cycle_unixtime": float(self.last_cycle_unixtime),
            }

    def update_cycle(
        self,
        *,
        monitored_chains: int,
        monitored_rules: int,
        cycle_duration_seconds: float,
        errors_in_cycle: int,
        now_ts: float | None = None,
    ) -> None:
        """Update values after one daemon cycle."""
        with self._lock:
            self.sync_cycles_total += 1
            self.sync_errors_total += int(errors_in_cycle)
            self.monitored_chains = int(monitored_chains)
            self.monitored_rules = int(monitored_rules)
            self.cycle_duration_seconds = float(cycle_duration_seconds)
            self.last_cycle_unixtime = float(time.time() if now_ts is None else now_ts)


class PrometheusExporter:
    """Prometheus exporter using optional prometheus_client.

    Args:
        host: Bind host for HTTP endpoint.
        port: Bind port for HTTP endpoint.
    """

    def __init__(self, host: str, port: int, *, last_activity: bool = False) -> None:
        """Initialize registry and start HTTP endpoint."""
        try:
            from prometheus_client import Counter, Gauge, start_http_server  # type: ignore[import-not-found]
        except Exception as e:  # pragma: no cover - import path tested via caller
            raise ImportError(str(e)) from e

        self._cycles_total = Counter(
            "iptablesman_sync_cycles_total",
            "Total completed daemon cycles.",
        )
        self._errors_total = Counter(
            "iptablesman_sync_errors_total",
            "Total per-target sync errors.",
        )
        self._monitored_chains = Gauge(
            "iptablesman_monitored_chains",
            "Number of monitored chains.",
        )
        self._monitored_rules = Gauge(
            "iptablesman_monitored_rules",
            "Number of monitored rules.",
        )
        self._cycle_duration = Gauge(
            "iptablesman_cycle_duration_seconds",
            "Last cycle duration in seconds.",
        )
        self._last_cycle_unixtime = Gauge(
            "iptablesman_last_cycle_unixtime",
            "Unix timestamp of last cycle.",
        )
        self._chain_packets = Gauge(
            "iptablesman_chain_packets",
            "Packet counters on monitored chains.",
            ["table", "chain"],
        )
        self._chain_bytes = Gauge(
            "iptablesman_chain_bytes",
            "Byte counters on monitored chains.",
            ["table", "chain"],
        )
        self._rule_packets = Gauge(
            "iptablesman_rule_packets",
            "Packet counters on monitored rules.",
            ["table", "chain", "comment"],
        )
        self._rule_bytes = Gauge(
            "iptablesman_rule_bytes",
            "Byte counters on monitored rules.",
            ["table", "chain", "comment"],
        )
        self._last_activity_enabled = bool(last_activity)
        self._last_activity_rule = Gauge(
            "iptablesman_rule_last_activity_unixtime",
            "Last minute timestamp when monitored rule counters changed.",
            ["table", "chain", "comment"],
        )
        self._last_activity_chain = Gauge(
            "iptablesman_chain_last_activity_unixtime",
            "Last minute timestamp when monitored chain counters changed.",
            ["table", "chain"],
        )
        self._seen_chain_labels: set[tuple[str, str]] = set()
        self._seen_rule_labels: set[tuple[str, str, str]] = set()
        self._prev_chain_counters: dict[tuple[str, str], tuple[int, int]] = {}
        self._prev_rule_counters: dict[tuple[str, str, str], tuple[int, int]] = {}
        self._last_chain_activity: dict[tuple[str, str], float] = {}
        self._last_rule_activity: dict[tuple[str, str, str], float] = {}
        self._last_cycles_total = 0.0
        self._last_errors_total = 0.0

        start_http_server(port, addr=host)
        log.info("prometheus metrics enabled on %s:%s/metrics", host, port)

    def push(
        self,
        snapshot: dict[str, Any],
        *,
        chain_counters: dict[tuple[str, str], tuple[int, int]],
        rule_counters: dict[tuple[str, str, str], tuple[int, int]],
    ) -> None:
        """Push state snapshot to Prometheus metrics."""
        cycles = float(snapshot["sync_cycles_total"])
        errors = float(snapshot["sync_errors_total"])
        if cycles > self._last_cycles_total:
            self._cycles_total.inc(cycles - self._last_cycles_total)
        if errors > self._last_errors_total:
            self._errors_total.inc(errors - self._last_errors_total)
        self._last_cycles_total = cycles
        self._last_errors_total = errors

        self._monitored_chains.set(float(snapshot["monitored_chains"]))
        self._monitored_rules.set(float(snapshot["monitored_rules"]))
        self._cycle_duration.set(float(snapshot["cycle_duration_seconds"]))
        self._last_cycle_unixtime.set(float(snapshot["last_cycle_unixtime"]))
        self._push_chain_rule_counters(chain_counters=chain_counters, rule_counters=rule_counters)

    def _push_chain_rule_counters(
        self,
        *,
        chain_counters: dict[tuple[str, str], tuple[int, int]],
        rule_counters: dict[tuple[str, str, str], tuple[int, int]],
    ) -> None:
        """Push chain/rule counters and optional last-activity timestamps."""
        for table, chain in sorted(self._seen_chain_labels - set(chain_counters.keys())):
            self._chain_packets.remove(table, chain)
            self._chain_bytes.remove(table, chain)
            if self._last_activity_enabled:
                self._last_activity_chain.remove(table, chain)
                self._last_chain_activity.pop((table, chain), None)
                self._prev_chain_counters.pop((table, chain), None)

        for table, chain, comment in sorted(self._seen_rule_labels - set(rule_counters.keys())):
            self._rule_packets.remove(table, chain, comment)
            self._rule_bytes.remove(table, chain, comment)
            if self._last_activity_enabled:
                self._last_activity_rule.remove(table, chain, comment)
                self._last_rule_activity.pop((table, chain, comment), None)
                self._prev_rule_counters.pop((table, chain, comment), None)

        self._seen_chain_labels = set(chain_counters.keys())
        self._seen_rule_labels = set(rule_counters.keys())

        now_minute = float(int(time.time() // 60) * 60)
        for (table, chain), (packets, bytes_) in chain_counters.items():
            self._chain_packets.labels(table, chain).set(float(packets))
            self._chain_bytes.labels(table, chain).set(float(bytes_))
            if self._last_activity_enabled:
                prev = self._prev_chain_counters.get((table, chain))
                if prev is None or prev != (packets, bytes_):
                    self._last_chain_activity[(table, chain)] = now_minute
                self._last_activity_chain.labels(table, chain).set(
                    self._last_chain_activity.get((table, chain), now_minute)
                )
                self._prev_chain_counters[(table, chain)] = (packets, bytes_)

        for (table, chain, comment), (packets, bytes_) in rule_counters.items():
            self._rule_packets.labels(table, chain, comment).set(float(packets))
            self._rule_bytes.labels(table, chain, comment).set(float(bytes_))
            if self._last_activity_enabled:
                prev = self._prev_rule_counters.get((table, chain, comment))
                if prev is None or prev != (packets, bytes_):
                    self._last_rule_activity[(table, chain, comment)] = now_minute
                self._last_activity_rule.labels(table, chain, comment).set(
                    self._last_rule_activity.get((table, chain, comment), now_minute)
                )
                self._prev_rule_counters[(table, chain, comment)] = (packets, bytes_)

