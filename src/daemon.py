"""Daemon loop: inotify, split timers, sync passes."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Optional

from src.config_watch import ConfigWatchCooldown, ConfigWatcher
from src.constants import SYNC_FAILURE_LOG_INTERVAL_SEC
from src.host_cache import HostResolveCache
from src.host_resolve import HostResolveLogState
from src.metrics import MetricsState, PrometheusExporter
from src.targets import (
    SyncState,
    Target,
    discover_targets,
    run_dns_pass,
    sync_due_backoff_files,
    sync_target_cycle,
)

log = logging.getLogger("iptablesman")


@dataclass
class DaemonConfig:
    """Runtime options for daemon loop."""

    config_dir: Path
    table: Optional[str]
    chain: Optional[str]
    interval: float
    dns_interval: float
    metrics_interval: float
    apply_failure_retry_interval: float
    no_create_chain: bool
    no_syslog: bool
    debug: bool
    config_watch: bool
    config_watch_scope: str
    config_watch_min_interval: float
    full_sync_on_interval: bool


def _compute_wait_timeout(
    now: float,
    interval: float,
    dns_interval: float,
    metrics_interval: float,
    last_interval_at: float,
    last_dns_at: float,
    last_metrics_at: float,
    prom_enabled: bool,
) -> float:
    """Seconds until next timer fires."""
    candidates = [
        max(0.0, interval - (now - last_interval_at)),
        max(0.0, dns_interval - (now - last_dns_at)),
    ]
    if prom_enabled:
        candidates.append(max(0.0, metrics_interval - (now - last_metrics_at)))
    return max(1.0, min(candidates))


def run_daemon_loop(
    *,
    cfg: DaemonConfig,
    iptables_bin: str,
    resolve_targets: Callable[[Path, Optional[str], Optional[str]], list[Target]],
    host_log_state: HostResolveLogState,
    metrics_state: MetricsState,
    prom: Optional[PrometheusExporter],
    collect_counters: Callable[
        [str, list[Target]],
        tuple[dict, dict],
    ],
    count_rules: Callable[[Target], int],
    forced: dict[str, bool],
    now: Callable[[], float] = time.time,
) -> None:
    """Main daemon loop until process exit."""
    states: dict[tuple[str, str], SyncState] = {}
    host_cache = HostResolveCache()
    watcher: Optional[ConfigWatcher] = None
    cooldown: Optional[ConfigWatchCooldown] = None

    cfg_eff = cfg
    if cfg.config_watch:
        try:
            watch_root = cfg.config_dir
            if cfg.table is not None and cfg.chain is not None:
                watch_root = cfg.config_dir / cfg.table / cfg.chain
            watcher = ConfigWatcher(cfg.config_dir, watch_root=watch_root)
            cooldown = ConfigWatchCooldown(min_interval_sec=cfg.config_watch_min_interval)
        except OSError as e:
            log.warning("config watch disabled: %s", e)
            watcher = None
            cfg_eff = replace(cfg, full_sync_on_interval=True)

    last_interval_at = 0.0
    last_dns_at = 0.0
    last_metrics_at = 0.0
    prom_enabled = prom is not None

    def _targets() -> list[Target]:
        return resolve_targets(cfg.config_dir, cfg.table, cfg.chain)

    def _sync_targets(
        targets: list[Target],
        *,
        resolve_hosts: bool,
        hosts_only: bool,
        files_filter: Optional[set[str]] = None,
        full_cycle: bool = False,
    ) -> int:
        errors = 0
        for t in targets:
            key = (t.table, t.chain)
            st = states.setdefault(key, SyncState())
            try:
                sync_target_cycle(
                    t,
                    iptables_bin,
                    no_create_chain=cfg.no_create_chain,
                    state=st,
                    host_log_state=host_log_state,
                    no_syslog=cfg.no_syslog,
                    apply_failure_retry_interval=cfg.apply_failure_retry_interval,
                    resolve_hosts=resolve_hosts,
                    hosts_only=hosts_only,
                    host_cache=host_cache,
                    files_filter=files_filter,
                    skip_removed_cleanup=hosts_only or files_filter is not None,
                    now=now,
                )
            except Exception:
                errors += 1
                tnow = now()
                due = (
                    cfg.debug
                    or st.last_sync_exception_log is None
                    or (tnow - st.last_sync_exception_log) >= SYNC_FAILURE_LOG_INTERVAL_SEC
                )
                if due:
                    log.exception("sync failed %s/%s", t.table, t.chain)
                    st.last_sync_exception_log = tnow
                else:
                    log.error(
                        "sync failed %s/%s (traceback suppressed; full log every %ss)",
                        t.table,
                        t.chain,
                        int(SYNC_FAILURE_LOG_INTERVAL_SEC),
                    )
        return errors

    def _full_sync(push_metrics: bool) -> None:
        nonlocal last_interval_at, last_dns_at, last_metrics_at
        tnow = now()
        targets = _targets()
        cycle_start = tnow
        errors = _sync_targets(targets, resolve_hosts=True, hosts_only=False, full_cycle=True)
        last_dns_at = tnow
        last_interval_at = tnow
        if push_metrics and prom_enabled:
            _metrics_pass(targets, cycle_start, errors)
            last_metrics_at = tnow

    def _metrics_pass(targets: list[Target], cycle_start: float, errors: int) -> None:
        monitored_rules = sum(count_rules(t) for t in targets)
        cycle_end = now()
        metrics_state.update_cycle(
            monitored_chains=len(targets),
            monitored_rules=monitored_rules,
            cycle_duration_seconds=(cycle_end - cycle_start),
            errors_in_cycle=errors,
            now_ts=cycle_end,
        )
        chain_counters, rule_counters = collect_counters(iptables_bin, targets)
        if prom is not None:
            prom.push(
                metrics_state.snapshot(),
                chain_counters=chain_counters,
                rule_counters=rule_counters,
            )

    def _interval_wake() -> None:
        nonlocal last_interval_at
        tnow = now()
        targets = _targets()
        for t in targets:
            key = (t.table, t.chain)
            st = states.setdefault(key, SyncState())
            try:
                sync_due_backoff_files(
                    t,
                    iptables_bin,
                    no_create_chain=cfg.no_create_chain,
                    state=st,
                    host_log_state=host_log_state,
                    no_syslog=cfg.no_syslog,
                    apply_failure_retry_interval=cfg.apply_failure_retry_interval,
                    host_cache=host_cache,
                    now=now,
                )
            except Exception:
                log.exception("backoff retry failed %s/%s", t.table, t.chain)
        if cfg_eff.full_sync_on_interval:
            _sync_targets(targets, resolve_hosts=True, hosts_only=False)
            last_dns_at = tnow
        last_interval_at = tnow

    def _dns_wake() -> None:
        nonlocal last_dns_at
        tnow = now()
        targets = _targets()
        run_dns_pass(
            targets,
            iptables_bin,
            no_create_chain=cfg.no_create_chain,
            states=states,
            host_log_state=host_log_state,
            no_syslog=cfg.no_syslog,
            apply_failure_retry_interval=cfg.apply_failure_retry_interval,
            host_cache=host_cache,
            now=now,
        )
        last_dns_at = tnow

    def _watch_sync(dirty: set[tuple[str, str]], rediscover: bool) -> None:
        targets = _targets()
        if rediscover:
            _sync_targets(targets, resolve_hosts=True, hosts_only=False)
            return
        if cfg.config_watch_scope == "full":
            _sync_targets(targets, resolve_hosts=True, hosts_only=False)
            return
        by_key = {(t.table, t.chain): t for t in targets}
        for key in dirty:
            t = by_key.get(key)
            if t is not None:
                _sync_targets([t], resolve_hosts=True, hosts_only=False)

    # startup full sync
    _full_sync(push_metrics=True)

    try:
        while True:
            tnow = now()
            wait_sec = _compute_wait_timeout(
                tnow,
                cfg.interval,
                cfg.dns_interval,
                cfg.metrics_interval,
                last_interval_at,
                last_dns_at,
                last_metrics_at,
                prom_enabled,
            )

            watch_result = None
            if watcher is not None:
                watch_result = watcher.wait(wait_sec, now=now)
                timed_out = watch_result.timed_out
            else:
                time.sleep(wait_sec)
                timed_out = True

            tnow = now()
            if forced["now"] or (watch_result and watch_result.overflow):
                forced["now"] = False
                _full_sync(push_metrics=True)
                continue

            if watch_result and watch_result.has_events and cooldown is not None:
                dirty = set(watch_result.dirty_targets)
                rediscover = watch_result.needs_rediscover
                if cooldown.should_sync(tnow):
                    pending_d, pending_r = cooldown.take_pending()
                    dirty |= pending_d
                    rediscover = rediscover or pending_r
                    _watch_sync(dirty, rediscover)
                    cooldown.note_sync(tnow)
                else:
                    cooldown.merge_pending(watch_result.dirty_targets, watch_result.needs_rediscover)

            dns_due = (tnow - last_dns_at) >= cfg.dns_interval
            interval_due = (tnow - last_interval_at) >= cfg.interval
            metrics_due = prom_enabled and (tnow - last_metrics_at) >= cfg.metrics_interval

            cycle_start = tnow
            cycle_errors = 0
            if dns_due:
                _dns_wake()
            if interval_due:
                _interval_wake()
            if metrics_due:
                targets = _targets()
                _metrics_pass(targets, cycle_start, cycle_errors)
                last_metrics_at = now()

            if cooldown is not None and cooldown.should_sync(now()):
                pending_d, pending_r = cooldown.take_pending()
                if pending_d or pending_r:
                    _watch_sync(pending_d, pending_r)
                    cooldown.note_sync(now())
    finally:
        if watcher is not None:
            watcher.close()
