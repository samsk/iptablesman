"""Config discovery, sync cycle, drop-in listing."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from src.apply import sync_file
from src.constants import DEFAULT_APPLY_FAILURE_RETRY_INTERVAL_SEC, DIR_GONE_ALERT_INTERVAL_SEC
from src.dropin_hosts import dropin_has_hosts
from src.rule_tokens import validate_basename, validate_table_or_chain
from src.host_resolve import HostResolveLogState
from src.host_cache import HostResolveCache
from src.iptables_exec import ensure_chain
from src.owned_rules import delete_all_owned_comments

log = logging.getLogger("iptablesman")


@dataclass
class Target:
    """One (table, chain) with filesystem path to drop-in dir."""

    table: str
    chain: str
    path: Path


def discover_targets(config_dir: Path) -> list[Target]:
    """Scan config_dir/<table>/<chain>/ for directory pairs."""
    out: list[Target] = []
    if not config_dir.is_dir():
        return out
    for tpath in sorted(config_dir.iterdir()):
        if not tpath.is_dir() or tpath.name.startswith("."):
            continue
        if not validate_table_or_chain(tpath.name):
            log.error("skip bad table name %r (allow [A-Za-z0-9_-] len<=30)", tpath.name)
            continue
        for cpath in sorted(tpath.iterdir()):
            if not cpath.is_dir() or cpath.name.startswith("."):
                continue
            if not validate_table_or_chain(cpath.name):
                log.error(
                    "skip bad chain name %r under %s",
                    cpath.name,
                    tpath.name,
                )
                continue
            out.append(Target(table=tpath.name, chain=cpath.name, path=cpath))
    return out


def explicit_target(config_dir: Path, table: str, chain: str) -> Optional[Target]:
    """Single target at config_dir/table/chain/."""
    if not validate_table_or_chain(table) or not validate_table_or_chain(chain):
        log.error("invalid --table or --chain name")
        return None
    p = config_dir / table / chain
    return Target(table=table, chain=chain, path=p)


def list_dropin_files(target_path: Path) -> list[str]:
    """Sorted basenames of regular files (non-hidden)."""
    if not target_path.is_dir():
        return []
    names: list[str] = []
    for p in target_path.iterdir():
        if p.name.startswith("."):
            continue
        if p.is_file():
            names.append(p.name)
    names.sort()
    return names


@dataclass
class SyncState:
    """Per-target bookkeeping across daemon cycles."""

    dir_ever_seen: bool = False
    prev_basenames: set[str] = field(default_factory=set)
    last_dir_gone_log: Optional[float] = None
    last_sync_exception_log: Optional[float] = None
    apply_fail_backoff_until: dict[str, float] = field(default_factory=dict)


def sync_target_cycle(
    target: Target,
    iptables_bin: str,
    *,
    no_create_chain: bool,
    state: SyncState,
    host_log_state: Optional[HostResolveLogState] = None,
    no_syslog: bool = False,
    test_mode: bool = False,
    apply_failure_retry_interval: float = DEFAULT_APPLY_FAILURE_RETRY_INTERVAL_SEC,
    resolve_hosts: bool = True,
    hosts_only: bool = False,
    host_cache: Optional[HostResolveCache] = None,
    files_filter: Optional[set[str]] = None,
    skip_removed_cleanup: bool = False,
    now: Callable[[], float] = time.time,
) -> None:
    """One sync pass for a target directory."""
    path = target.path
    if not path.is_dir():
        if state.dir_ever_seen:
            t = now()
            if state.last_dir_gone_log is None or (
                t - state.last_dir_gone_log >= DIR_GONE_ALERT_INTERVAL_SEC
            ):
                log.error(
                    "chain directory missing (no iptables changes): %s/%s path %s",
                    target.table,
                    target.chain,
                    path,
                )
                state.last_dir_gone_log = t
        return

    state.dir_ever_seen = True
    state.last_dir_gone_log = None
    tnow = now()

    current = set(list_dropin_files(path))
    if not skip_removed_cleanup and not hosts_only:
        removed = state.prev_basenames - current
        for bn in sorted(removed):
            if validate_basename(bn):
                ensure_chain(iptables_bin, target.table, target.chain, no_create=no_create_chain)
                delete_all_owned_comments(iptables_bin, target.table, target.chain, bn)

    basenames = sorted(current if files_filter is None else current & files_filter)
    for bn in basenames:
        fp = path / bn
        if not fp.is_file():
            continue
        if hosts_only and not dropin_has_hosts(fp):
            continue
        if not test_mode:
            retry_at = state.apply_fail_backoff_until.get(bn)
            if retry_at is not None and tnow < retry_at:
                continue
        ok = sync_file(
            iptables_bin,
            target.table,
            target.chain,
            fp,
            no_create_chain=no_create_chain,
            host_log_state=host_log_state,
            no_syslog=no_syslog,
            test_mode=test_mode,
            resolve_hosts=resolve_hosts,
            hosts_only=hosts_only,
            host_cache=host_cache,
            now=now,
        )
        if ok:
            state.apply_fail_backoff_until.pop(bn, None)
        elif not test_mode:
            state.apply_fail_backoff_until[bn] = tnow + apply_failure_retry_interval
        if test_mode and not ok:
            raise RuntimeError(f"iptables test failed for {target.table}/{target.chain}/{bn}")

    if not hosts_only and files_filter is None:
        state.prev_basenames = current.copy()


def sync_due_backoff_files(
    target: Target,
    iptables_bin: str,
    *,
    no_create_chain: bool,
    state: SyncState,
    host_log_state: Optional[HostResolveLogState],
    no_syslog: bool,
    apply_failure_retry_interval: float,
    host_cache: Optional[HostResolveCache],
    now: Callable[[], float] = time.time,
) -> None:
    """Retry drop-ins whose apply-failure backoff has expired."""
    tnow = now()
    due = {
        bn
        for bn, retry_at in state.apply_fail_backoff_until.items()
        if tnow >= retry_at
    }
    if not due:
        return
    sync_target_cycle(
        target,
        iptables_bin,
        no_create_chain=no_create_chain,
        state=state,
        host_log_state=host_log_state,
        no_syslog=no_syslog,
        apply_failure_retry_interval=apply_failure_retry_interval,
        resolve_hosts=True,
        hosts_only=False,
        host_cache=host_cache,
        files_filter=due,
        skip_removed_cleanup=True,
        now=now,
    )


def run_dns_pass(
    targets: list[Target],
    iptables_bin: str,
    *,
    no_create_chain: bool,
    states: dict[tuple[str, str], SyncState],
    host_log_state: HostResolveLogState,
    no_syslog: bool,
    apply_failure_retry_interval: float,
    host_cache: HostResolveCache,
    now: Callable[[], float] = time.time,
) -> int:
    """DNS-only sync for @host drop-ins; return error count."""
    errors = 0
    for t in targets:
        st = states.setdefault((t.table, t.chain), SyncState())
        try:
            sync_target_cycle(
                t,
                iptables_bin,
                no_create_chain=no_create_chain,
                state=st,
                host_log_state=host_log_state,
                no_syslog=no_syslog,
                apply_failure_retry_interval=apply_failure_retry_interval,
                resolve_hosts=True,
                hosts_only=True,
                host_cache=host_cache,
                skip_removed_cleanup=True,
                now=now,
            )
        except Exception:
            errors += 1
            log.exception("dns pass failed %s/%s", t.table, t.chain)
    return errors
