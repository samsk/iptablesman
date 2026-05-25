"""CLI entry: iptablesman.py"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from src.constants import (
    DEFAULT_INTERVAL,
    DEFAULT_LOCK_FILE,
    SCRIPT_NAME,
    SYNC_FAILURE_LOG_INTERVAL_SEC,
    SYSLOG_PROCNAME,
)
from src.dropin import parse_dropin_blocks
from src.locking import acquire_single_instance_lock
from src.logging_util import setup_logging
from src.metrics import MetricsState, PrometheusExporter
from src.proctitle import apply_proctitle
from src.rule_tokens import normalize_iptables_path
from src.host_resolve import HostResolveLogState
from src.status_cmd import cmd_list, cmd_status
from src.public_api import (
    SyncState,
    Target,
    discover_targets,
    explicit_target,
    sync_target_cycle,
    list_dropin_files,
)
from src.version import __version__, get_version_string


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=SCRIPT_NAME, description="Sync iptables from drop-in files.")
    p.add_argument(
        "--version",
        action="store_true",
        help="Print zip build timestamp and exit",
    )
    p.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="Root directory; rules live in <config-dir>/<table>/<chain>/",
    )
    p.add_argument("-t", "--table", default=None, help="Table (requires --chain)")
    p.add_argument("-N", "--chain", default=None, help="Chain (requires --table)")
    p.add_argument(
        "-i",
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"Daemon resync interval seconds (default {DEFAULT_INTERVAL})",
    )
    p.add_argument("--list", action="store_true", help="List targets and files; exit")
    p.add_argument("--status", action="store_true", help="Show desired vs live; exit")
    p.add_argument(
        "--test",
        action="store_true",
        help="Validate desired rules via iptables -C only; no changes",
    )
    p.add_argument(
        "--iptables-path",
        default="/usr/sbin/iptables",
        help="Absolute path to iptables (default /usr/sbin/iptables)",
    )
    p.add_argument(
        "--no-create-chain",
        action="store_true",
        help="Do not run iptables -N for missing chains",
    )
    p.add_argument("--no-syslog", action="store_true", help="Log to stderr only")
    p.add_argument("--log-level", default="info", help="info, debug, warning, error")
    p.add_argument("--debug", action="store_true", help="Force DEBUG logging and verbose traces")
    p.add_argument(
        "--lock-file",
        default=DEFAULT_LOCK_FILE,
        help=f"Single-instance lock file (default {DEFAULT_LOCK_FILE})",
    )
    p.add_argument(
        "--resync",
        action="store_true",
        help="Signal running daemon (SIGHUP) for immediate resync, then exit",
    )
    p.add_argument("--prometheus-metrics", action=argparse.BooleanOptionalAction, default=False,
                   help="Enable Prometheus metrics endpoint (default: False)")
    p.add_argument("--prometheus-host", default="localhost",
                   help="Prometheus HTTP host bind (default: localhost)")
    p.add_argument("--prometheus-port", type=int, default=9109,
                   help="Prometheus HTTP port bind (default: 9109)")
    p.add_argument(
        "--prometheus-metrics-last-activity",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Track last activity timestamp from chain/rule counter changes (default: False)",
    )
    return p


def resolve_targets(
    config_dir: Path,
    table: Optional[str],
    chain: Optional[str],
) -> list:
    if table is not None and chain is not None:
        t = explicit_target(config_dir, table, chain)
        return [t] if t else []
    return discover_targets(config_dir)


def main(argv: Optional[list[str]] = None) -> int:
    raw = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(raw)
    if args.version:
        print(get_version_string())
        return 0
    if args.resync:
        try:
            pid = int(Path(args.lock_file).read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGHUP)
        except Exception as e:
            print(f"resync failed: {e}", file=sys.stderr)
            return 2
        print(f"resync requested for pid={pid}")
        return 0
    if args.config_dir is None:
        parser.error("the following arguments are required: --config-dir")
    log = setup_logging(
        args.log_level,
        debug=args.debug,
        no_syslog=args.no_syslog,
    )
    try:
        iptables_bin = normalize_iptables_path(args.iptables_path)
    except ValueError as e:
        log.error("%s", e)
        return 2

    apply_proctitle(raw, base=SYSLOG_PROCNAME.decode())

    if (args.table is None) ^ (args.chain is None):
        log.error("--table and --chain must be used together or both omitted")
        return 2

    targets = resolve_targets(args.config_dir, args.table, args.chain)

    if args.list:
        cmd_list(args.config_dir, targets)
        return 0
    if args.status:
        cmd_status(iptables_bin, targets)
        return 0
    if args.test:
        test_ok = True
        for t in targets:
            st = SyncState()
            try:
                sync_target_cycle(
                    t,
                    iptables_bin,
                    no_create_chain=args.no_create_chain,
                    state=st,
                    host_log_state=HostResolveLogState(),
                    no_syslog=args.no_syslog,
                    test_mode=True,
                )
            except Exception:
                log.exception("test failed %s/%s", t.table, t.chain)
                test_ok = False
        return 0 if test_ok else 2

    if args.debug:
        log.debug("version %s (%s)", __version__, get_version_string())

    log.info(
        "daemon start config-dir=%s interval=%s targets=%s",
        args.config_dir,
        args.interval,
        len(targets),
    )
    if not targets:
        log.warning("no sync targets (no config-dir/<table>/<chain>/ directories found)")
    states: dict[tuple[str, str], SyncState] = {}
    host_log_state = HostResolveLogState()
    metrics_state = MetricsState()
    prom: Optional[PrometheusExporter] = None
    if args.prometheus_metrics:
        try:
            prom = PrometheusExporter(
                args.prometheus_host,
                int(args.prometheus_port),
                last_activity=bool(args.prometheus_metrics_last_activity),
            )
        except ImportError:
            log.error("prometheus metrics enabled but python module missing: prometheus_client")
            log.error("install module and retry: apt install python3-prometheus-client")
            return 2

    forced = {"now": False}

    def _on_sighup(_sig: int, _frame: object) -> None:
        forced["now"] = True
        log.info("resync signal received")

    signal.signal(signal.SIGHUP, _on_sighup)

    with acquire_single_instance_lock(Path(args.lock_file)):
        while True:
            cycle_start = time.time()
            cycle_errors = 0
            targets = resolve_targets(args.config_dir, args.table, args.chain)
            monitored_rules = 0
            for t in targets:
                monitored_rules += _count_target_rules(t)
                key = (t.table, t.chain)
                st = states.setdefault(key, SyncState())
                try:
                    sync_target_cycle(
                        t,
                        iptables_bin,
                        no_create_chain=args.no_create_chain,
                        state=st,
                        host_log_state=host_log_state,
                        no_syslog=args.no_syslog,
                    )
                except Exception:
                    cycle_errors += 1
                    tnow = time.time()
                    due = (
                        args.debug
                        or st.last_sync_exception_log is None
                        or (tnow - st.last_sync_exception_log) >= SYNC_FAILURE_LOG_INTERVAL_SEC
                    )
                    if due:
                        log.exception("sync failed %s/%s", t.table, t.chain)
                        st.last_sync_exception_log = tnow
                    else:
                        log.error(
                            "sync failed %s/%s (traceback suppressed; full log every %ss, or use --debug)",
                            t.table,
                            t.chain,
                            int(SYNC_FAILURE_LOG_INTERVAL_SEC),
                        )
            cycle_end = time.time()
            metrics_state.update_cycle(
                monitored_chains=len(targets),
                monitored_rules=monitored_rules,
                cycle_duration_seconds=(cycle_end - cycle_start),
                errors_in_cycle=cycle_errors,
                now_ts=cycle_end,
            )
            chain_counters, rule_counters = _collect_monitored_counters(iptables_bin, targets)
            if prom is not None:
                prom.push(
                    metrics_state.snapshot(),
                    chain_counters=chain_counters,
                    rule_counters=rule_counters,
                )
            if forced["now"]:
                forced["now"] = False
                continue
            time.sleep(max(1.0, float(args.interval)))


def _count_target_rules(target: Target) -> int:
    """Count parsed rules in all drop-in files for one target.

    Args:
        target: Target instance with `path`.

    Returns:
        Parsed block count.
    """
    path = target.path
    if not path.is_dir():
        return 0
    total = 0
    for fp in sorted(path.iterdir()):
        if fp.name.startswith(".") or not fp.is_file():
            continue
        try:
            raw = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        blocks, _tags, fatal = parse_dropin_blocks(fp, raw)
        if fatal:
            continue
        total += len(blocks)
    return total


_SAVE_COUNTER_LINE_RE = re.compile(r"^\[(\d+):(\d+)\]\s+(.+)$")


def _collect_monitored_counters(
    iptables_bin: str,
    targets: list[Target],
) -> tuple[dict[tuple[str, str], tuple[int, int]], dict[tuple[str, str, str], tuple[int, int]]]:
    """Collect packet/byte counters from iptables-save for monitored chains/rules."""
    chain_counters: dict[tuple[str, str], tuple[int, int]] = {}
    rule_counters: dict[tuple[str, str, str], tuple[int, int]] = {}

    by_table: dict[str, list[Target]] = {}
    for t in targets:
        by_table.setdefault(t.table, []).append(t)

    for table, table_targets in by_table.items():
        iptables_save_bin = _derive_iptables_save_path(iptables_bin)
        rr = subprocess.run(
            [iptables_save_bin, "-c", "-t", table],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
        )
        if rr.returncode != 0:
            continue

        monitored_chains = {(t.table, t.chain) for t in table_targets}
        known_basenames: dict[tuple[str, str], set[str]] = {}
        for t in table_targets:
            known_basenames[(t.table, t.chain)] = set(list_dropin_files(t.path))

        for line in rr.stdout.splitlines():
            m = _SAVE_COUNTER_LINE_RE.match(line.strip())
            if not m:
                continue
            packets = int(m.group(1))
            bytes_ = int(m.group(2))
            rest = m.group(3)
            try:
                toks = shlex.split(rest)
            except ValueError:
                continue
            if len(toks) < 3 or toks[0] != "-A":
                continue
            chain = toks[1]
            key = (table, chain)
            if key not in monitored_chains:
                continue

            cur_packets, cur_bytes = chain_counters.get(key, (0, 0))
            chain_counters[key] = (cur_packets + packets, cur_bytes + bytes_)

            comment = _extract_comment(toks[2:])
            if not comment:
                continue
            if not _owned_by_any_basename(comment, known_basenames.get(key, set())):
                continue
            rkey = (table, chain, comment)
            rule_counters[rkey] = (packets, bytes_)

    return chain_counters, rule_counters


def _extract_comment(rule_tokens: list[str]) -> str:
    """Extract --comment value from tokenized iptables rule."""
    for i in range(len(rule_tokens) - 1):
        if rule_tokens[i] == "--comment":
            return rule_tokens[i + 1]
    return ""


def _owned_by_any_basename(comment: str, basenames: set[str]) -> bool:
    """Return True if comment belongs to any monitored drop-in basename."""
    for bn in basenames:
        if comment == bn or comment.startswith(bn + "/"):
            return True
    return False


def _derive_iptables_save_path(iptables_bin: str) -> str:
    """Derive iptables-save path from iptables binary path."""
    p = Path(iptables_bin)
    name = p.name
    if name.startswith("iptables"):
        return str(p.with_name(name.replace("iptables", "iptables-save", 1)))
    return "/usr/sbin/iptables-save"


if __name__ == "__main__":
    raise SystemExit(main())
