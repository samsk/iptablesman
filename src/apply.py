"""Diff apply: orphan -D, -R, -A with @host gating."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable, Optional

from src.rule_tokens import validate_basename
from src.dropin import parse_dropin_blocks
from src.host_resolve import (
    HostResolveLogState,
    emit_host_syslog_alert,
    format_no_ipv4_resolved_msg,
    hosts_resolve_ipv4,
    substitute_host_tokens,
)
from src.iptables_exec import ensure_chain, run_iptables
from src.owned_rules import (
    chain_snapshot_owned,
    comment_owned_by_basename,
    delete_all_owned_comments,
    rule_tag_key,
    tokens_without_comment,
)

log = logging.getLogger("iptablesman")


def sync_file(
    iptables_bin: str,
    table: str,
    chain: str,
    file_path: Path,
    *,
    no_create_chain: bool,
    host_log_state: Optional[HostResolveLogState] = None,
    no_syslog: bool = False,
    test_mode: bool = False,
    now: Callable[[], float] = time.time,
) -> bool:
    """Apply one drop-in with diff apply and @host gating."""
    basename = file_path.name
    if not validate_basename(basename):
        log.error("skip file bad basename %r", basename)
        return False
    try:
        raw_lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        log.error("read %s: %s", file_path, e)
        return False

    blocks, tags, fatal = parse_dropin_blocks(file_path, raw_lines)
    if fatal:
        return False

    if not test_mode:
        ensure_chain(iptables_bin, table, chain, no_create=no_create_chain)

    config_tags = set(tags)
    tnow = now()

    host_ok_list: list[bool] = []
    desired_tokens_list: list[list[str]] = []
    for b, tag in zip(blocks, tags):
        if b.hosts:
            ok, ipv4_details = hosts_resolve_ipv4(b.hosts)
            detail = [(d.hostname, d.ok) for d in ipv4_details]
            host_ok_list.append(ok)
            mapping = {d.hostname: d.chosen_ip for d in ipv4_details if d.ok}
            body = substitute_host_tokens(b.rule_tokens, mapping)
            desired_tokens_list.append(
                body + ["-m", "comment", "--comment", tag]
            )
            suffix = rule_tag_key(tag, basename)
            tag_display = basename if not suffix else f"{basename}/{suffix}"
            if host_log_state is not None:
                host_log_state.notify(
                    table=table,
                    chain=chain,
                    basename=basename,
                    rule_tag_suffix=suffix,
                    host_ok=ok,
                    hosts_detail=detail,
                    file_path=str(file_path),
                    no_syslog=no_syslog,
                    now=tnow,
                    ipv4_details=ipv4_details,
                )
                multi = [d for d in ipv4_details if d.ok and d.multi_a]
                if ok:
                    host_log_state.notify_multi_a(
                        table=table,
                        chain=chain,
                        basename=basename,
                        rule_tag_suffix=suffix,
                        multi_details=multi,
                        file_path=str(file_path),
                        no_syslog=no_syslog,
                        now=tnow,
                    )
                else:
                    host_log_state.notify_multi_a(
                        table=table,
                        chain=chain,
                        basename=basename,
                        rule_tag_suffix=suffix,
                        multi_details=[],
                        file_path=str(file_path),
                        no_syslog=no_syslog,
                        now=tnow,
                    )
            elif not ok:
                msg = format_no_ipv4_resolved_msg(
                    tag_display,
                    str(file_path),
                    ipv4_details=ipv4_details,
                    hosts_detail=detail,
                )
                emit_host_syslog_alert(msg, no_syslog=no_syslog)
        else:
            host_ok_list.append(True)
            desired_tokens_list.append(
                b.rule_tokens + ["-m", "comment", "--comment", tag]
            )

    if test_mode:
        return _validate_desired_rules_test_mode(
            iptables_bin,
            table,
            chain,
            file_path,
            host_ok_list,
            desired_tokens_list,
        )

    live = chain_snapshot_owned(iptables_bin, table, chain, basename)

    orphan_tags = [
        tag
        for tag in live
        if tag not in config_tags and comment_owned_by_basename(tag, basename)
    ]
    orphan_nums = sorted(
        (live[t][0] for t in orphan_tags),
        reverse=True,
    )
    for rulenum in orphan_nums:
        rr = run_iptables(
            [iptables_bin, "-t", table, "-D", chain, str(rulenum)],
            capture=True,
            check=False,
        )
        if rr.returncode != 0:
            log.warning(
                "orphan -D failed %s/%s #%s: %s",
                table,
                chain,
                rulenum,
                (rr.stderr or "").strip(),
            )

    live = chain_snapshot_owned(iptables_bin, table, chain, basename)

    gated_live = any(
        not ok and tag in live
        for ok, tag in zip(host_ok_list, tags)
    )

    for ok, tag, desired in zip(host_ok_list, tags, desired_tokens_list):
        if not ok:
            continue
        if tag in live:
            rulenum, live_toks = live[tag]
            if tokens_without_comment(live_toks) == tokens_without_comment(desired):
                continue
            rr = run_iptables(
                [iptables_bin, "-t", table, "-R", chain, str(rulenum)] + desired,
                capture=True,
                check=False,
            )
            if rr.returncode != 0:
                log.warning(
                    "iptables -R failed %s tag=%s: %s",
                    file_path,
                    tag,
                    (rr.stderr or "").strip(),
                )
                if not gated_live:
                    delete_all_owned_comments(iptables_bin, table, chain, basename)
                    return _append_all(
                        iptables_bin,
                        table,
                        chain,
                        file_path,
                        host_ok_list,
                        desired_tokens_list,
                    )
        else:
            rr = run_iptables(
                [iptables_bin, "-t", table, "-A", chain] + desired,
                capture=True,
                check=False,
            )
            if rr.returncode != 0:
                log.error(
                    "iptables -A failed %s: %s",
                    file_path,
                    (rr.stderr or "").strip(),
                )
                return False

    return True


def _append_all(
    iptables_bin: str,
    table: str,
    chain: str,
    file_path: Path,
    host_ok_list: list[bool],
    desired_tokens_list: list[list[str]],
) -> bool:
    for ok, desired in zip(host_ok_list, desired_tokens_list):
        if not ok:
            continue
        rr = run_iptables(
            [iptables_bin, "-t", table, "-A", chain] + desired,
            capture=True,
            check=False,
        )
        if rr.returncode != 0:
            log.error("iptables -A failed %s: %s", file_path, (rr.stderr or "").strip())
            return False
    return True


def _validate_desired_rules_test_mode(
    iptables_bin: str,
    table: str,
    chain: str,
    file_path: Path,
    host_ok_list: list[bool],
    desired_tokens_list: list[list[str]],
) -> bool:
    """Validate desired rules with iptables -C, without changing rules."""
    ok = True
    for host_ok, desired in zip(host_ok_list, desired_tokens_list):
        if not host_ok:
            log.error("test blocked %s/%s unresolved @host in %s", table, chain, file_path)
            ok = False
            continue
        if log.isEnabledFor(logging.DEBUG):
            log.debug("test rule %s/%s %s", table, chain, " ".join(desired))
        rr = run_iptables(
            [iptables_bin, "-t", table, "-C", chain] + desired,
            capture=True,
            check=False,
        )
        if rr.returncode not in (0, 1):
            log.error("iptables test -C failed %s: %s", file_path, (rr.stderr or "").strip())
            ok = False
    return ok
