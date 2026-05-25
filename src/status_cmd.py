"""--status and --list CLI output."""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path

from src.rule_tokens import validate_basename
from src.dropin import parse_dropin_blocks
from src.host_resolve import (
    HostIpv4Detail,
    hosts_resolve_ipv4,
    substitute_host_tokens,
)
from src.owned_rules import (
    comment_owned_by_basename,
    count_live_owned_rules,
    iter_managed_comments,
)
from src.targets import Target, list_dropin_files


@dataclass
class StatusBlock:
    """One rule block for --status output."""

    tag: str
    hosts: list[str]
    host_detail: list[tuple[str, bool]]
    host_ipv4_detail: list[HostIpv4Detail]
    host_ok: bool
    line_no: int
    rule_line: str
    rule_effective_line: str


def collect_status_blocks(target: Target) -> dict[str, list[StatusBlock]]:
    """Map basename -> status rows per drop-in file."""
    out: dict[str, list[StatusBlock]] = {}
    if not target.path.is_dir():
        return out
    for bn in list_dropin_files(target.path):
        fp = target.path / bn
        if not validate_basename(bn):
            continue
        try:
            raw = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as e:
            out[bn] = [
                StatusBlock(
                    tag="",
                    hosts=[],
                    host_detail=[],
                    host_ipv4_detail=[],
                    host_ok=False,
                    line_no=0,
                    rule_line=f"<read error: {e}>",
                    rule_effective_line=f"<read error: {e}>",
                )
            ]
            continue
        blocks, tags, fatal = parse_dropin_blocks(fp, raw)
        if fatal:
            out[bn] = [
                StatusBlock(
                    tag="",
                    hosts=[],
                    host_detail=[],
                    host_ipv4_detail=[],
                    host_ok=False,
                    line_no=0,
                    rule_line="<file skipped: metachar>",
                    rule_effective_line="<file skipped: metachar>",
                )
            ]
            continue
        rows: list[StatusBlock] = []
        for b, tag in zip(blocks, tags):
            if b.hosts:
                ok, ipv4_details = hosts_resolve_ipv4(b.hosts)
                det = [(d.hostname, d.ok) for d in ipv4_details]
                mapping = {d.hostname: d.chosen_ip for d in ipv4_details if d.ok}
                eff_tokens = substitute_host_tokens(b.rule_tokens, mapping)
            else:
                ok, ipv4_details = True, []
                det = []
                eff_tokens = b.rule_tokens
            line = " ".join(shlex.quote(t) for t in b.rule_tokens)
            eff_line = " ".join(shlex.quote(t) for t in eff_tokens)
            rows.append(
                StatusBlock(
                    tag=tag,
                    hosts=list(b.hosts),
                    host_detail=det,
                    host_ipv4_detail=list(ipv4_details),
                    host_ok=ok,
                    line_no=b.line_no,
                    rule_line=line,
                    rule_effective_line=eff_line,
                )
            )
        out[bn] = rows
    return out


def collect_desired_rules(target: Target) -> dict[str, list[str]]:
    """Map basename -> rule lines (compat)."""
    desired: dict[str, list[str]] = {}
    for bn, rows in collect_status_blocks(target).items():
        desired[bn] = [r.rule_effective_line for r in rows if r.rule_effective_line]
    return desired


def cmd_list(config_dir: Path, targets: list[Target]) -> None:
    print(f"config-dir: {config_dir}")
    for t in targets:
        files = list_dropin_files(t.path) if t.path.is_dir() else []
        print(f"  {t.table}/{t.chain}  {t.path}")
        for f in files:
            print(f"    {f}")


def _blocked_reason(detail: list[tuple[str, bool]]) -> str:
    bad = [h for h, o in detail if not o]
    if not bad:
        return ""
    return "unresolved: " + ",".join(bad)


def _status_blocked_reason_display(apply_yes: bool, detail: list[tuple[str, bool]]) -> str:
    """Human-readable blocked_reason for --status (no repr quotes)."""
    if apply_yes:
        return "(none)"
    br = _blocked_reason(detail)
    return br if br else "(none)"


def cmd_status(iptables_bin: str, targets: list[Target]) -> None:
    for t in targets:
        print(f"=== {t.table}/{t.chain} {t.path} ===")
        if not t.path.is_dir():
            print("  (directory missing)")
            blocks_map: dict[str, list[StatusBlock]] = {}
        else:
            blocks_map = collect_status_blocks(t)
        for bn in sorted(blocks_map.keys()):
            rows = blocks_map[bn]
            live_n = count_live_owned_rules(iptables_bin, t.table, t.chain, bn)
            print(f"  [{bn}] live_owned_rules={live_n}")
            for r in rows:
                print(f"    comment={r.tag} line={r.line_no}")
                print(f"      rule (file): {r.rule_line}")
                print(f"      rule (effective): {r.rule_effective_line}")
                if r.hosts:
                    parts = []
                    for d in r.host_ipv4_detail:
                        st = "OK" if d.ok else "FAIL"
                        ips = ",".join(d.ipv4_sorted) if d.ipv4_sorted else "-"
                        ch = d.chosen_ip or "-"
                        flag = " MULTI-A" if d.multi_a else ""
                        parts.append(f"{d.hostname}={st} ips=[{ips}] chosen={ch}{flag}")
                    print(f"      @host: {' '.join(parts)}")
                else:
                    print("      @host: (none)")
                apply_yes = r.host_ok
                br_disp = _status_blocked_reason_display(apply_yes, r.host_detail)
                print(f"      apply: {'yes' if apply_yes else 'no'} blocked_reason={br_disp}")
        if t.path.is_dir():
            known = set(blocks_map.keys())
            extra = sorted(
                c
                for c in set(iter_managed_comments(iptables_bin, t.table, t.chain))
                if not any(comment_owned_by_basename(c, k) for k in known)
            )
            if extra:
                print(f"  (live comments not owned by any file in dir: {', '.join(extra)})")
