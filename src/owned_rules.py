"""Comment tags, owned-prefix matching, chain snapshot, bulk delete."""

from __future__ import annotations

import logging
import re
import shlex
from typing import Iterator, Optional

from src.rule_tokens import strip_user_comment_tokens
from src.iptables_exec import iptables_list_chain, run_iptables

log = logging.getLogger("iptablesman")

_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


def rule_has_comment(rule_line: str, comment: str) -> bool:
    """True if -S line contains our --comment value (exact)."""
    pat = re.compile(
        r"(?:^|\s)-m\s+comment\s+--comment\s+" + re.escape(comment) + r"(?:\s|$)"
    )
    return bool(pat.search(rule_line))


def extract_comment_from_line(line: str) -> Optional[str]:
    """Parse --comment value from one iptables -S line.

    Expects a single shell token (no spaces). Quoted values yield only
    the first whitespace-free slice after --comment (often wrong).
    """
    m = re.search(r"-m\s+comment\s+--comment\s+(\S+)(?:\s|$)", line)
    return m.group(1) if m else None


def comment_owned_by_basename(comment: str, basename: str) -> bool:
    """True if comment belongs to drop-in basename (legacy or basename/…)."""
    if comment == basename:
        return True
    if not comment.startswith(basename + "/"):
        return False
    suffix = comment[len(basename) + 1 :]
    if not suffix:
        return False
    for part in suffix.split("/"):
        if not part or not _SEGMENT_RE.match(part):
            return False
    return True


def rule_tag_key(full_comment: str, basename: str) -> str:
    """Suffix after basename/ for logging; '' for legacy basename-only."""
    if full_comment == basename:
        return ""
    return full_comment[len(basename) + 1 :]


def tokens_without_comment(tokens: list[str]) -> list[str]:
    """Rule body tokens for compare (strip comment module)."""
    return strip_user_comment_tokens(tokens)


def chain_snapshot_owned(
    iptables_bin: str,
    table: str,
    chain: str,
    basename: str,
) -> dict[str, tuple[int, list[str]]]:
    """Map full comment tag -> (1-based rulenum, argv after chain name).

    Duplicate owned tags: first match wins; later duplicates log WARNING and are ignored.
    """
    text = iptables_list_chain(iptables_bin, table, chain)
    by_tag: dict[str, tuple[int, list[str]]] = {}
    duplicates: set[str] = set()
    n = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("-A "):
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if len(parts) < 3 or parts[0] != "-A" or parts[1] != chain:
            continue
        n += 1
        tag = extract_comment_from_line(line)
        if not tag or not comment_owned_by_basename(tag, basename):
            continue
        if tag in by_tag:
            duplicates.add(tag)
            continue
        by_tag[tag] = (n, parts[2:])
    if duplicates:
        log.warning(
            "duplicate owned comments for %s in %s/%s: %s",
            basename,
            table,
            chain,
            ", ".join(sorted(duplicates)),
        )
    return by_tag


def delete_all_owned_comments(
    iptables_bin: str,
    table: str,
    chain: str,
    basename: str,
) -> None:
    """Remove every rule whose comment is owned by basename (prefix tree)."""
    for _ in range(512):
        text = iptables_list_chain(iptables_bin, table, chain)
        target_line: Optional[str] = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line.startswith("-A "):
                continue
            c = extract_comment_from_line(line)
            if c and comment_owned_by_basename(c, basename):
                target_line = line
                break
        if target_line is None:
            break
        try:
            parts = shlex.split(target_line)
        except ValueError:
            break
        if len(parts) < 3 or parts[0] != "-A" or parts[1] != chain:
            break
        rr = run_iptables(
            [iptables_bin, "-t", table, "-D", chain, *parts[2:]],
            capture=True,
            check=False,
        )
        if rr.returncode != 0:
            log.warning(
                "delete owned comment for %s failed: %s",
                basename,
                (rr.stderr or "").strip(),
            )
            break


def count_live_owned_rules(
    iptables_bin: str,
    table: str,
    chain: str,
    basename: str,
) -> int:
    n = 0
    for raw in iptables_list_chain(iptables_bin, table, chain).splitlines():
        if not raw.strip().startswith("-A "):
            continue
        c = extract_comment_from_line(raw)
        if c and comment_owned_by_basename(c, basename):
            n += 1
    return n


def iter_managed_comments(iptables_bin: str, table: str, chain: str) -> Iterator[str]:
    """Yield comment values from -m comment in chain (best-effort)."""
    for raw in iptables_list_chain(iptables_bin, table, chain).splitlines():
        line = raw.strip()
        if not line.startswith("-A "):
            continue
        for m in re.finditer(r"-m\s+comment\s+--comment\s+(\S+)", line):
            yield m.group(1)
