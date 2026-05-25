"""Parse optional # @key=value stacks before rule lines; assign comment tags."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterator, Optional

from src.constants import BASENAME_RE

log = logging.getLogger("iptablesman")

# Same character class as drop-in basename (plan: @name uses NAME_RE)
NAME_RE = BASENAME_RE
_DIGIT_NAME_RE = re.compile(r"^\d+$")


@dataclass
class ParsedBlock:
    """One rule block from a drop-in file before tag assignment."""

    hosts: list[str]
    name_raw: Optional[str]
    name_valid: bool
    rule_tokens: list[str]
    line_no: int


def _parse_kv_segment(seg: str) -> Iterator[tuple[str, str]]:
    """Yield (key, value) from one segment like '@host=a' or '@name=x'."""
    seg = seg.strip()
    if not seg.startswith("@"):
        return
    rest = seg[1:]
    if "=" not in rest:
        return
    k, _, v = rest.partition("=")
    k, v = k.strip(), v.strip()
    if k and v:
        yield (k, v)


def parse_annotation_line(line: str) -> dict[str, list[str]]:
    """Parse one # line for @key=value tokens; empty if unparseable."""
    s = line.strip()
    if not s.startswith("#"):
        return {}
    # strip leading #s and spaces
    body = s.lstrip("#").strip()
    if not body:
        return {}
    out: dict[str, list[str]] = {}
    # split on whitespace but keep @key=value as units
    for part in body.split():
        if not part.startswith("@"):
            continue
        for k, v in _parse_kv_segment(part):
            out.setdefault(k, []).append(v)
    return out


def merge_annotation_dicts(into: dict[str, list[str]], chunk: dict[str, list[str]]) -> None:
    for k, vals in chunk.items():
        into.setdefault(k, []).extend(vals)


def build_parsed_block(
    pending: dict[str, list[str]],
    pending_line: int,
    rule_line_no: int,
    rule_tokens: list[str],
    file_path: str,
) -> ParsedBlock:
    """Turn stacked annotations + rule tokens into one ParsedBlock."""
    hosts = list(pending.get("host", []))
    if "hosts" in pending:
        hosts.extend(pending["hosts"])
    name_vals = pending.get("name", [])
    name_raw: Optional[str] = name_vals[-1] if name_vals else None

    ref_line = pending_line or rule_line_no
    for k in pending:
        if k in ("host", "hosts", "name"):
            continue
        log.warning("%s:%s unknown @%s, ignoring", file_path, ref_line, k)

    name_valid = bool(name_raw and NAME_RE.match(name_raw))
    if name_raw and not name_valid:
        log.warning(
            "%s:%s invalid @name=%r, using auto slot",
            file_path,
            ref_line,
            name_raw,
        )
    if name_raw and _DIGIT_NAME_RE.match(name_raw):
        log.warning(
            "%s:%s @name=%r is numeric-only, forbidden; using auto slot",
            file_path,
            ref_line,
            name_raw,
        )
        name_valid = False
        name_raw = None

    return ParsedBlock(
        hosts=hosts,
        name_raw=name_raw if name_valid else None,
        name_valid=name_valid,
        rule_tokens=rule_tokens,
        line_no=rule_line_no,
    )


def assign_comment_tags(basename: str, blocks: list[ParsedBlock]) -> list[str]:
    """Return full iptables --comment string per block (parallel to blocks)."""
    n = len(blocks)
    if n == 0:
        return []

    name_occurrence: dict[str, int] = {}
    unnamed_seq = 0
    tags: list[str] = []

    for b in blocks:
        if b.name_valid and b.name_raw:
            occ = name_occurrence.get(b.name_raw, 0) + 1
            name_occurrence[b.name_raw] = occ
            if occ == 1:
                tags.append(f"{basename}/{b.name_raw}")
            else:
                tags.append(f"{basename}/{b.name_raw}/{occ}")
        else:
            if n == 1:
                tags.append(basename)
            else:
                unnamed_seq += 1
                tags.append(f"{basename}/{unnamed_seq}")

    return tags
