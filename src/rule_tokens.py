"""Parse and validate iptables rule token lists from drop-in lines."""

from __future__ import annotations

import shlex
from typing import Optional

from src.constants import (
    BASENAME_RE,
    DEFAULT_IPTABLES,
    METACHAR_CHARS,
    TABLE_CHAIN_RE,
)


def validate_table_or_chain(name: str) -> bool:
    """True if name is allowed for table/chain directory or CLI."""
    return bool(TABLE_CHAIN_RE.match(name))


def validate_basename(name: str) -> bool:
    """True if drop-in filename is a valid iptables comment basename."""
    return bool(BASENAME_RE.match(name))


def normalize_iptables_path(path: str) -> str:
    """Require absolute path; default /usr/sbin/iptables."""
    p = path or DEFAULT_IPTABLES
    if not p.startswith("/"):
        raise ValueError(f"iptables path must be absolute: {p!r}")
    return p


def token_has_metachar(tok: str) -> bool:
    return any(c in METACHAR_CHARS for c in tok)


def validate_rule_tokens(tokens: list[str]) -> bool:
    """False if any token contains shell metacharacters."""
    return not any(token_has_metachar(t) for t in tokens)


def strip_user_comment_tokens(tokens: list[str]) -> list[str]:
    """Remove -m comment --comment <value> from token list."""
    out: list[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        if (
            i + 3 < n
            and tokens[i] == "-m"
            and tokens[i + 1] == "comment"
            and tokens[i + 2] == "--comment"
        ):
            i += 4
            continue
        out.append(tokens[i])
        i += 1
    return out


def parse_rule_line(line: str) -> Optional[list[str]]:
    """Split one config line; return tokens or None on shlex error."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    try:
        return shlex.split(s, comments=False)
    except ValueError:
        return None
