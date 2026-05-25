"""Set process title and prctl comm (ovs-vm-arbiter style)."""

from __future__ import annotations

import sys


def set_process_name(name: bytes) -> None:
    """prctl PR_SET_NAME; max 15 bytes + NUL on Linux."""
    if not name or len(name) > 15:
        return
    try:
        if sys.platform == "linux":
            libc = __import__("ctypes").CDLL(None)
            PR_SET_NAME = 15
            libc.prctl(PR_SET_NAME, name, 0, 0, 0)
    except Exception:
        pass


def build_process_title(argv: list[str], base: str, max_len: int = 255) -> str:
    if not argv or (len(argv) == 1 and not argv[0].strip()):
        return base
    rest = " ".join(argv)
    title = f"{base} {rest}" if rest else base
    return title[:max_len] if len(title) > max_len else title


def apply_proctitle(argv: list[str], base: str) -> None:
    """setproctitle + prctl short name."""
    try:
        import setproctitle

        setproctitle.setproctitle(build_process_title(argv, base=base))
    except Exception:
        pass
    # Linux comm max 15 chars
    short = base[:15].encode("ascii", errors="ignore")
    if len(short) <= 15:
        set_process_name(short)
