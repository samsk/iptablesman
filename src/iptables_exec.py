"""Run iptables subprocess; list chain rules (-S)."""

from __future__ import annotations

import logging
import subprocess

log = logging.getLogger("iptablesman")


def run_iptables(
    iptables: list[str],
    *,
    capture: bool = False,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run iptables argv; never use shell."""
    if log.isEnabledFor(logging.DEBUG):
        log.debug("run: %s", " ".join(iptables))
    return subprocess.run(
        iptables,
        shell=False,
        capture_output=capture,
        text=True,
        check=check,
    )


def iptables_list_chain(iptables_bin: str, table: str, chain: str) -> str:
    """Return iptables -S output for chain."""
    r = run_iptables(
        [iptables_bin, "-t", table, "-S", chain],
        capture=True,
        check=False,
    )
    if r.returncode != 0:
        return ""
    return r.stdout or ""


def ensure_chain(
    iptables_bin: str,
    table: str,
    chain: str,
    *,
    no_create: bool,
) -> None:
    if no_create:
        return
    run_iptables(
        [iptables_bin, "-t", table, "-N", chain],
        capture=True,
        check=False,
    )
