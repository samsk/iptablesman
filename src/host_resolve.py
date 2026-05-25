"""@host getaddrinfo, multi-A alerts, syslog ALERT / hourly ERROR."""

from __future__ import annotations

import logging
import socket
import syslog
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("iptablesman")

HOST_CHECK_INTERVAL_SEC = 3600.0


def emit_host_syslog_alert(msg: str, *, no_syslog: bool) -> None:
    """LOG_ALERT (or critical) plus log.error; same first-strike path as @host notify."""
    if no_syslog:
        log.critical("%s", msg)
    else:
        try:
            syslog.openlog(
                "iptablesman",
                logoption=syslog.LOG_PID,
                facility=syslog.LOG_LOCAL0,
            )
            syslog.syslog(syslog.LOG_ALERT, msg)
        except OSError:
            log.critical("%s", msg)
    log.error("%s", msg)


def _ipv4_sort_key(ip: str) -> tuple[int, int, int, int]:
    """Sort key for dotted-quad IPv4 strings."""
    parts = ip.split(".")
    if len(parts) != 4:
        return (0, 0, 0, 0)
    try:
        a, b, c, d = (int(p) for p in parts)
        return (a, b, c, d)
    except ValueError:
        return (0, 0, 0, 0)


@dataclass
class HostIpv4Detail:
    """One hostname: resolution ok, distinct IPv4s sorted, chosen is first."""

    hostname: str
    ok: bool
    ipv4_sorted: list[str]
    dns_error: Optional[str] = None

    @property
    def chosen_ip(self) -> str:
        return self.ipv4_sorted[0] if self.ipv4_sorted else ""

    @property
    def multi_a(self) -> bool:
        return len(self.ipv4_sorted) > 1


def format_no_ipv4_resolved_msg(
    tag_display: str,
    file_path: str,
    *,
    ipv4_details: Optional[list[HostIpv4Detail]] = None,
    hosts_detail: Optional[list[tuple[str, bool]]] = None,
) -> str:
    """Build @host failure text for ALERT/ERROR (empty answer vs DNS error)."""
    if ipv4_details is not None:
        parts: list[str] = []
        for d in ipv4_details:
            if d.ok:
                continue
            if d.dns_error:
                parts.append(f"{d.hostname} (DNS error: {d.dns_error})")
            else:
                parts.append(f"{d.hostname} (no IPv4 in DNS answer)")
        failed_msg = "; ".join(parts)
    else:
        failed = [h for h, o in (hosts_detail or []) if not o]
        failed_msg = ", ".join(failed)
    return f"@host no IPv4 resolved for {tag_display} in {file_path}: {failed_msg}"


def hosts_resolve_ipv4(hosts: list[str]) -> tuple[bool, list[HostIpv4Detail]]:
    """Resolve each distinct hostname to sorted unique IPv4s; all must resolve."""
    seen: set[str] = set()
    ordered: list[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            ordered.append(h)
    ordered.sort()

    details: list[HostIpv4Detail] = []
    all_ok = True
    for h in ordered:
        try:
            raw: set[str] = set()
            for res in socket.getaddrinfo(h, None, socket.AF_INET, socket.SOCK_STREAM):
                sockaddr = res[4]
                if sockaddr and sockaddr[0]:
                    raw.add(sockaddr[0])
            ips = sorted(raw, key=_ipv4_sort_key)
            if not ips:
                details.append(HostIpv4Detail(hostname=h, ok=False, ipv4_sorted=[]))
                all_ok = False
            else:
                details.append(HostIpv4Detail(hostname=h, ok=True, ipv4_sorted=ips))
        except OSError as e:
            details.append(
                HostIpv4Detail(hostname=h, ok=False, ipv4_sorted=[], dns_error=str(e))
            )
            all_ok = False
    return all_ok, details


def hosts_resolve_details(hosts: list[str]) -> tuple[bool, list[tuple[str, bool]]]:
    """Return (all_ok, [(hostname, ok), ...]) using IPv4-only getaddrinfo."""
    ok, details = hosts_resolve_ipv4(hosts)
    return ok, [(d.hostname, d.ok) for d in details]


def substitute_host_tokens(tokens: list[str], host_to_ip: dict[str, str]) -> list[str]:
    """Replace tokens that match a hostname key with chosen IPv4."""
    return [host_to_ip.get(t, t) for t in tokens]


@dataclass
class _EpisodeState:
    failing: bool = False
    alert_sent: bool = False
    last_hourly_error: float = 0.0


@dataclass
class HostResolveLogState:
    """In-memory ALERT + hourly ERROR for @host failures and multi-A."""

    episodes: dict[tuple[str, str, str, str], _EpisodeState] = field(default_factory=dict)
    multi_a_episodes: dict[tuple[str, str, str, str], _EpisodeState] = field(
        default_factory=dict
    )

    def notify(
        self,
        *,
        table: str,
        chain: str,
        basename: str,
        rule_tag_suffix: str,
        host_ok: bool,
        hosts_detail: list[tuple[str, bool]],
        file_path: str,
        no_syslog: bool,
        now: float,
        ipv4_details: Optional[list[HostIpv4Detail]] = None,
    ) -> None:
        """Emit syslog ALERT + log.error on first failure, then ERROR at most hourly."""
        key = (table, chain, basename, rule_tag_suffix)
        st = self.episodes.setdefault(key, _EpisodeState())
        if host_ok:
            st.failing = False
            st.alert_sent = False
            st.last_hourly_error = 0.0
            return

        tag_display = basename if not rule_tag_suffix else f"{basename}/{rule_tag_suffix}"
        msg = format_no_ipv4_resolved_msg(
            tag_display,
            file_path,
            ipv4_details=ipv4_details,
            hosts_detail=hosts_detail,
        )

        if not st.failing:
            st.failing = True
            st.alert_sent = False
            st.last_hourly_error = 0.0

        if not st.alert_sent:
            st.alert_sent = True
            st.last_hourly_error = now
            emit_host_syslog_alert(msg, no_syslog=no_syslog)
            return

        if now - st.last_hourly_error >= HOST_CHECK_INTERVAL_SEC:
            st.last_hourly_error = now
            log.error("%s", msg)

    def notify_multi_a(
        self,
        *,
        table: str,
        chain: str,
        basename: str,
        rule_tag_suffix: str,
        multi_details: list[HostIpv4Detail],
        file_path: str,
        no_syslog: bool,
        now: float,
    ) -> None:
        """ALERT when any @host has multiple A records; clear episode when none."""
        key = (table, chain, basename, rule_tag_suffix)
        if not multi_details:
            self.multi_a_episodes.pop(key, None)
            return

        parts: list[str] = []
        for d in multi_details:
            joined = ",".join(d.ipv4_sorted)
            parts.append(
                f"{d.hostname} has [{joined}] using {d.chosen_ip} "
                "(sorted, first wins)"
            )
        tag_display = basename if not rule_tag_suffix else f"{basename}/{rule_tag_suffix}"
        msg = (
            f"@host multiple IPv4 for {tag_display} in {file_path}: "
            + "; ".join(parts)
            + ". Round-robin or changing DNS is ambiguous for firewall rules "
            "(iptables resolves names at rule load). Prefer one A record or "
            "use a literal IP in the drop-in."
        )

        st = self.multi_a_episodes.setdefault(key, _EpisodeState())
        if not st.failing:
            st.failing = True
            st.alert_sent = False
            st.last_hourly_error = 0.0

        if not st.alert_sent:
            st.alert_sent = True
            st.last_hourly_error = now
            emit_host_syslog_alert(msg, no_syslog=no_syslog)
            return

        if now - st.last_hourly_error >= HOST_CHECK_INTERVAL_SEC:
            st.last_hourly_error = now
            log.error("%s", msg)
