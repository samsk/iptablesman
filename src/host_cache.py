"""Cache last @host resolution per rule tag."""

from __future__ import annotations

from dataclasses import dataclass, field

from src.host_resolve import HostIpv4Detail


@dataclass
class HostResolveCache:
    """hostname to chosen IPv4 per (table, chain, tag)."""

    _by_tag: dict[tuple[str, str, str], dict[str, str]] = field(default_factory=dict)

    def update(
        self,
        table: str,
        chain: str,
        tag: str,
        ipv4_details: list[HostIpv4Detail],
    ) -> None:
        """Store mapping from successful resolve."""
        mapping = {
            d.hostname: d.chosen_ip
            for d in ipv4_details
            if d.ok and d.chosen_ip
        }
        if mapping:
            self._by_tag[(table, chain, tag)] = mapping

    def mapping_for(
        self,
        table: str,
        chain: str,
        tag: str,
        hosts: list[str],
    ) -> dict[str, str] | None:
        """Return cached mapping if all hosts present."""
        cached = self._by_tag.get((table, chain, tag))
        if not cached:
            return None
        out: dict[str, str] = {}
        for h in hosts:
            if h not in cached:
                return None
            out[h] = cached[h]
        return out
