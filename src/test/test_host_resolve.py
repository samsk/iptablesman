"""Tests: host_resolve getaddrinfo and HostResolveLogState."""

from __future__ import annotations

import socket
import unittest
from typing import Any

from unittest.mock import MagicMock, patch

from src.host_resolve import (
    HostIpv4Detail,
    HostResolveLogState,
    format_no_ipv4_resolved_msg,
    hosts_resolve_details,
    hosts_resolve_ipv4,
    substitute_host_tokens,
)


def _ga_row(ip: str) -> tuple[Any, ...]:
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))


class TestHostsResolveDetails(unittest.TestCase):
    @patch("src.host_resolve.socket.getaddrinfo")
    def test_all_ok(self, m_ga: MagicMock) -> None:
        m_ga.return_value = [_ga_row("192.0.2.1")]
        ok, det = hosts_resolve_details(["a.example", "b.example"])
        self.assertTrue(ok)
        self.assertEqual(det, [("a.example", True), ("b.example", True)])

    @patch("src.host_resolve.socket.getaddrinfo")
    def test_one_fails(self, m_ga: MagicMock) -> None:
        def side_effect(host: str, *a: Any, **kw: Any) -> list:
            if host == "bad":
                raise OSError("nxdomain")
            return [_ga_row("192.0.2.1")]

        m_ga.side_effect = side_effect
        ok, det = hosts_resolve_details(["good", "bad"])
        self.assertFalse(ok)
        self.assertEqual(det, [("bad", False), ("good", True)])

    def test_empty_hosts_ok(self) -> None:
        ok, det = hosts_resolve_details([])
        self.assertTrue(ok)
        self.assertEqual(det, [])

    @patch("src.host_resolve.socket.getaddrinfo")
    def test_uses_ipv4_only(self, m_ga: MagicMock) -> None:
        m_ga.return_value = [_ga_row("192.0.2.1")]
        hosts_resolve_details(["h.example"])
        self.assertEqual(m_ga.call_args[0][2], socket.AF_INET)


class TestHostsResolveIpv4(unittest.TestCase):
    @patch("src.host_resolve.socket.getaddrinfo")
    def test_sorts_ips_numeric(self, m_ga: MagicMock) -> None:
        m_ga.return_value = [_ga_row("10.0.0.9"), _ga_row("10.0.0.10")]
        ok, details = hosts_resolve_ipv4(["h"])
        self.assertTrue(ok)
        self.assertEqual(details[0].ipv4_sorted, ["10.0.0.9", "10.0.0.10"])
        self.assertEqual(details[0].chosen_ip, "10.0.0.9")
        self.assertTrue(details[0].multi_a)

    @patch("src.host_resolve.socket.getaddrinfo")
    def test_distinct_host_order_sorted(self, m_ga: MagicMock) -> None:
        def side_effect(host: str, *a: Any, **kw: Any) -> list:
            return [_ga_row("192.0.2.1")]

        m_ga.side_effect = side_effect
        ok, details = hosts_resolve_ipv4(["zebra", "alpha"])
        self.assertTrue(ok)
        self.assertEqual([d.hostname for d in details], ["alpha", "zebra"])

    @patch("src.host_resolve.socket.getaddrinfo")
    def test_empty_result_fails(self, m_ga: MagicMock) -> None:
        m_ga.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("", 0))]
        ok, details = hosts_resolve_ipv4(["h"])
        self.assertFalse(ok)
        self.assertFalse(details[0].ok)


class TestFormatNoIpv4Msg(unittest.TestCase):
    def test_dns_error_vs_empty_answer(self) -> None:
        m = format_no_ipv4_resolved_msg(
            "f/u",
            "/etc/x",
            ipv4_details=[
                HostIpv4Detail("a", False, [], dns_error="nxdomain"),
                HostIpv4Detail("b", False, []),
            ],
        )
        self.assertIn("@host no IPv4 resolved", m)
        self.assertIn("DNS error: nxdomain", m)
        self.assertIn("no IPv4 in DNS answer", m)


class TestSubstituteHostTokens(unittest.TestCase):
    def test_replaces_exact_tokens(self) -> None:
        toks = ["-d", "h.example", "-j", "RETURN"]
        out = substitute_host_tokens(toks, {"h.example": "1.1.1.1"})
        self.assertEqual(out, ["-d", "1.1.1.1", "-j", "RETURN"])


class TestHostResolveLogState(unittest.TestCase):
    def test_alert_once_then_hourly(self) -> None:
        st = HostResolveLogState()
        with patch("src.host_resolve.syslog.syslog") as m_syslog:
            st.notify(
                table="nat",
                chain="C",
                basename="f",
                rule_tag_suffix="u",
                host_ok=False,
                hosts_detail=[("h1", False)],
                file_path="/x",
                no_syslog=False,
                now=0.0,
            )
            self.assertEqual(m_syslog.call_count, 1)
            st.notify(
                table="nat",
                chain="C",
                basename="f",
                rule_tag_suffix="u",
                host_ok=False,
                hosts_detail=[("h1", False)],
                file_path="/x",
                no_syslog=False,
                now=10.0,
            )
            self.assertEqual(m_syslog.call_count, 1)
            st.notify(
                table="nat",
                chain="C",
                basename="f",
                rule_tag_suffix="u",
                host_ok=False,
                hosts_detail=[("h1", False)],
                file_path="/x",
                no_syslog=False,
                now=4000.0,
            )
            self.assertEqual(m_syslog.call_count, 1)

    def test_success_clears_episode(self) -> None:
        st = HostResolveLogState()
        with patch("src.host_resolve.syslog.syslog"):
            st.notify(
                table="nat",
                chain="C",
                basename="f",
                rule_tag_suffix="",
                host_ok=False,
                hosts_detail=[("h", False)],
                file_path="/x",
                no_syslog=True,
                now=0.0,
            )
        st.notify(
            table="nat",
            chain="C",
            basename="f",
            rule_tag_suffix="",
            host_ok=True,
            hosts_detail=[("h", True)],
            file_path="/x",
            no_syslog=True,
            now=1.0,
        )
        with patch("src.host_resolve.syslog.syslog") as m2:
            st.notify(
                table="nat",
                chain="C",
                basename="f",
                rule_tag_suffix="",
                host_ok=False,
                hosts_detail=[("h", False)],
                file_path="/x",
                no_syslog=False,
                now=2.0,
            )
            self.assertEqual(m2.call_count, 1)

    def test_multi_a_alert_once(self) -> None:
        st = HostResolveLogState()
        multi = [
            HostIpv4Detail("h", True, ["10.0.0.1", "10.0.0.2"]),
        ]
        with patch("src.host_resolve.syslog.syslog") as m_syslog:
            st.notify_multi_a(
                table="nat",
                chain="C",
                basename="f",
                rule_tag_suffix="",
                multi_details=multi,
                file_path="/x",
                no_syslog=False,
                now=0.0,
            )
            self.assertEqual(m_syslog.call_count, 1)
            st.notify_multi_a(
                table="nat",
                chain="C",
                basename="f",
                rule_tag_suffix="",
                multi_details=multi,
                file_path="/x",
                no_syslog=False,
                now=10.0,
            )
            self.assertEqual(m_syslog.call_count, 1)

    def test_multi_a_clear_when_single(self) -> None:
        st = HostResolveLogState()
        multi = [HostIpv4Detail("h", True, ["10.0.0.1", "10.0.0.2"])]
        with patch("src.host_resolve.syslog.syslog"):
            st.notify_multi_a(
                table="nat",
                chain="C",
                basename="f",
                rule_tag_suffix="",
                multi_details=multi,
                file_path="/x",
                no_syslog=True,
                now=0.0,
            )
        st.notify_multi_a(
            table="nat",
            chain="C",
            basename="f",
            rule_tag_suffix="",
            multi_details=[],
            file_path="/x",
            no_syslog=True,
            now=1.0,
        )
        with patch("src.host_resolve.syslog.syslog") as m2:
            st.notify_multi_a(
                table="nat",
                chain="C",
                basename="f",
                rule_tag_suffix="",
                multi_details=multi,
                file_path="/x",
                no_syslog=False,
                now=2.0,
            )
            self.assertEqual(m2.call_count, 1)


if __name__ == "__main__":
    unittest.main()
