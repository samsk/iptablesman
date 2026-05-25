"""Tests: owned_rules comment parsing and chain helpers."""

from __future__ import annotations

import logging
import unittest
from unittest.mock import patch

from src.owned_rules import (
    chain_snapshot_owned,
    comment_owned_by_basename,
    count_live_owned_rules,
    extract_comment_from_line,
    iter_managed_comments,
    rule_has_comment,
    rule_tag_key,
    tokens_without_comment,
)


class TestExtractComment(unittest.TestCase):
    def test_found(self) -> None:
        line = "-A C -j RETURN -m comment --comment mytag"
        self.assertEqual(extract_comment_from_line(line), "mytag")

    def test_missing(self) -> None:
        self.assertIsNone(extract_comment_from_line("-A C -j RETURN"))

    def test_quoted_comment_only_first_shell_token(self) -> None:
        line = '-A C -j RETURN -m comment --comment "two words"'
        self.assertEqual(extract_comment_from_line(line), '"two')


class TestRuleHasComment(unittest.TestCase):
    def test_match(self) -> None:
        line = (
            "-A NATPROXY -p udp -j DNAT --to-destination 10.0.0.1:53 "
            "-m comment --comment dns-udp"
        )
        self.assertTrue(rule_has_comment(line, "dns-udp"))
        self.assertFalse(rule_has_comment(line, "other"))


class TestCommentOwnedByBasename(unittest.TestCase):
    def test_happy(self) -> None:
        self.assertTrue(comment_owned_by_basename("f", "f"))
        self.assertTrue(comment_owned_by_basename("f/a", "f"))
        self.assertTrue(comment_owned_by_basename("f/a/2", "f"))

    def test_not_owned(self) -> None:
        self.assertFalse(comment_owned_by_basename("fx", "f"))
        self.assertFalse(comment_owned_by_basename("g/a", "f"))
        self.assertFalse(comment_owned_by_basename("f", "ff"))
        self.assertFalse(comment_owned_by_basename("f/", "f"))


class TestRuleTagKey(unittest.TestCase):
    def test_legacy_and_suffix(self) -> None:
        self.assertEqual(rule_tag_key("f", "f"), "")
        self.assertEqual(rule_tag_key("f/u", "f"), "u")


class TestTokensWithoutComment(unittest.TestCase):
    def test_strips_comment(self) -> None:
        toks = ["-j", "RETURN", "-m", "comment", "--comment", "x", "-p", "tcp"]
        self.assertEqual(tokens_without_comment(toks), ["-j", "RETURN", "-p", "tcp"])


class TestChainSnapshotOwned(unittest.TestCase):
    def test_maps_tags(self) -> None:
        text = (
            "-A MYCHAIN -j RETURN -m comment --comment f/1\n"
            "-A MYCHAIN -p tcp -j ACCEPT -m comment --comment f/2\n"
            "-A MYCHAIN -j DROP -m comment --comment other\n"
        )
        with patch(
            "src.owned_rules.iptables_list_chain",
            return_value=text,
        ):
            m = chain_snapshot_owned("/sbin/iptables", "nat", "MYCHAIN", "f")
        self.assertEqual(set(m.keys()), {"f/1", "f/2"})
        self.assertEqual(m["f/1"][0], 1)
        self.assertIn("-j", m["f/1"][1])

    def test_duplicate_tag_warns_keeps_first(self) -> None:
        text = (
            "-A MYCHAIN -j RETURN -m comment --comment f/1\n"
            "-A MYCHAIN -p udp -j DROP -m comment --comment f/1\n"
        )
        with patch(
            "src.owned_rules.iptables_list_chain",
            return_value=text,
        ):
            with self.assertLogs("iptablesman", level=logging.WARNING) as cm:
                m = chain_snapshot_owned("/sbin/iptables", "nat", "MYCHAIN", "f")
        self.assertEqual(set(m.keys()), {"f/1"})
        self.assertEqual(m["f/1"][0], 1)
        self.assertIn("-j", m["f/1"][1])
        self.assertTrue(any("duplicate" in r.message for r in cm.records))


class TestCountLiveOwned(unittest.TestCase):
    def test_counts_owned_only(self) -> None:
        text = (
            "-A C -m comment --comment f\n"
            "-A C -m comment --comment f/a\n"
            "-A C -m comment --comment other\n"
        )
        with patch("src.owned_rules.iptables_list_chain", return_value=text):
            n = count_live_owned_rules("/x", "t", "C", "f")
        self.assertEqual(n, 2)


class TestIterManagedComments(unittest.TestCase):
    def test_yields_all_comments(self) -> None:
        text = "-A C -m comment --comment a\n-A C -m comment --comment b\n"
        with patch("src.owned_rules.iptables_list_chain", return_value=text):
            self.assertEqual(list(iter_managed_comments("/x", "t", "C")), ["a", "b"])


if __name__ == "__main__":
    unittest.main()
