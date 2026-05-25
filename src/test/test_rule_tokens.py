"""Tests: rule_tokens normalize, validate, parse, strip."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from src.constants import DEFAULT_IPTABLES
from src.rule_tokens import (
    normalize_iptables_path,
    parse_rule_line,
    strip_user_comment_tokens,
    token_has_metachar,
    validate_basename,
    validate_rule_tokens,
    validate_table_or_chain,
)


class TestNormalizeIptablesPath(unittest.TestCase):
    def test_default_when_empty(self) -> None:
        self.assertEqual(normalize_iptables_path(""), DEFAULT_IPTABLES)

    def test_absolute_ok(self) -> None:
        self.assertEqual(normalize_iptables_path("/sbin/iptables"), "/sbin/iptables")

    def test_relative_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            normalize_iptables_path("iptables")
        self.assertIn("absolute", str(ctx.exception).lower())


class TestTokenMetachar(unittest.TestCase):
    def test_clean_token(self) -> None:
        self.assertFalse(token_has_metachar("tcp"))
        self.assertFalse(token_has_metachar("8080"))

    def test_rejects_shell_chars(self) -> None:
        for bad in (";", "|", "&", "$", "`", "\n"):
            with self.subTest(bad=bad):
                self.assertTrue(token_has_metachar(f"a{bad}b"))


class TestValidateRuleTokens(unittest.TestCase):
    def test_happy(self) -> None:
        self.assertTrue(validate_rule_tokens(["-p", "tcp", "--dport", "80"]))

    def test_failure_metachar(self) -> None:
        self.assertFalse(validate_rule_tokens(["-j", "LOG;rm"]))


class TestParseRuleLine(unittest.TestCase):
    def test_comment_and_empty(self) -> None:
        self.assertIsNone(parse_rule_line("# c"))
        self.assertIsNone(parse_rule_line(""))
        self.assertIsNone(parse_rule_line("   "))

    def test_happy_split(self) -> None:
        self.assertEqual(parse_rule_line("-p udp"), ["-p", "udp"])
        self.assertEqual(parse_rule_line('  -j "ACCEPT"  '), ["-j", "ACCEPT"])

    @patch("src.rule_tokens.shlex.split", side_effect=ValueError("bad"))
    def test_shlex_error_returns_none(self, _m: object) -> None:
        self.assertIsNone(parse_rule_line("not a comment"))


class TestStripUserComment(unittest.TestCase):
    def test_removes_one_comment_module(self) -> None:
        t = ["-p", "udp", "-m", "comment", "--comment", "x", "-j", "ACCEPT"]
        self.assertEqual(strip_user_comment_tokens(t), ["-p", "udp", "-j", "ACCEPT"])

    def test_no_comment_unchanged(self) -> None:
        t = ["-j", "RETURN"]
        self.assertEqual(strip_user_comment_tokens(t), t)


class TestValidateNames(unittest.TestCase):
    def test_table_chain(self) -> None:
        self.assertTrue(validate_table_or_chain("nat"))
        self.assertTrue(validate_table_or_chain("NATPROXY"))
        self.assertFalse(validate_table_or_chain("bad;nat"))
        self.assertFalse(validate_table_or_chain("x" * 31))

    def test_basename(self) -> None:
        self.assertTrue(validate_basename("dns-udp"))
        self.assertFalse(validate_basename("bad name"))


if __name__ == "__main__":
    unittest.main()
