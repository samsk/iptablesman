"""Tests: annotations parse, merge, tag assignment, build_parsed_block."""

from __future__ import annotations

import logging
import unittest

from src.annotations import (
    ParsedBlock,
    assign_comment_tags,
    build_parsed_block,
    merge_annotation_dicts,
    parse_annotation_line,
)


class TestParseAnnotationLine(unittest.TestCase):
    def test_empty_and_plain_hash(self) -> None:
        self.assertEqual(parse_annotation_line(""), {})
        self.assertEqual(parse_annotation_line("#"), {})
        self.assertEqual(parse_annotation_line("not a comment"), {})

    def test_host_and_name(self) -> None:
        d = parse_annotation_line("# @host=a @name=udp")
        self.assertEqual(d.get("host"), ["a"])
        self.assertEqual(d.get("name"), ["udp"])

    def test_repeated_host(self) -> None:
        d = parse_annotation_line("# @host=a @host=b")
        self.assertEqual(d.get("host"), ["a", "b"])

    def test_ignores_non_at_tokens(self) -> None:
        d = parse_annotation_line("# foo @host=x bar")
        self.assertEqual(d.get("host"), ["x"])


class TestMergeAnnotationDicts(unittest.TestCase):
    def test_extends_lists(self) -> None:
        a: dict[str, list[str]] = {"host": ["a"]}
        merge_annotation_dicts(a, {"host": ["b"], "name": ["n"]})
        self.assertEqual(a["host"], ["a", "b"])
        self.assertEqual(a["name"], ["n"])


class TestAssignCommentTags(unittest.TestCase):
    def test_empty_blocks(self) -> None:
        self.assertEqual(assign_comment_tags("f", []), [])

    def test_single_unnamed_legacy(self) -> None:
        b = ParsedBlock([], None, False, ["-j", "RETURN"], 1)
        self.assertEqual(assign_comment_tags("f", [b]), ["f"])

    def test_multi_unnamed(self) -> None:
        b1 = ParsedBlock([], None, False, ["-j", "RETURN"], 1)
        b2 = ParsedBlock([], None, False, ["-j", "RETURN"], 2)
        self.assertEqual(assign_comment_tags("f", [b1, b2]), ["f/1", "f/2"])

    def test_duplicate_name_disambiguation(self) -> None:
        b1 = ParsedBlock([], "x", True, ["-j", "RETURN"], 1)
        b2 = ParsedBlock([], "x", True, ["-j", "RETURN"], 2)
        self.assertEqual(assign_comment_tags("f", [b1, b2]), ["f/x", "f/x/2"])


class TestBuildParsedBlock(unittest.TestCase):
    def test_hosts_from_host_and_hosts_keys(self) -> None:
        pending = {"host": ["a"], "hosts": ["b"]}
        b = build_parsed_block(pending, 1, 2, ["-j", "RETURN"], "/x/f")
        self.assertEqual(sorted(b.hosts), ["a", "b"])

    def test_numeric_name_rejected(self) -> None:
        pending = {"name": ["1"]}
        with self.assertLogs("iptablesman", level=logging.WARNING):
            b = build_parsed_block(pending, 1, 2, ["-j", "RETURN"], "/x/f")
        self.assertFalse(b.name_valid)
        self.assertIsNone(b.name_raw)

    def test_unknown_key_logs_warning(self) -> None:
        pending = {"foo": ["bar"]}
        with self.assertLogs("iptablesman", level=logging.WARNING) as cm:
            build_parsed_block(pending, 1, 2, ["-j", "RETURN"], "/x/f")
        self.assertTrue(any("unknown @foo" in x for x in cm.output))


if __name__ == "__main__":
    unittest.main()
