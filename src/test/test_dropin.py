"""Tests: dropin.parse_dropin_blocks."""

from __future__ import annotations

import logging
import tempfile
import unittest
from pathlib import Path

from src.dropin import parse_dropin_blocks


class TestParseDropinBlocks(unittest.TestCase):
    def test_host_and_name(self) -> None:
        p = Path("/n/myf")
        raw = [
            "# @host=svc.example",
            "# @name=udp",
            "-p udp -j RETURN",
        ]
        blocks, tags, fatal = parse_dropin_blocks(p, raw)
        self.assertFalse(fatal)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].hosts, ["svc.example"])
        self.assertEqual(tags, ["myf/udp"])

    def test_metachar_fatal(self) -> None:
        p = Path("/n/bad")
        blocks, tags, fatal = parse_dropin_blocks(p, ["-j", "LOG;rm"])
        self.assertTrue(fatal)
        self.assertEqual(blocks, [])
        self.assertEqual(tags, [])

    def test_empty_file(self) -> None:
        p = Path("/n/empty")
        blocks, tags, fatal = parse_dropin_blocks(p, [])
        self.assertFalse(fatal)
        self.assertEqual(blocks, [])
        self.assertEqual(tags, [])

    def test_trailing_annotations_warning(self) -> None:
        p = Path("/n/t")
        with self.assertLogs("iptablesman", level=logging.WARNING):
            parse_dropin_blocks(p, ["# @host=x"])

    def test_unknown_annotation_line_warning(self) -> None:
        p = Path("/n/u")
        with self.assertLogs("iptablesman", level=logging.WARNING):
            parse_dropin_blocks(p, ["# not-at-syntax", "-j RETURN"])

    def test_multi_rule_unnamed_tags(self) -> None:
        p = Path("/n/f")
        raw = ["-j RETURN", "-p tcp -j ACCEPT"]
        _blocks, tags, fatal = parse_dropin_blocks(p, raw)
        self.assertFalse(fatal)
        self.assertEqual(tags, ["f/1", "f/2"])

    def test_real_path_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "myrule"
            fp.write_text("-j RETURN\n", encoding="utf-8")
            raw = fp.read_text(encoding="utf-8").splitlines()
            _b, tags, fatal = parse_dropin_blocks(fp, raw)
            self.assertFalse(fatal)
            self.assertEqual(tags, ["myrule"])


if __name__ == "__main__":
    unittest.main()
