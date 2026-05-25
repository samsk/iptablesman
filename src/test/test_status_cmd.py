"""Tests: status_cmd collection and helpers."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.status_cmd import (
    StatusBlock,
    _blocked_reason,
    _status_blocked_reason_display,
    cmd_status,
    collect_desired_rules,
    collect_status_blocks,
    cmd_list,
)
from src.targets import Target


class TestBlockedReason(unittest.TestCase):
    def test_empty_when_ok(self) -> None:
        self.assertEqual(_blocked_reason([("h", True)]), "")

    def test_lists_failed(self) -> None:
        s = _blocked_reason([("a", True), ("b", False)])
        self.assertIn("unresolved", s)
        self.assertIn("b", s)


class TestStatusBlockedReasonDisplay(unittest.TestCase):
    def test_apply_yes_is_none(self) -> None:
        self.assertEqual(_status_blocked_reason_display(True, [("h", False)]), "(none)")

    def test_apply_no_shows_unresolved(self) -> None:
        s = _status_blocked_reason_display(False, [("a", False)])
        self.assertIn("unresolved", s)
        self.assertIn("a", s)
        self.assertNotIn("'", s)

    @patch("src.status_cmd.count_live_owned_rules", return_value=0)
    @patch("src.status_cmd.collect_status_blocks")
    def test_cmd_status_line_format(self, m_blocks: MagicMock, _c: MagicMock) -> None:
        m_blocks.return_value = {
            "f": [
                StatusBlock(
                    tag="f",
                    hosts=["bad"],
                    host_detail=[("bad", False)],
                    host_ipv4_detail=[],
                    host_ok=False,
                    line_no=1,
                    rule_line="-j RETURN",
                    rule_effective_line="-j RETURN",
                )
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            t = Target("nat", "C", Path(tmp))
            buf = io.StringIO()
            with redirect_stdout(buf):
                cmd_status("/sbin/iptables", [t])
        out = buf.getvalue()
        self.assertIn("blocked_reason=unresolved: bad", out)
        self.assertNotIn("blocked_reason='", out)


class TestCollectStatusBlocks(unittest.TestCase):
    def test_empty_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Target("nat", "C", Path(tmp))
            self.assertEqual(collect_status_blocks(t), {})

    def test_happy_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "f1").write_text("# @host=127.0.0.1\n-j RETURN\n", encoding="utf-8")
            t = Target("nat", "C", root)
            m = collect_status_blocks(t)
        self.assertIn("f1", m)
        self.assertEqual(len(m["f1"]), 1)
        row = m["f1"][0]
        self.assertIsInstance(row, StatusBlock)
        self.assertEqual(row.tag, "f1")
        self.assertTrue(row.host_ok)

    @patch("pathlib.Path.read_text", side_effect=OSError("boom"))
    def test_read_error_row(self, _m: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad").write_text("x", encoding="utf-8")
            t = Target("nat", "C", root)
            m = collect_status_blocks(t)
        self.assertIn("read error", m["bad"][0].rule_line)


class TestCollectDesiredRules(unittest.TestCase):
    def test_maps_rule_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "r").write_text("-j RETURN\n", encoding="utf-8")
            t = Target("nat", "C", root)
            d = collect_desired_rules(t)
        self.assertIn("r", d)
        self.assertTrue(any("RETURN" in ln for ln in d["r"]))


class TestCmdList(unittest.TestCase):
    def test_prints_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "nat" / "C").mkdir(parents=True)
            (root / "nat" / "C" / "a").write_text("x", encoding="utf-8")
            t = Target("nat", "C", root / "nat" / "C")
            buf = io.StringIO()
            with redirect_stdout(buf):
                cmd_list(root, [t])
            out = buf.getvalue()
            self.assertIn("config-dir:", out)
            self.assertIn("a", out)


if __name__ == "__main__":
    unittest.main()
