"""Tests: targets discovery, list_dropin_files, explicit_target."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.targets import (
    discover_targets,
    explicit_target,
    list_dropin_files,
)


class TestListDropinFiles(unittest.TestCase):
    def test_sorted_skips_hidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "z").write_text("x", encoding="utf-8")
            (root / "a").write_text("x", encoding="utf-8")
            (root / ".hidden").write_text("x", encoding="utf-8")
            (root / "subdir").mkdir()
            self.assertEqual(list_dropin_files(root), ["a", "z"])

    def test_missing_dir(self) -> None:
        self.assertEqual(list_dropin_files(Path("/nonexistent/iptablesman-list")), [])


class TestExplicitTarget(unittest.TestCase):
    def test_invalid_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(explicit_target(Path(tmp), "bad;", "nat"))

    def test_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "nat" / "X").mkdir(parents=True)
            e = explicit_target(root, "nat", "X")
            assert e is not None
            self.assertEqual(e.path, root / "nat" / "X")


class TestDiscoverTargets(unittest.TestCase):
    def test_discover_two_deep(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "nat" / "C1").mkdir(parents=True)
            (root / "nat" / "C1" / "f1").write_text("-j RETURN\n", encoding="utf-8")
            t = discover_targets(root)
            self.assertEqual(len(t), 1)
            self.assertEqual(t[0].table, "nat")
            self.assertEqual(t[0].chain, "C1")

    def test_missing_config_dir(self) -> None:
        self.assertEqual(discover_targets(Path("/nonexistent/iptablesman-disc")), [])


if __name__ == "__main__":
    unittest.main()
