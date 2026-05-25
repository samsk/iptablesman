"""Tests: version semver and CLI --version."""

from __future__ import annotations

import unittest

from src.main import main
from src.version import __version__, get_version_string


class TestVersion(unittest.TestCase):
    def test_semver_defined(self) -> None:
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+")

    def test_version_string_source(self) -> None:
        self.assertEqual(get_version_string(), "source")

    def test_cli_version_exit(self) -> None:
        rc = main(["--version"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
