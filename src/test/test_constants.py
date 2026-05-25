"""Smoke: constants module loads."""

from __future__ import annotations

import unittest

from src import constants


class TestConstants(unittest.TestCase):
    def test_expected_names(self) -> None:
        self.assertTrue(constants.SCRIPT_NAME.endswith(".py"))
        self.assertGreater(constants.DEFAULT_INTERVAL, 0)
        self.assertIsNotNone(constants.BASENAME_RE.match("ok-name"))


if __name__ == "__main__":
    unittest.main()
