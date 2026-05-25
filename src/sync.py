"""Backward-compatible alias; prefer src.public_api."""

from __future__ import annotations

from src.public_api import *  # noqa: F403
from src.public_api import __all__
