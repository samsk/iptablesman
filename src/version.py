"""Semantic release tag; CLI --version uses zip mtime like ovs-vm-arbiter."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

__version__ = "1.0.0"


def get_version_string() -> str:
    """Return zip mtime as ISO UTC when run from zip, else 'source'."""
    try:
        f = globals().get("__file__") or getattr(sys.modules.get("__main__"), "__file__", "")
        if not f or ".zip" not in f:
            return "source"
        zip_path = f.split(".zip", 1)[0] + ".zip"
        if not os.path.isfile(zip_path):
            return "source"
        mtime = os.path.getmtime(zip_path)
        return datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return "unknown"
