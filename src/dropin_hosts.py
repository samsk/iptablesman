"""Detect @host in drop-in files."""

from __future__ import annotations

from pathlib import Path

from src.annotations import parse_annotation_line


def dropin_has_hosts(file_path: Path) -> bool:
    """True if file contains any @host / @hosts annotation."""
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    for line in raw:
        if line.strip().startswith("#"):
            ad = parse_annotation_line(line)
            if ad and ("host" in ad or "hosts" in ad):
                return True
    return False
