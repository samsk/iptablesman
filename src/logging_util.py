"""Logging: syslog + stderr, ovs-vm-arbiter style."""

from __future__ import annotations

import logging
import logging.handlers
import sys
from typing import Optional

_LEVEL_MAP = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}

NO_DEDUP_ATTR = "no_dedup"


class DebugDedupFilter(logging.Filter):
    """Suppress consecutive duplicate DEBUG messages."""

    def __init__(self, max_keys: Optional[int] = None) -> None:
        super().__init__()
        self._last: Optional[str] = None

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno != logging.DEBUG:
            return True
        if getattr(record, NO_DEDUP_ATTR, False):
            return True
        key = record.getMessage()
        if key == self._last:
            return False
        self._last = key
        return True


def setup_logging(log_level: str, debug: bool = False, no_syslog: bool = False) -> logging.Logger:
    """Configure logger iptablesman: optional syslog, always stderr."""
    if debug:
        log_level = "debug"
    level = _LEVEL_MAP.get(log_level.lower(), logging.INFO)
    log = logging.getLogger("iptablesman")
    log.setLevel(level)
    log.propagate = False
    log.handlers.clear()
    log.addFilter(DebugDedupFilter())
    if not no_syslog:
        try:
            h = logging.handlers.SysLogHandler(
                address="/dev/log",
                facility=logging.handlers.SysLogHandler.LOG_LOCAL0,
            )
            h.setFormatter(logging.Formatter("%(message)s"))
            h.setLevel(level)
            log.addHandler(h)
        except OSError:
            pass
    eh = logging.StreamHandler(sys.stderr)
    eh.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    eh.setLevel(level)
    log.addHandler(eh)
    return log
