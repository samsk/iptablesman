"""inotify watch on config-dir with coalesce and sync cooldown."""

from __future__ import annotations

import ctypes
import errno
import os
import select
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from src.rule_tokens import validate_table_or_chain

# Linux inotify (usr/include/sys/inotify.h)
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_MODIFY = 0x00000002
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000

WATCH_MASK = (
    IN_CREATE
    | IN_DELETE
    | IN_MODIFY
    | IN_MOVED_TO
    | IN_MOVED_FROM
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)

_EVENT_HDR = struct.Struct("iIII")
_COALESCE_SEC = 0.5

_libc = ctypes.CDLL(None, use_errno=True)
_inotify_init = _libc.inotify_init
_inotify_add_watch = _libc.inotify_add_watch
_inotify_rm_watch = _libc.inotify_rm_watch


def map_event_path(
    config_dir: Path,
    event_path: Path,
) -> tuple[set[tuple[str, str]], bool]:
    """Map absolute path under config_dir to dirty targets or rediscover flag."""
    try:
        rel = event_path.resolve().relative_to(config_dir.resolve())
    except ValueError:
        return set(), False
    parts = rel.parts
    if len(parts) == 0:
        return set(), True
    if len(parts) == 1:
        return set(), True
    if len(parts) == 2:
        return set(), True
    table, chain = parts[0], parts[1]
    if not validate_table_or_chain(table) or not validate_table_or_chain(chain):
        return set(), False
    return {(table, chain)}, False


@dataclass
class ConfigWatchResult:
    """Result from ConfigWatcher.wait()."""

    timed_out: bool = False
    overflow: bool = False
    dirty_targets: set[tuple[str, str]] = field(default_factory=set)
    needs_rediscover: bool = False
    has_events: bool = False


@dataclass
class ConfigWatchCooldown:
    """Rate-limit inotify-triggered syncs; retain pending changes."""

    min_interval_sec: float
    last_watch_sync_at: Optional[float] = None
    pending_dirty: set[tuple[str, str]] = field(default_factory=set)
    pending_rediscover: bool = False

    def should_sync(self, now: float) -> bool:
        """True if min interval elapsed since last watch sync."""
        if self.last_watch_sync_at is None:
            return True
        return (now - self.last_watch_sync_at) >= self.min_interval_sec

    def note_sync(self, now: float) -> None:
        """Record watch sync time; clear pending."""
        self.last_watch_sync_at = now
        self.pending_dirty.clear()
        self.pending_rediscover = False

    def merge_pending(
        self,
        dirty: set[tuple[str, str]],
        rediscover: bool,
    ) -> None:
        """Accumulate events suppressed by cooldown."""
        self.pending_dirty |= dirty
        self.pending_rediscover = self.pending_rediscover or rediscover

    def take_pending(self) -> tuple[set[tuple[str, str]], bool]:
        """Return and clear pending state."""
        dirty = set(self.pending_dirty)
        rediscover = self.pending_rediscover
        self.pending_dirty.clear()
        self.pending_rediscover = False
        return dirty, rediscover


class ConfigWatcher:
    """Recursive inotify on config_dir."""

    def __init__(self, config_dir: Path, *, watch_root: Optional[Path] = None) -> None:
        self._config_dir = config_dir.resolve()
        self._root = (watch_root or config_dir).resolve()
        self._fd = _inotify_init()
        if self._fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), "inotify_init")
        self._wd_map: dict[int, Path] = {}
        self._add_tree(self._root)

    def close(self) -> None:
        """Close inotify fd."""
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1

    def _add_tree(self, path: Path) -> None:
        if not path.is_dir():
            return
        self._add_watch(path)
        for child in path.iterdir():
            if child.is_dir() and not child.name.startswith("."):
                self._add_tree(child)

    def _add_watch(self, path: Path) -> None:
        bpath = os.fsencode(str(path))
        wd = _inotify_add_watch(self._fd, bpath, WATCH_MASK)
        if wd < 0:
            err = ctypes.get_errno()
            if err != errno.ENOENT:
                raise OSError(err, os.strerror(err), str(path))
            return
        self._wd_map[wd] = path

    def _read_events(self) -> tuple[set[tuple[str, str]], bool, bool]:
        dirty: set[tuple[str, str]] = set()
        rediscover = False
        overflow = False
        buf = os.read(self._fd, 65536)
        offset = 0
        while offset + _EVENT_HDR.size <= len(buf):
            wd, mask, _cookie, name_len = _EVENT_HDR.unpack_from(buf, offset)
            offset += _EVENT_HDR.size
            name = ""
            if name_len > 0:
                raw_name = buf[offset : offset + name_len]
                offset += name_len
                name = raw_name.split(b"\0", 1)[0].decode(errors="replace")
            if mask & IN_Q_OVERFLOW:
                overflow = True
            if wd not in self._wd_map:
                continue
            base = self._wd_map[wd]
            if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                rediscover = True
                continue
            if name:
                ep = base / name
            else:
                ep = base
            d, r = map_event_path(self._config_dir, ep)
            dirty |= d
            rediscover = rediscover or r
            if (mask & IN_ISDIR) and (mask & (IN_CREATE | IN_MOVED_TO)):
                if ep.is_dir():
                    self._add_tree(ep)
        return dirty, rediscover, overflow

    def wait(
        self,
        timeout_sec: float,
        *,
        now: Callable[[], float] = time.time,
    ) -> ConfigWatchResult:
        """Block up to timeout_sec; coalesce events for _COALESCE_SEC."""
        poll = select.poll()
        poll.register(self._fd, select.POLLIN)
        ms = max(0, int(timeout_sec * 1000))
        events = poll.poll(ms)
        if not events:
            return ConfigWatchResult(timed_out=True)
        dirty, rediscover, overflow = self._read_events()
        deadline = now() + _COALESCE_SEC
        while now() < deadline:
            remaining_ms = max(0, int((deadline - now()) * 1000))
            more = poll.poll(remaining_ms)
            if not more:
                break
            d2, r2, o2 = self._read_events()
            dirty |= d2
            rediscover = rediscover or r2
            overflow = overflow or o2
        return ConfigWatchResult(
            timed_out=False,
            overflow=overflow,
            dirty_targets=dirty,
            needs_rediscover=rediscover,
            has_events=bool(dirty or rediscover or overflow),
        )
