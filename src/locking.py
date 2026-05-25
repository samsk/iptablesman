"""Single-instance lock helpers."""

from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


@contextmanager
def acquire_single_instance_lock(lock_file: Path) -> Iterator[None]:
    """Acquire non-blocking lock file.

    Args:
        lock_file: Path to lock file.

    Yields:
        None while lock is held.

    Raises:
        RuntimeError: Another process already holds the lock.
    """
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with lock_file.open("a+", encoding="utf-8") as fh:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            fh.seek(0)
            holder = fh.read().strip() or "unknown"
            raise RuntimeError(f"lock busy: {lock_file} held by pid={holder}") from exc
        fh.seek(0)
        fh.truncate(0)
        fh.write(str(os.getpid()))
        fh.flush()
        try:
            yield
        finally:
            fh.seek(0)
            fh.truncate(0)
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

