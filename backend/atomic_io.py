"""Atomic text writes that survive Windows file sharing (WinError 32)."""
from __future__ import annotations

import errno
import os
import time
from pathlib import Path

_RETRY_WIN = {5, 32, 33}  # access denied, sharing violation, lock violation
_RETRY_ERRNO = {errno.EACCES, errno.EPERM, errno.EBUSY}


def _retryable(err: OSError) -> bool:
    win = getattr(err, "winerror", None)
    if win in _RETRY_WIN:
        return True
    return err.errno in _RETRY_ERRNO


def _replace(tmp: Path, dest: Path) -> None:
    delay = 0.03
    last: OSError | None = None
    for _ in range(16):
        try:
            os.replace(tmp, dest)
            return
        except OSError as e:
            last = e
            if not _retryable(e):
                raise
            time.sleep(delay)
            delay = min(delay * 1.5, 0.4)
    data = tmp.read_bytes()
    delay = 0.03
    for _ in range(10):
        try:
            dest.write_bytes(data)
            tmp.unlink(missing_ok=True)
            return
        except OSError as e:
            last = e
            if not _retryable(e):
                raise
            time.sleep(delay)
            delay = min(delay * 1.5, 0.4)
    if last:
        raise last


def write_text_replace(path: Path, text: str, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    try:
        tmp.write_text(text, encoding=encoding)
        _replace(tmp, path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
