"""Detached analysis worker: pid file, spawn flags, liveness. Survives API restart."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from .atomic_io import write_text_replace
from .config import JOBS_DIR, WEBAPP_ROOT

STILL_ACTIVE = 259
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def worker_dir(job_id: str) -> Path:
    return JOBS_DIR / job_id


def pid_path(job_id: str) -> Path:
    return worker_dir(job_id) / "worker.pid"


def payload_path(job_id: str) -> Path:
    return worker_dir(job_id) / "worker_payload.json"


def result_path(job_id: str) -> Path:
    return worker_dir(job_id) / "worker_result.json"


def log_path(job_id: str) -> Path:
    return worker_dir(job_id) / "worker.log"


def write_worker_pid(job_id: str, pid: int) -> None:
    path = pid_path(job_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{int(pid)}\n{job_id}\n", encoding="utf-8")


def read_worker_pid(job_id: str) -> int | None:
    path = pid_path(job_id)
    if not path.is_file():
        return None
    try:
        first = path.read_text(encoding="utf-8").splitlines()[0].strip()
        pid = int(first)
        return pid if pid > 0 else None
    except (OSError, ValueError, IndexError):
        return None


def pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        k32 = ctypes.windll.kernel32
        handle = k32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ok = k32.GetExitCodeProcess(handle, ctypes.byref(code))
        k32.CloseHandle(handle)
        return bool(ok) and code.value == STILL_ACTIVE
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def write_worker_result(job_id: str, result: dict[str, Any]) -> None:
    write_text_replace(result_path(job_id), json.dumps(result, ensure_ascii=False))


def read_worker_result(job_id: str) -> dict[str, Any] | None:
    path = result_path(job_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def write_worker_payload(job_id: str, payload: dict[str, Any]) -> Path:
    path = payload_path(job_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def read_worker_payload(job_id: str) -> dict[str, Any] | None:
    path = payload_path(job_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def spawn_worker(job_id: str, payload: dict[str, Any]) -> subprocess.Popen:
    """Start python -m backend.worker_cli in a new process group (not killed with the API)."""
    path = write_worker_payload(job_id, payload)
    try:
        result_path(job_id).unlink(missing_ok=True)
    except OSError:
        pass
    cmd = [sys.executable, "-m", "backend.worker_cli", str(path)]
    kwargs: dict[str, Any] = {
        "cwd": str(WEBAPP_ROOT),
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if sys.platform == "win32":
        kwargs["close_fds"] = False
        flags = CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB
        try:
            return subprocess.Popen(cmd, creationflags=flags, **kwargs)
        except OSError:
            return subprocess.Popen(cmd, creationflags=CREATE_NEW_PROCESS_GROUP, **kwargs)
    kwargs["start_new_session"] = True
    kwargs["close_fds"] = True
    return subprocess.Popen(cmd, **kwargs)
