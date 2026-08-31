"""CLI entry for a detached analysis worker. Invoked as: python -m backend.worker_cli <payload.json>"""
from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _redirect_log(job_id: str) -> None:
    from backend.config import JOBS_DIR

    log = JOBS_DIR / job_id / "worker.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    handle = open(log, "ab", buffering=0)
    try:
        os.dup2(handle.fileno(), 1)
        os.dup2(handle.fileno(), 2)
    except OSError:
        pass


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python -m backend.worker_cli <payload.json>", file=sys.stderr)
        return 2
    payload_path = Path(sys.argv[1])
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    kind = str(payload.pop("_kind", "full") or "full")
    job_id = str(payload.get("job_id") or "")
    if not job_id:
        print("missing job_id", file=sys.stderr)
        return 2

    from backend.worker_proc import write_worker_pid, write_worker_result

    write_worker_pid(job_id, os.getpid())
    _redirect_log(job_id)
    print(f"[worker] pid={os.getpid()} job={job_id} kind={kind}", flush=True)

    from backend.services.analysis_worker import run_analysis_job, run_audit_job, run_hotspot_job, run_llm_phase_job

    fn = {
        "full": run_analysis_job,
        "hotspot": run_hotspot_job,
        "llm": run_llm_phase_job,
        "audit": run_audit_job,
    }.get(kind)
    try:
        if fn is None:
            result = {"ok": False, "status": "failed", "error": f"unknown worker {kind}"}
        else:
            result = fn(payload) or {"ok": False, "status": "failed", "error": "empty worker result"}
        write_worker_result(job_id, result)
        return 0 if result.get("ok") else 1
    except Exception as e:
        traceback.print_exc()
        result = {"ok": False, "status": "failed", "error": str(e)}
        try:
            write_worker_result(job_id, result)
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
