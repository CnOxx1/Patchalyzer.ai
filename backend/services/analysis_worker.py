"""Analysis in a child process so the API process keeps its own GIL."""
from __future__ import annotations

import json
import traceback
from pathlib import Path
from typing import Any

from ..agents.graph import finalize_soc, invoke_analysis_graph, invoke_hotspot_rerun, invoke_llm_phase
from ..config import JOBS_DIR
from ..database import get_job, update_job
from ..services.kernel_audit import run_kernel_audit
from ..services.patch_resolver import PatchResolveError, resolve_pair_from_cve, resolve_patched_binary
from ..services.pipeline import (
    PipelineCancelled,
    clear_cancel,
    clear_progress_file,
    load_routing_mode,
    write_progress_file,
)


def _cb(job_id: str):
    def inner(msg: str, pct: int) -> None:
        try:
            write_progress_file(job_id, msg, pct)
        except OSError:
            return
    return inner


def _fail(job_id: str, error: str, status: str = "failed") -> dict[str, Any]:
    clear_progress_file(job_id)
    try:
        update_job(job_id, status=status, error=error)
    except Exception:
        traceback.print_exc()
    return {"ok": False, "status": status, "error": error}


def run_analysis_job(payload: dict[str, Any]) -> dict[str, Any]:
    job_id = str(payload.get("job_id") or "")
    if not job_id:
        return {"ok": False, "status": "failed", "error": "missing job_id"}
    run_llm = bool(payload.get("run_llm", True))
    cve = str(payload.get("cve") or "")
    resume = bool(payload.get("resume"))
    force_nodes = payload.get("force_nodes")
    job = get_job(job_id)
    if not job:
        return {"ok": False, "status": "failed", "error": "Job not found"}
    work = JOBS_DIR / job_id
    enabled = job.get("enabled_agents")
    clear_cancel(job_id)
    cb = _cb(job_id)
    try:
        update_job(job_id, status="running")
        write_progress_file(job_id, "开始分析…", 1)
        old_name = job.get("old_filename") or ""
        new_name = job.get("new_filename") or ""
        resolve_info = None
        ingest_path = work / "ingest.json"
        ingest: dict[str, Any] = {}
        if ingest_path.is_file():
            try:
                ingest = json.loads(ingest_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                ingest = {}
        if cve:
            ingest.setdefault("cve", cve)

        old_path = work / old_name if old_name else None
        need_pair = (not old_path or not old_path.is_file()) and not new_name
        if need_pair:
            cve_id = (ingest.get("cve") or cve or job.get("title") or "").strip()
            if not cve_id:
                raise PatchResolveError("未上传样本，且未提供 CVE 编号")
            old_name = "old_vulnerable.sys"
            new_name = "new_patched.sys"
            resolve_info = resolve_pair_from_cve(
                cve_id,
                work / old_name,
                work / new_name,
                filename=str(ingest.get("filename") or ""),
                progress_cb=cb,
            )
            update_job(
                job_id,
                old_filename=old_name,
                new_filename=new_name,
                new_label=resolve_info.get("new_version") or "修复版",
                old_label=resolve_info.get("old_version") or "漏洞版",
                title=(job.get("title") or resolve_info.get("cve") or cve_id),
            )
            job = get_job(job_id) or job
            (work / "resolve.json").write_text(
                json.dumps(resolve_info, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        elif not new_name:
            if not cve:
                raise PatchResolveError("未上传修复版，且未提供 CVE 编号")
            if not old_path or not old_path.is_file():
                raise PatchResolveError("找不到漏洞样本")
            new_name = "new_patched.sys"
            resolve_info = resolve_patched_binary(
                old_path,
                cve,
                work / new_name,
                cb,
            )
            update_job(
                job_id,
                new_filename=new_name,
                new_label=resolve_info.get("new_version") or "修复版",
                old_label=resolve_info.get("old_version") or job.get("old_label"),
            )
            job = get_job(job_id) or job
            (work / "resolve.json").write_text(
                json.dumps(resolve_info, ensure_ascii=False, indent=2), encoding="utf-8"
            )

        if not resolve_info:
            cached_resolve = work / "resolve.json"
            if cached_resolve.is_file():
                try:
                    loaded = json.loads(cached_resolve.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict) and loaded:
                        resolve_info = loaded
                except json.JSONDecodeError:
                    pass

        new_path = work / (job.get("new_filename") or new_name)
        old_path = work / (job.get("old_filename") or old_name)
        mid_name = job.get("mid_filename")
        artifacts = invoke_analysis_graph(
            old_path,
            new_path,
            work,
            job["title"],
            run_llm=run_llm,
            mid_sys=Path(work / mid_name) if mid_name else None,
            old_label=job.get("old_label") or "漏洞版",
            new_label=job.get("new_label") or "修复版",
            mid_label=job.get("mid_label") or "更早版本",
            progress_cb=cb,
            enabled_agents=enabled,
            resume=resume,
            force_nodes=force_nodes,
            routing_mode=load_routing_mode(work),
            patch_resolve=resolve_info,
        )
        if resolve_info:
            artifacts["patch_resolve"] = resolve_info
            artifacts = finalize_soc(artifacts, job["title"], work)
        result = {
            "artifacts": artifacts,
            "progress": {"message": "Complete", "percent": 100},
            "graph": "langgraph-multi-agent",
        }
        clear_progress_file(job_id)
        update_job(job_id, status="completed", result_json=json.dumps(result, ensure_ascii=False), error=None)
        return {"ok": True, "status": "completed"}
    except PipelineCancelled:
        return _fail(job_id, "任务已取消", status="cancelled")
    except PatchResolveError as e:
        return _fail(job_id, str(e))
    except Exception as e:
        traceback.print_exc()
        return _fail(job_id, str(e))


def run_hotspot_job(payload: dict[str, Any]) -> dict[str, Any]:
    job_id = str(payload.get("job_id") or "")
    names = [str(n).strip() for n in (payload.get("names") or []) if str(n).strip()]
    run_llm = bool(payload.get("run_llm", True))
    job = get_job(job_id)
    if not job:
        return {"ok": False, "status": "failed", "error": "Job not found"}
    artifacts = (job.get("result") or {}).get("artifacts") or {}
    clear_cancel(job_id)
    cb = _cb(job_id)
    try:
        update_job(job_id, status="running")
        artifacts = invoke_hotspot_rerun(
            artifacts,
            job["title"],
            names,
            run_llm=run_llm,
            progress_cb=cb,
            enabled_agents=job.get("enabled_agents"),
        )
        clear_progress_file(job_id)
        result = job.get("result") or {}
        result["artifacts"] = artifacts
        update_job(job_id, status="completed", result_json=json.dumps(result, ensure_ascii=False), error=None)
        return {"ok": True, "status": "completed"}
    except PipelineCancelled:
        return _fail(job_id, "任务已取消", status="cancelled")
    except Exception as e:
        traceback.print_exc()
        return _fail(job_id, str(e))


def run_llm_phase_job(payload: dict[str, Any]) -> dict[str, Any]:
    job_id = str(payload.get("job_id") or "")
    selected = payload.get("selected")
    job = get_job(job_id)
    if not job:
        return {"ok": False, "status": "failed", "error": "Job not found"}
    artifacts = (job.get("result") or {}).get("artifacts") or {}
    if not artifacts:
        return {"ok": False, "status": "completed", "error": "No analysis artifacts"}
    try:
        write_progress_file(job_id, "正在生成报告…", 80)
        artifacts = invoke_llm_phase(artifacts, job["title"], selected)
        work = JOBS_DIR / job_id
        if artifacts.get("llm_report"):
            (work / "report.md").write_text(artifacts["llm_report"], encoding="utf-8")
        result = job.get("result") or {}
        result["artifacts"] = artifacts
        clear_progress_file(job_id)
        update_job(job_id, result_json=json.dumps(result, ensure_ascii=False))
        return {
            "ok": True,
            "status": "completed",
            "report_preview": (artifacts.get("llm_report") or "")[:500],
        }
    except Exception as e:
        traceback.print_exc()
        clear_progress_file(job_id)
        return {"ok": False, "status": "completed", "error": str(e)}


def run_audit_job(payload: dict[str, Any]) -> dict[str, Any]:
    job_id = str(payload.get("job_id") or "")
    if not job_id:
        return {"ok": False, "status": "failed", "error": "missing job_id"}
    run_llm = bool(payload.get("run_llm", True))
    job = get_job(job_id)
    if not job:
        return {"ok": False, "status": "failed", "error": "Job not found"}
    work = JOBS_DIR / job_id
    sample = job.get("old_filename") or job.get("new_filename") or ""
    sys_path = work / sample if sample else None
    if sys_path is None or not sys_path.is_file():
        for cand in sorted(work.glob("sample_*")) + sorted(work.glob("old_*")) + sorted(work.glob("*.sys")):
            if cand.is_file():
                sys_path = cand
                break
    if sys_path is None or not sys_path.is_file():
        return _fail(job_id, "找不到审计样本")
    clear_cancel(job_id)
    cb = _cb(job_id)
    try:
        update_job(job_id, status="running")
        write_progress_file(job_id, "开始内核审计…", 1)
        artifacts = run_kernel_audit(
            sys_path,
            work,
            job.get("title") or sys_path.name,
            job_id=job_id,
            run_llm=run_llm,
            resume=bool(payload.get("resume")),
            progress_cb=cb,
        )
        result = {
            "artifacts": artifacts,
            "progress": {"message": "Complete", "percent": 100},
            "graph": "kernel-audit",
        }
        clear_progress_file(job_id)
        update_job(job_id, status="completed", result_json=json.dumps(result, ensure_ascii=False), error=None)
        return {"ok": True, "status": "completed"}
    except PipelineCancelled:
        return _fail(job_id, "任务已取消", status="cancelled")
    except Exception as e:
        traceback.print_exc()
        return _fail(job_id, str(e))

