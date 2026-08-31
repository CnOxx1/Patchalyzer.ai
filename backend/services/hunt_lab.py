"""Isolated tool-calling hunt lab: patch-bypass tests + Windows variant hunting.

Not part of the LangGraph specialist pipeline. Reuses the shared analysis toolbox.
No exploit / PoC / payload generation.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from langchain_core.messages import HumanMessage, SystemMessage

from ..agents.llm import make_chat
from ..services.agent_tools import (
    HUNT_LAB_BUDGET,
    HUNT_LAB_NUDGE,
    SAFETY,
    AnalysisToolbox as HuntLabContext,
    _clip,
    bind_tools,
    run_tool_loop,
)
from ..services.llm_service import LLMError, llm_configured
from ..services.pipeline import PipelineCancelled, check_cancel
from ..services.surface import build_surface_map, observations_from_scores

BYPASS_SYSTEM = (
    "你是独立的 Windows 补丁完整性测试员，不属于主分析流水线。"
    "目标：验证这次补丁是否还能从门控关闭、未改调用点、CFG 未覆盖路径、失败返回、检查-使用窗口到达原缺陷。"
    "流程必须逐步走，每步用工具取证，不要在脑内确认："
    "1) 用 patched_pattern / function_meta / disasm 弄清补丁加了什么检查；"
    "2) 对假设 H1 Feature 关闭回旧路径、H2 只打了部分 CALL 点、H3 CFG 路径未覆盖、"
    "H4 失败返回跳过检查、H5 检查与 free/probe 之间仍有窗口，分别调用工具验证；"
    "每个假设标 confirmed / refuted / unknown，证据必须来自工具返回。"
    "禁止按函数名推断职责或调用关系。没有 disasm/compare_calls/call_neighbors 返回就 unknown，禁止 confirmed。"
    "需要数据时调用工具；完成后只输出 JSON："
    '{"done":true,"verdict":"closed|partial|bypassable|unknown","confidence":"high|medium|low",'
    '"summary":"...","hypotheses":[{"id":"H1","status":"confirmed|refuted|unknown","evidence":"..."}],'
    '"findings":[{"method":"...","target":"...","status":"confirmed|refuted|unknown",'
    '"likelihood":"high|medium|low","evidence":"...","hardening":"..."}]}。'
    + SAFETY
)

SIMILAR_SYSTEM = (
    "你是独立的 Windows 内核变体狩猎员（patch diffing / variant analysis），不属于主分析流水线。"
    "目标：在同一驱动里找与本次根因同类、但补丁未改的函数。"
    "必须按 Windows 挖洞流程逐步走，每步用工具："
    "1) 定位补丁：list_symbols / function_meta / patched_pattern，看热点与 calls_added；"
    "2) 还原缺陷类：对照 read_evidence(root_cause) 与热点 disasm，判断缺锁 / 缺 Probe / UAF / TOCTOU 等；"
    "3) 枚举变体：同前缀符号、call_neighbors、未改尺寸的兄弟、Dispatch/IOCTL 入口；"
    "4) 取样 disasm / compare_calls，对照是否仍缺同类检查；"
    "5) 有汇编证据写 suspect，仅名字像写 similar，对不上写 cleared；没有可靠嫌疑则 none。"
    "完成后只输出 JSON："
    '{"done":true,"verdict":"none|suspects|likely|unknown","confidence":"high|medium|low",'
    '"summary":"...","bug_class":"...","findings":[{"function":"...","pattern":"...",'
    '"severity":"high|medium|low","status":"suspect|similar|cleared","evidence":"..."}]}。'
    + SAFETY
)

WRITER_SYSTEM = (
    "你是独立深度狩猎的执笔人。根据表面图、处理函数打分、两条狩猎线的 JSON 与工具轨迹写中文报告。"
    "一级标题必须且仅用："
    "## 1. 结论"
    "## 2. 用户入口（IOCTL / FastIo）"
    "## 3. 补丁绕过面（方法测试）"
    "## 4. 同类残留（变体狩猎）"
    "## 5. 隔离 VM 观察清单"
    "不要套用主报告的 19 节模板。不要写 exploit / PoC / 逐步利用 / IOCTL 触发序列。"
    "没有证据的嫌疑写成待核对，不要硬编。"
)


def _brief_user(artifacts: dict[str, Any], title: str, track: str) -> str:
    labels = artifacts.get("labels") or {}
    hunt = artifacts.get("hunt_brief") or {}
    notes = artifacts.get("agent_notes") or {}
    return (
        f"任务: {title}\n"
        f"样本: {labels.get('old') or 'old'} → {labels.get('new') or 'new'}\n"
        f"热点: {json.dumps((artifacts.get('hotspot_names') or [])[:12], ensure_ascii=False)}\n"
        f"根因摘要:\n{(notes.get('root_cause') or '（无）')[:1800]}\n\n"
        f"HuntPrep 高优先级: {json.dumps(hunt.get('high_priority') or [], ensure_ascii=False)}\n"
        f"可用工具: pe_info, list_symbols, function_meta, disasm, cfg_blocks, call_neighbors, "
        f"patched_pattern, feature_info, read_evidence, compare_calls。\n"
        f"本轮任务: {'补丁绕过面方法测试' if track == 'bypass' else '同类变体狩猎'}。"
        "先调用工具，不要直接下结论。"
    )


def run_track(
    track: str,
    ctx: HuntLabContext,
    artifacts: dict[str, Any],
    title: str,
    *,
    job_id: str = "",
    progress_cb: Callable[[str, int], None] | None = None,
    pct_start: int = 10,
    pct_end: int = 48,
) -> dict[str, Any]:
    system = BYPASS_SYSTEM if track == "bypass" else SIMILAR_SYSTEM
    try:
        result = run_tool_loop(
            system=system,
            user=_brief_user(artifacts, title, track),
            tools=bind_tools(ctx),
            job_id=job_id,
            budget=HUNT_LAB_BUDGET,
            require_json=True,
            progress_cb=progress_cb,
            progress_label=f"深度狩猎 · {track}",
            pct_start=pct_start,
            pct_end=pct_end,
            nudge=HUNT_LAB_NUDGE,
        )
    except LLMError as e:
        return {
            "track": track,
            "verdict": "unknown",
            "summary": f"模型调用失败: {e}",
            "findings": [],
            "tool_calls": [],
            "tool_call_count": 0,
            "rounds": 0,
        }
    final = result.parsed or {"verdict": "unknown", "summary": result.text[:1500], "findings": []}
    if not isinstance(final, dict):
        final = {"verdict": "unknown", "summary": str(final)[:1500], "findings": []}
    if not final.get("verdict") and not final.get("findings"):
        final = {"verdict": "unknown", "summary": result.text[:1500] or "未在轮次内给出结论", "findings": []}
    final["track"] = track
    final["tool_calls"] = result.tool_log
    final["tool_call_count"] = result.calls
    final["rounds"] = result.rounds
    return final


def write_hunt_report(
    title: str,
    bypass: dict[str, Any] | None,
    similar: dict[str, Any] | None,
    *,
    job_id: str = "",
    surface: dict[str, Any] | None = None,
    scores: list | None = None,
    observations: list | None = None,
) -> str:
    check_cancel(job_id=job_id)
    llm = make_chat(max_tokens=5000, temperature=0.1)
    slim_surface = {k: (surface or {}).get(k) for k in ("status", "dispatch", "immediate", "fastio", "handler_count")}
    hot_scores = [r for r in (scores or []) if r.get("risk") in ("high", "medium")][:16]
    user = (
        f"任务: {title}\n\n"
        f"## 表面图\n{_clip(slim_surface, 5000)}\n\n"
        f"## 打分 high/medium\n{_clip(hot_scores, 3000)}\n\n"
        f"## 绕过面测试 JSON\n{_clip(bypass or {'skipped': True}, 7000)}\n\n"
        f"## 变体狩猎 JSON\n{_clip(similar or {'skipped': True}, 7000)}\n\n"
        f"## 观察清单\n{_clip(observations or [], 2500)}\n\n"
        "按五节模板写中文报告。引用工具或表面图里出现过的函数名。禁止 exploit。"
    )
    resp = llm.invoke([SystemMessage(content=WRITER_SYSTEM), HumanMessage(content=user)])
    content = getattr(resp, "content", "") or ""
    if isinstance(content, list):
        content = "".join(str(x) for x in content)
    return str(content).strip()


def run_hunt_lab(
    artifacts: dict[str, Any],
    title: str,
    *,
    old_sys: Path,
    new_sys: Path,
    work: Path,
    tracks: list[str] | None = None,
    job_id: str = "",
    new_pdb: Path | None = None,
    old_pdb: Path | None = None,
    progress_cb: Callable[[str, int], None] | None = None,
    on_update: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    want = [t for t in (tracks or ["bypass", "similar"]) if t in {"bypass", "similar"}]
    if not want:
        want = ["bypass", "similar"]
    out: dict[str, Any] = {
        "status": "running",
        "isolated": True,
        "tracks": want,
        "flow": ["surface", "score", "bypass", "similar", "observe"],
        "bypass": None,
        "similar": None,
        "surface": None,
        "scores": [],
        "observations": [],
        "report": "",
        "error": None,
        "llm": llm_configured(),
    }
    if progress_cb:
        progress_cb("深度狩猎启动：表面图 → 打分 → 绕过/变体", 4)
    try:
        check_cancel(job_id=job_id)
        if progress_cb:
            progress_cb("解析 IOCTL / FastIo 表面图", 8)
        pdb = new_pdb if new_pdb and Path(new_pdb).exists() else None
        surface = build_surface_map(new_sys, pdb)
        scores = surface.get("scores") or []
        obs = observations_from_scores(scores)
        out["surface"] = surface
        out["scores"] = scores
        out["observations"] = obs
        artifacts = {**artifacts, "surface_map": surface, "handler_scores": scores}
        work.mkdir(parents=True, exist_ok=True)
        (work / "surface_map.json").write_text(json.dumps(surface, ensure_ascii=False, indent=2), encoding="utf-8")
        (work / "handler_scores.json").write_text(json.dumps(scores, ensure_ascii=False, indent=2), encoding="utf-8")
        if on_update:
            on_update(dict(out))

        if not llm_configured():
            out["status"] = "completed"
            out["llm"] = False
            out["error"] = "LLM API key 未配置；已保留表面图与打分，未跑绕过/变体"
            out["finished_at"] = _utc_now()
            if progress_cb:
                progress_cb("仅完成表面图与打分", 100)
            return out

        ctx = HuntLabContext(
            artifacts,
            old_sys=old_sys,
            new_sys=new_sys,
            work=work,
            disasm_budget=HUNT_LAB_BUDGET.disasm_budget,
            cfg_budget=HUNT_LAB_BUDGET.cfg_budget,
        )
        if "bypass" in want:
            out["bypass"] = run_track(
                "bypass",
                ctx,
                artifacts,
                title,
                job_id=job_id,
                progress_cb=progress_cb,
                pct_start=20,
                pct_end=54,
            )
            if on_update:
                on_update(dict(out))
        if "similar" in want:
            out["similar"] = run_track(
                "similar",
                ctx,
                artifacts,
                title,
                job_id=job_id,
                progress_cb=progress_cb,
                pct_start=56,
                pct_end=88,
            )
            if on_update:
                on_update(dict(out))
        if progress_cb:
            progress_cb("深度狩猎执笔", 92)
        out["report"] = write_hunt_report(
            title,
            out.get("bypass"),
            out.get("similar"),
            job_id=job_id,
            surface=out.get("surface"),
            scores=out.get("scores"),
            observations=out.get("observations"),
        )
        out["status"] = "completed"
        out["disasm_used"] = ctx.disasm_used
        out["cfg_used"] = ctx.cfg_used
        out["finished_at"] = _utc_now()
        if progress_cb:
            progress_cb("深度狩猎完成", 100)
        return out
    except PipelineCancelled:
        out["status"] = "cancelled"
        out["error"] = "已取消"
        out["finished_at"] = _utc_now()
        return out
    except Exception as e:
        out["status"] = "failed"
        out["error"] = str(e)
        out["finished_at"] = _utc_now()
        return out


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hunt_lab_dir(job_id: str, jobs_dir: Path) -> Path:
    path = Path(jobs_dir) / job_id / "hunt_lab"
    path.mkdir(parents=True, exist_ok=True)
    return path


def hunt_summary(pack: dict[str, Any] | None) -> dict[str, Any]:
    pack = pack or {}
    return {
        "run_id": pack.get("run_id") or "",
        "status": pack.get("status") or "",
        "started_at": pack.get("started_at"),
        "finished_at": pack.get("finished_at"),
        "tracks": pack.get("tracks") or [],
        "bypass_verdict": (pack.get("bypass") or {}).get("verdict"),
        "similar_verdict": (pack.get("similar") or {}).get("verdict"),
        "error": pack.get("error"),
        "has_report": bool(pack.get("report")),
    }


def load_hunt_index(job_id: str, jobs_dir: Path) -> list[dict[str, Any]]:
    path = hunt_lab_dir(job_id, jobs_dir) / "index.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def save_hunt_index(job_id: str, jobs_dir: Path, items: list[dict[str, Any]]) -> None:
    path = hunt_lab_dir(job_id, jobs_dir) / "index.json"
    path.write_text(json.dumps(items[:50], ensure_ascii=False, indent=2), encoding="utf-8")


def load_hunt_run(job_id: str, jobs_dir: Path, run_id: str) -> dict[str, Any] | None:
    if not run_id:
        return None
    path = hunt_lab_dir(job_id, jobs_dir) / f"{run_id}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def load_current_hunt_lab(job_id: str, jobs_dir: Path) -> dict[str, Any] | None:
    path = Path(jobs_dir) / job_id / "hunt_lab.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def archive_hunt_run(job_id: str, jobs_dir: Path, pack: dict[str, Any] | None) -> dict[str, Any] | None:
    """Write a finished (or interrupted) pack into hunt_lab/{run_id}.json and index.json."""
    if not pack:
        return None
    if pack.get("status") == "running" and not (pack.get("bypass") or pack.get("similar") or pack.get("report")):
        return None
    run_id = str(pack.get("run_id") or uuid.uuid4().hex[:12])
    packed = {**pack, "run_id": run_id}
    if packed.get("status") == "running":
        packed = {**packed, "status": "interrupted", "error": packed.get("error") or "中断时已归档", "finished_at": packed.get("finished_at") or _utc_now()}
    folder = hunt_lab_dir(job_id, jobs_dir)
    (folder / f"{run_id}.json").write_text(json.dumps(packed, ensure_ascii=False, indent=2), encoding="utf-8")
    if packed.get("report"):
        (folder / f"{run_id}.md").write_text(str(packed.get("report") or ""), encoding="utf-8")
    index = [row for row in load_hunt_index(job_id, jobs_dir) if row.get("run_id") != run_id]
    index.insert(0, hunt_summary(packed))
    save_hunt_index(job_id, jobs_dir, index)
    return packed


def ensure_hunt_index(job_id: str, jobs_dir: Path, current: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Backfill index.json from the latest hunt_lab.json if this job has no history yet."""
    index = load_hunt_index(job_id, jobs_dir)
    if index:
        return index
    pack = current or load_current_hunt_lab(job_id, jobs_dir)
    if pack and pack.get("status") and pack.get("status") != "running":
        archived = archive_hunt_run(job_id, jobs_dir, pack)
        if archived:
            return load_hunt_index(job_id, jobs_dir)
    return index


def stamp_hunt_pack(pack: dict[str, Any], *, existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """Keep run_id / started_at across incremental persists."""
    out = dict(pack or {})
    prev = existing or {}
    out["run_id"] = out.get("run_id") or prev.get("run_id") or uuid.uuid4().hex[:12]
    out["started_at"] = out.get("started_at") or prev.get("started_at") or _utc_now()
    st = out.get("status")
    if st in {"completed", "failed", "cancelled", "interrupted"} and not out.get("finished_at"):
        out["finished_at"] = _utc_now()
    return out

