"""Isolated research flow: surface map → handler scores → optional LLM variant hunt.

Invoked from the frontend Research menu. Not part of the main LangGraph.
No exploit / PoC / payload / IOCTL trigger steps.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from langchain_core.messages import HumanMessage, SystemMessage

from ..agents.llm import make_chat
from ..services.agent_tools import (
    HUNT_LAB_BUDGET,
    HUNT_LAB_NUDGE,
    SAFETY,
    AnalysisToolbox,
    _clip,
    bind_tools,
    run_tool_loop,
)
from ..services.llm_service import LLMError, llm_configured
from ..services.pipeline import check_cancel
from ..services.surface import build_surface_map, observations_from_scores

RESEARCH_SYSTEM = (
    "你是独立的 Windows 内核研究流程执行员，不属于主分析 19 节流水线。"
    "必须按下列顺序用工具取证，不要在脑内确认："
    "1) 读 read_evidence(surface) 与 ioctl_table，弄清用户入口（IOCTL / FastIo / Immediate）；"
    "2) 读 handler_score 与 patched_pattern，对照本次补丁 class（锁/Probe/Feature）；"
    "3) 对 high/medium 或 missing_* 的处理函数 disasm / compare_calls；"
    "4) 有汇编证据写 suspect，仅名字像写 similar，METHOD_BUFFERED 且无用户指针写 cleared；"
    "5) 输出观察条件（在哪个函数看哪把锁/引用），禁止写触发步骤或 IOCTL 发送序列。"
    "wrapper 必须看 wrapper_of / 子函数。没有工具返回就 unknown。"
    "完成后只输出 JSON："
    '{"done":true,"verdict":"none|suspects|likely|unknown","confidence":"high|medium|low",'
    '"bug_class":"...","summary":"...",'
    '"findings":[{"function":"...","pattern":"...","severity":"high|medium|low",'
    '"status":"suspect|similar|cleared","evidence":"..."}]}。'
    + SAFETY
)

WRITER_SYSTEM = (
    "根据表面图 JSON、处理函数打分、以及（若有）变体狩猎 JSON 写中文短报告。"
    "一级标题必须且仅用："
    "## 1. 结论"
    "## 2. 用户入口（IOCTL / FastIo）"
    "## 3. 处理函数打分"
    "## 4. 与本次补丁同类的残留"
    "## 5. 隔离 VM 观察清单"
    "不要套用主报告 19 节。不要写 exploit / PoC / 逐步利用 / 可复制的 IOCTL 触发序列。"
)


def _user_prompt(artifacts: dict[str, Any], title: str, surface: dict[str, Any]) -> str:
    notes = artifacts.get("agent_notes") or {}
    hunt = artifacts.get("hunt_brief") or {}
    scores = (surface.get("scores") or [])[:24]
    slim_scores = [
        {k: r.get(k) for k in ("name", "risk", "why", "method", "size")}
        for r in scores
    ]
    ioctl = ((surface.get("dispatch") or {}).get("ioctl") or [])[:20]
    return (
        f"任务: {title}\n"
        f"热点: {json.dumps((artifacts.get('hotspot_names') or [])[:12], ensure_ascii=False)}\n"
        f"根因摘要:\n{(notes.get('root_cause') or '（无）')[:1600]}\n"
        f"HuntPrep 高优先级: {json.dumps(hunt.get('high_priority') or [], ensure_ascii=False)}\n"
        f"表面图 status={surface.get('status')} handlers={surface.get('handler_count')}\n"
        f"IOCTL 摘录: {json.dumps(ioctl, ensure_ascii=False)[:2500]}\n"
        f"打分摘录: {json.dumps(slim_scores, ensure_ascii=False)[:3500]}\n"
        "可用工具: pe_info, list_symbols, function_meta, disasm, cfg_blocks, call_neighbors, "
        "patched_pattern, feature_info, read_evidence, compare_calls, ioctl_table, handler_score。\n"
        "本轮：按研究流程核对表面图与补丁 class，找出同类残留。先调用工具。"
    )


def run_research_lab(
    artifacts: dict[str, Any],
    title: str,
    *,
    new_sys: Path,
    old_sys: Path,
    work: Path,
    new_pdb: Path,
    old_pdb: Path,
    job_id: str = "",
    run_llm: bool = True,
    progress_cb: Callable[[str, int], None] | None = None,
    on_update: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    def tick(msg: str, pct: int) -> None:
        if progress_cb:
            progress_cb(msg, pct)

    tick("解析 IOCTL / FastIo 表面图", 8)
    check_cancel(job_id=job_id)
    surface = build_surface_map(new_sys, new_pdb if new_pdb.exists() else None)
    scores = surface.get("scores") or []
    obs = observations_from_scores(scores)
    pack: dict[str, Any] = {
        "status": "running",
        "isolated": True,
        "flow": ["surface", "score", "variant", "observe"],
        "surface": surface,
        "scores": scores,
        "observations": obs,
        "variant": None,
        "report": "",
        "error": None,
        "llm": False,
    }
    artifacts = {**artifacts, "surface_map": surface, "handler_scores": scores}
    if on_update:
        on_update(pack)
    work.mkdir(parents=True, exist_ok=True)
    (work / "surface_map.json").write_text(json.dumps(surface, ensure_ascii=False, indent=2), encoding="utf-8")
    (work / "handler_scores.json").write_text(json.dumps(scores, ensure_ascii=False, indent=2), encoding="utf-8")

    tick("表面图完成，处理函数已打分", 42)
    if run_llm:
        if not llm_configured():
            pack["error"] = "LLM API key 未配置；已保留表面图与打分，未跑变体狩猎"
            pack["status"] = "completed"
            pack["llm"] = False
            tick("跳过 LLM，仅输出表面图", 100)
            pack["report"] = _offline_report(title, surface, scores, obs, pack.get("error"))
            return pack
        tick("对照补丁 class 做变体狩猎", 50)
        ctx = AnalysisToolbox(
            artifacts,
            old_sys=old_sys,
            new_sys=new_sys,
            work=work,
            disasm_budget=HUNT_LAB_BUDGET.disasm_budget,
            cfg_budget=HUNT_LAB_BUDGET.cfg_budget,
        )
        try:
            result = run_tool_loop(
                system=RESEARCH_SYSTEM,
                user=_user_prompt(artifacts, title, surface),
                tools=bind_tools(ctx),
                job_id=job_id,
                budget=HUNT_LAB_BUDGET,
                require_json=True,
                progress_cb=progress_cb,
                progress_label="研究流程 · 变体",
                pct_start=50,
                pct_end=82,
                nudge=HUNT_LAB_NUDGE,
            )
            variant = result.parsed or {"verdict": "unknown", "summary": result.text[:1500], "findings": []}
            if not isinstance(variant, dict):
                variant = {"verdict": "unknown", "summary": str(variant)[:1500], "findings": []}
            variant["tool_calls"] = result.tool_log
            variant["tool_call_count"] = result.calls
            variant["rounds"] = result.rounds
            pack["variant"] = variant
            pack["llm"] = True
        except LLMError as e:
            pack["variant"] = {"verdict": "unknown", "summary": f"模型调用失败: {e}", "findings": []}
            pack["error"] = str(e)
        if on_update:
            on_update(pack)
        tick("撰写研究短报告", 88)
        try:
            check_cancel(job_id=job_id)
            llm = make_chat(max_tokens=4000, temperature=0.1)
            user = (
                f"任务: {title}\n\n"
                f"## 表面图\n{_clip({k: surface.get(k) for k in ('status', 'dispatch', 'immediate', 'fastio', 'handler_count')}, 6000)}\n\n"
                f"## 打分 high/medium\n{_clip([r for r in scores if r.get('risk') in ('high', 'medium')][:20], 4000)}\n\n"
                f"## 变体 JSON\n{_clip(pack.get('variant') or {'skipped': True}, 5000)}\n\n"
                "按五节模板写中文。引用工具或表面图里出现过的函数名。禁止 exploit。"
            )
            resp = llm.invoke([SystemMessage(content=WRITER_SYSTEM), HumanMessage(content=user)])
            content = getattr(resp, "content", "") or ""
            if isinstance(content, list):
                content = "".join(str(x) for x in content)
            pack["report"] = str(content).strip()
        except Exception as e:
            pack["report"] = _offline_report(title, surface, scores, obs, str(e))
    else:
        pack["llm"] = False
        pack["report"] = _offline_report(title, surface, scores, obs, None)

    pack["status"] = "completed"
    pack["disasm_used"] = None
    tick("研究流程完成", 100)
    return pack


def _offline_report(title: str, surface: dict, scores: list, obs: list, err: str | None) -> str:
    high = [r for r in scores if r.get("risk") == "high"]
    med = [r for r in scores if r.get("risk") == "medium"]
    lines = [
        f"# {title} · 研究流程",
        "",
        "## 1. 结论",
        err or f"表面图 status={surface.get('status')}，处理函数 {surface.get('handler_count')} 个。"
        f" high={len(high)} medium={len(med)}。未跑 LLM 变体时，high/medium 仅表示静态启发式。",
        "",
        "## 2. 用户入口（IOCTL / FastIo）",
        f"- DeviceControl: {(surface.get('dispatch') or {}).get('handler')} "
        f"槽={(surface.get('dispatch') or {}).get('limit')}",
        f"- Immediate: {(surface.get('immediate') or {}).get('symbol')} "
        f"已填={(surface.get('immediate') or {}).get('filled')}",
        f"- FastIo 直接调用: {len(((surface.get('fastio') or {}).get('callees') or []))}",
        "",
        "## 3. 处理函数打分",
    ]
    for r in (high + med)[:16]:
        lines.append(f"- `{r.get('name')}` · {r.get('risk')} · {'; '.join(r.get('why') or [])}")
    if not high and not med:
        lines.append("- 无 high/medium。多数处理函数为 hardened / wrapper / buffered。")
    lines += ["", "## 4. 与本次补丁同类的残留", "- 未启用 LLM，本节为空。", "", "## 5. 隔离 VM 观察清单"]
    for o in obs[:12]:
        lines.append(f"- `{o.get('function')}` {o.get('bp') or ''} — {o.get('watch')}（{o.get('why')}）")
    if not obs:
        lines.append("- 无 high/medium，不生成观察点。")
    lines.append("")
    lines.append("禁止 exploit / PoC / 逐步触发。")
    return "\n".join(lines)
