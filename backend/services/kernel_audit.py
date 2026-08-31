"""Single-binary Windows kernel LPE audit.

PE → PDB → surface map → absolute pattern scan → optional LLM classify.
No exploit / PoC / payload / IOCTL trigger steps.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from langchain_core.messages import HumanMessage, SystemMessage

from ..agents.llm import make_chat
from ..services.agent_tools import (
    AUDIT_SHARED_CFG,
    AUDIT_SHARED_DISASM,
    PATH_BUDGET,
    PATH_HARDENED_BUDGET,
    PATH_HARDENED_NUDGE,
    PATH_NUDGE,
    SAFETY,
    AnalysisToolbox,
    _clip,
    bind_tools,
    run_tool_loop,
)
from ..services.analyzer import disassemble_functions, extract_pe, fetch_pdb, pdb_ok
from ..services.llm_service import LLMError, llm_configured
from ..services.lpe_patterns import classify_audit, observations_from_audit
from ..services.pipeline import PipelineCancelled, check_cancel
from ..services.surface import build_surface_map

MAX_PATH_AGENTS = 32
AGENTS_CHECKPOINT = "path_agents.json"
_RISKY_METHOD = {"neither", "in_direct", "out_direct"}
_RISK_PRI = {"high": 0, "medium": 1, "low": 2, "buffered": 3, "hardened": 4, "wrapper": 5}
_KIND_PRI = {"immediate": 0, "ioctl": 1, "fastio": 2, "major": 3}

PATH_SYSTEM = (
    "你是专门审计一条用户可达入口的 Windows 内核研究员。"
    "其它入口由别的 agent 负责，禁止切换目标、禁止扫整份驱动。"
    "确定性扫描只是起点。从本入口处理函数开始，按调用链循环跟，直到这条路径没有提权面，或证据在某一跳断掉。"
    "流程："
    "1) disasm 本入口 handler，列出 CALL；"
    "2) 本模块子函数继续 disasm；"
    "3) CALL/导入指向其它 .sys/.dll 时先 list_imports，再 load_module(文件名)，"
    "然后 disasm(name, module=该文件) 继续跟；"
    "4) 用户数据被 Probe/MDL/METHOD_BUFFERED 消化、或锁/特权检查挡住 → findings 写 cleared；"
    "5) 有汇编证据写 suspect；只跟了一半且下一步还能 disasm/load_module 的放进 unresolved，禁止 done；"
    "load_module 失败或符号缺失写入 blocked（附原因）后可以 done。"
    "没有 patched_pattern。禁止 exploit / PoC / IOCTL 触发序列。"
    "完成后只输出 JSON："
    '{"done":true,"verdict":"none|suspects|likely|unknown","confidence":"high|medium|low",'
    '"bug_class":"...","summary":"...",'
    '"followed":["模块!函数"],'
    '"unresolved":["还能继续跟的下一跳"],'
    '"blocked":[{"hop":"...","reason":"..."}],'
    '"findings":[{"function":"...","module":"...","pattern":"...","severity":"high|medium|low",'
    '"status":"suspect|similar|cleared","evidence":"..."}]}。'
    + SAFETY
)

WRITER_SYSTEM = (
    "根据表面图、处理函数打分、确定性扫描以及「每个入口一个 agent」的跟链 JSON 写中文短报告。"
    "一级标题必须且仅用："
    "## 1. 结论"
    "## 2. 用户入口（IOCTL / FastIo / MajorFunction）"
    "## 3. 处理函数打分"
    "## 4. 缺陷类证据"
    "## 5. 隔离 VM 观察清单"
    "§2 写清拆出了多少个入口 agent。"
    "§1/§4 按入口分组：哪条已经跟到其它模块、哪条在哪一跳停下、为什么还不能排除提权。"
    "不要套用主报告 19 节。不要写 exploit / PoC / 逐步利用 / 可复制的 IOCTL 触发序列。"
    "没有证据的嫌疑写成待核对，不要硬编。"
)


def _tick(cb: Callable[[str, int], None] | None, msg: str, pct: int) -> None:
    if cb:
        cb(msg, pct)


_SKIP_CALLEE = (
    r"^(Feature_|WPP_|_guard_|Rtl|Ex[A-Z]|Ke[A-Z]|Io[A-Z]|Ob[A-Z]|Mm[A-Z]|Nt[A-Z]|Zw[A-Z]|"
    r"Hal|Ps[A-Z]|Se[A-Z]|Cc[A-Z]|FsRtl|memcpy|memmove|memset|memcmp|Iof|"
    r"ProbeFor|MmProbe|__security|__chkstk|memmove_s|memcpy_s)"
)


def _interesting_callee(name: str) -> bool:
    n = str(name or "").strip()
    if not n or len(n) < 4:
        return False
    if "__private_" in n or n.startswith("Feature_"):
        return False
    if re.match(_SKIP_CALLEE, n, re.I):
        return False
    return bool(re.match(r"^[A-Za-z_][\w]*$", n))


def _score_by_name(scores: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(s.get("name") or ""): s for s in scores if s.get("name")}


def _handler_ok(name: str) -> bool:
    n = str(name or "").strip()
    if not n or n in {"(null)", "null"}:
        return False
    if n.startswith("sub_") or n.startswith("Feature_") or n.startswith("WPP_"):
        return False
    return True


def _want_hunt_api(method: str | None, score: dict[str, Any] | None, *, default_if_unscored: bool = False) -> bool:
    risk = str((score or {}).get("risk") or "")
    if risk in {"high", "medium"}:
        return True
    if method in _RISKY_METHOD:
        return True
    if default_if_unscored and not score:
        return True
    if risk in {"wrapper", "buffered", "hardened"}:
        return False
    return False


def _entry_budget(risk: str | None) -> str:
    return "short" if str(risk or "") in {"hardened", "wrapper"} else "full"


def collect_hunt_apis(
    surface: dict[str, Any],
    scores: list[dict[str, Any]] | None = None,
    *,
    cap: int = MAX_PATH_AGENTS,
) -> list[dict[str, Any]]:
    """One agent per user-reachable API that can still carry an LPE surface.

    METHOD_NEITHER / Direct IOCTLs, Immediate table slots, FastIo data-path
    callees, and high/medium MajorFunction entries. IOCTLs that share a
    trampoline (DeviceControl / ImmediateCallDispatch) collapse to the table
    targets so we do not spawn N identical dispatcher agents.
    """
    by = _score_by_name(list(scores or surface.get("scores") or []))
    dispatch = surface.get("dispatch") or {}
    immediate = surface.get("immediate") or {}
    trampolines = {str(dispatch.get("handler") or ""), str(immediate.get("symbol") or "")} - {""}
    have_imm = bool(immediate.get("entries"))

    def is_trampoline(name: str) -> bool:
        if name in trampolines:
            return True
        return bool(have_imm and re.search(r"(DispatchImmediateIrp|ImmediateCallDispatch)$", name, re.I))
    apis: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(api: dict[str, Any]) -> None:
        h = str(api.get("handler") or "")
        if not _handler_ok(h) or h in seen:
            return
        seen.add(h)
        apis.append(api)

    for row in immediate.get("entries") or []:
        h = str(row.get("handler") or "")
        sc = by.get(h)
        if sc and sc.get("risk") == "wrapper":
            continue
        if not _want_hunt_api(None, sc, default_if_unscored=True):
            continue
        idx = row.get("index")
        add(
            {
                "id": f"immediate:{h}",
                "kind": "immediate",
                "handler": h,
                "codes": [],
                "index": idx,
                "method": "neither",
                "risk": (sc or {}).get("risk") or "medium",
                "budget": _entry_budget((sc or {}).get("risk") or "medium"),
                "title": f"Immediate[{idx}] → {h}",
            }
        )

    groups: dict[str, list[dict[str, Any]]] = {}
    for row in dispatch.get("ioctl") or []:
        if not isinstance(row, dict):
            continue
        h = str(row.get("handler") or "")
        if have_imm and is_trampoline(h):
            continue
        sc = by.get(h)
        if not _want_hunt_api(row.get("method"), sc):
            continue
        groups.setdefault(h, []).append(row)

    for h, rows in groups.items():
        codes = [str(r.get("code")) for r in rows if r.get("code")]
        methods = [str(r.get("method") or "") for r in rows]
        method = "neither" if "neither" in methods else (methods[0] if methods else "")
        sc = by.get(h) or {}
        label = ", ".join(codes[:4]) if codes else "IOCTL"
        if len(codes) > 4:
            label += f" 等{len(codes)}个"
        add(
            {
                "id": f"ioctl:{h}",
                "kind": "ioctl",
                "handler": h,
                "codes": codes[:32],
                "method": method,
                "risk": sc.get("risk") or method or "medium",
                "budget": _entry_budget(sc.get("risk") or method or "medium"),
                "title": f"IOCTL {label} → {h}",
            }
        )

    for edge in (surface.get("fastio") or {}).get("callees") or []:
        if not isinstance(edge, dict):
            continue
        h = str(edge.get("to") or "")
        sc = by.get(h)
        if sc and sc.get("risk") == "wrapper":
            continue
        named_fast = bool(re.search(r"(FastIo|RioFastIo|DeviceControl)$", h, re.I))
        if not named_fast and not _interesting_callee(h):
            continue
        if not _want_hunt_api(None, sc, default_if_unscored=named_fast):
            continue
        add(
            {
                "id": f"fastio:{h}",
                "kind": "fastio",
                "handler": h,
                "codes": [],
                "method": "fastio",
                "risk": (sc or {}).get("risk") or "medium",
                "budget": _entry_budget((sc or {}).get("risk") or "medium"),
                "title": f"FastIo → {h}",
            }
        )

    for mj, rec in (surface.get("major_functions") or {}).items():
        if mj in {"close", "cleanup"}:
            continue
        h = str((rec or {}).get("handler") or "")
        sc = by.get(h)
        if not _want_hunt_api(None, sc):
            continue
        add(
            {
                "id": f"mj:{mj}:{h}",
                "kind": "major",
                "major": mj,
                "handler": h,
                "codes": [],
                "method": str(mj),
                "risk": (sc or {}).get("risk") or "medium",
                "budget": _entry_budget((sc or {}).get("risk") or "medium"),
                "title": f"IRP_MJ_{str(mj).upper()} → {h}",
            }
        )

    apis.sort(
        key=lambda a: (
            _RISK_PRI.get(str(a.get("risk") or ""), 6),
            _KIND_PRI.get(str(a.get("kind") or ""), 9),
            str(a.get("handler") or ""),
        )
    )
    return apis[: max(0, int(cap))]


def _path_done_ok(parsed: dict[str, Any] | None, _log: list) -> bool:
    if not isinstance(parsed, dict):
        return False
    hops = [str(x).strip() for x in (parsed.get("unresolved") or []) if str(x).strip()]
    return not hops


def _api_key(api: dict[str, Any]) -> str:
    return str(api.get("id") or api.get("handler") or "")


def _agent_complete(rec: dict[str, Any] | None) -> bool:
    if not rec:
        return False
    if rec.get("error"):
        return False
    return bool(rec.get("rounds") or rec.get("verdict") in {"none", "suspects", "likely", "unknown"})


def _is_quota_error(err: str | None) -> bool:
    s = (err or "").lower()
    return any(
        x in s
        for x in (
            "402",
            "429",
            "insufficient",
            "balance",
            "quota",
            "rate limit",
            "rate_limit",
            "too many requests",
        )
    )


def _finalize_budget(rec: dict[str, Any], *, max_rounds: int, max_calls: int) -> dict[str, Any]:
    hops = [str(x).strip() for x in (rec.get("unresolved") or []) if str(x).strip()]
    exhausted = int(rec.get("rounds") or 0) >= max_rounds or int(rec.get("tool_call_count") or 0) >= max_calls
    if hops and exhausted:
        blocked = list(rec.get("blocked") or [])
        seen = {(str(b.get("hop") or "") if isinstance(b, dict) else str(b)) for b in blocked}
        for hop in hops:
            if hop in seen:
                continue
            blocked.append({"hop": hop, "reason": "budget_exhausted"})
            seen.add(hop)
        rec["blocked"] = blocked
        rec["unresolved"] = []
        if rec.get("verdict") not in {"likely", "suspects"}:
            rec["verdict"] = "unknown"
        note = "预算用尽，剩余跳记入 blocked。"
        rec["summary"] = (str(rec.get("summary") or "").rstrip() + " " + note).strip()
    return rec


def _load_agent_checkpoint(work: Path) -> list[dict[str, Any]]:
    path = Path(work) / AGENTS_CHECKPOINT
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return []
    if isinstance(data, dict):
        data = data.get("agents") or []
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def _save_agent_checkpoint(work: Path, agents: list[dict[str, Any]]) -> None:
    path = Path(work) / AGENTS_CHECKPOINT
    path.write_text(
        json.dumps({"agents": [_agent_public(r) for r in agents]}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _pack_llm(
    agents: list[dict[str, Any]],
    classified: dict[str, Any],
    artifacts: dict[str, Any],
    *,
    error: str | None = None,
) -> dict[str, Any]:
    public = [_agent_public(r) for r in agents]
    all_findings: list[dict[str, Any]] = []
    followed: list[str] = []
    unresolved: list[str] = []
    blocked: list[Any] = []
    for rec in public:
        all_findings.extend(rec.get("findings") or [])
        followed.extend(str(x) for x in (rec.get("followed") or []) if x)
        unresolved.extend(str(x) for x in (rec.get("unresolved") or []) if x)
        blocked.extend(rec.get("blocked") or [])
    pack = {
        "mode": "per_api_agents",
        "agent_count": len(public),
        "agents": public,
        "verdict": _aggregate_verdict(
            str(classified.get("verdict") or "none"),
            [str(r.get("verdict") or "") for r in public],
        ),
        "summary": "；".join(
            f"{r.get('handler')}: {(r.get('summary') or r.get('verdict') or '')[:80]}" for r in public[:12]
        ),
        "findings": all_findings,
        "followed": followed,
        "unresolved": unresolved,
        "blocked": blocked,
        "tool_call_count": sum(int(r.get("tool_call_count") or 0) for r in public),
        "rounds": sum(int(r.get("rounds") or 0) for r in public),
        "loaded_modules": artifacts.get("loaded_modules") or [],
    }
    if error:
        pack["error"] = error
    return pack


def _publish_partial(
    *,
    job_id: str,
    work: Path,
    artifacts: dict[str, Any],
    hunt_apis: list[dict[str, Any]],
    classified: dict[str, Any],
    obs: list[dict[str, Any]],
    agents: list[dict[str, Any]],
    scores: list[dict[str, Any]],
    surface: dict[str, Any],
    error: str | None = None,
) -> dict[str, Any]:
    llm_pack = _pack_llm(agents, classified, artifacts, error=error)
    pack = {
        "kind": "kernel_audit",
        "status": "running",
        "verdict": llm_pack.get("verdict") or classified.get("verdict") or "none",
        "bug_classes": classified.get("bug_classes") or [],
        "findings": _merge_llm_findings(
            list(classified.get("findings") or []),
            llm_pack.get("findings") if isinstance(llm_pack.get("findings"), list) else [],
        ),
        "observations": obs,
        "surface": surface,
        "scores": scores,
        "hunt_apis": hunt_apis,
        "agents": llm_pack.get("agents") or [],
        "llm": True,
        "llm_review": llm_pack,
        "loaded_modules": artifacts.get("loaded_modules") or [],
        "error": error,
    }
    artifacts["kernel_audit"] = pack
    _save_agent_checkpoint(work, agents)
    (work / "kernel_audit.json").write_text(json.dumps(pack, ensure_ascii=False, indent=2), encoding="utf-8")
    if job_id:
        try:
            from ..database import update_job

            update_job(
                job_id,
                result_json=json.dumps(
                    {"artifacts": artifacts, "graph": "kernel-audit"},
                    ensure_ascii=False,
                ),
            )
        except Exception:
            pass
    return llm_pack


def _verdict_rank(v: str) -> int:
    return {"likely": 0, "suspects": 1, "unknown": 2, "none": 3}.get(str(v or ""), 4)


def _aggregate_verdict(current: str, extras: list[str]) -> str:
    best = str(current or "none")
    for v in extras:
        if _verdict_rank(v) < _verdict_rank(best):
            best = v
    return best if best in {"likely", "suspects", "none", "unknown"} else "unknown"


def _agent_public(rec: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k in (
        "id",
        "kind",
        "handler",
        "codes",
        "method",
        "title",
        "verdict",
        "summary",
        "followed",
        "unresolved",
        "blocked",
        "findings",
        "rounds",
        "tool_call_count",
        "error",
        "budget",
        "resumed",
    ):
        if k in rec:
            out[k] = rec[k]
    return out


def _path_user(
    *,
    title: str,
    pe: dict[str, Any],
    sys_name: str,
    api: dict[str, Any],
    scores: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    followed: list[str],
) -> str:
    handler = str(api.get("handler") or "")
    sc = next((r for r in scores if r.get("name") == handler), {}) or {}
    related = [f for f in findings if str(f.get("function") or "") == handler]
    codes = api.get("codes") or []
    return (
        f"任务: {title}\n"
        f"样本: {pe.get('original_filename') or sys_name} {pe.get('file_version') or ''}\n"
        f"你只负责这一条入口，不要审其它 IOCTL / Immediate 槽。\n"
        f"入口: {api.get('title')}\n"
        f"kind={api.get('kind')} handler={handler} method={api.get('method')}\n"
        f"IOCTL codes: {', '.join(str(c) for c in codes) or '（无独立 code，从处理函数跟）'}\n"
        f"打分: risk={sc.get('risk') or api.get('risk')} size={sc.get('size')} "
        f"why={'; '.join(sc.get('why') or [])}\n"
        f"top_calls: {', '.join(str(c) for c in (sc.get('top_calls') or [])[:8]) or '无'}\n"
        f"本函数确定性起点: {_clip(related, 1500) if related else '无'}\n"
        f"已预反汇编（本模块，可复用）: {', '.join(followed[:24]) or '无'}\n"
        "工具: list_imports, load_module, disasm, list_symbols, function_meta, xrefs, call_neighbors, "
        "cfg_blocks, ioctl_table, handler_score, read_evidence, pe_info。\n"
        f"从 `{handler}` 开始 disasm，顺着 CALL 跟链循环，直到 unresolved 为空。"
        + (
            "本入口静态已 hardened：只确认 Probe/MDL 仍罩住用户数据即可 cleared，不要扫无关调用。"
            if api.get("budget") == "short"
            else "跨模块先 load_module 再 disasm(name, module=...)。"
        )
        + "禁止 exploit。"
    )


def _run_path_agents(
    *,
    apis: list[dict[str, Any]],
    ctx: AnalysisToolbox,
    artifacts: dict[str, Any],
    title: str,
    pe: dict[str, Any],
    sys_name: str,
    scores: list[dict[str, Any]],
    classified: dict[str, Any],
    followed_names: list[str],
    job_id: str,
    work: Path,
    hunt_apis: list[dict[str, Any]],
    obs: list[dict[str, Any]],
    surface: dict[str, Any],
    progress_cb: Callable[[str, int], None] | None,
    resume: bool = False,
) -> dict[str, Any]:
    saved = _load_agent_checkpoint(work) if resume else []
    done_by = {_api_key(r): r for r in saved if _agent_complete(r)}
    agents: list[dict[str, Any]] = []
    findings = list(classified.get("findings") or [])
    n = max(1, len(apis))
    tools = bind_tools(ctx)
    quota_error: str | None = None
    for i, api in enumerate(apis):
        key = _api_key(api)
        lo = 76 + int(16 * i / n)
        hi = 76 + int(16 * (i + 1) / n)
        short = api.get("budget") == "short"
        budget = PATH_HARDENED_BUDGET if short else PATH_BUDGET
        label = f"入口 {i + 1}/{len(apis)} · {api.get('handler')}"
        if short:
            label += " · 短确认"
        check_cancel(job_id=job_id)
        prev = done_by.get(key)
        if prev:
            rec = dict(prev)
            rec["resumed"] = True
            agents.append(rec)
            _tick(progress_cb, f"{label} · 已缓存", hi)
            continue
        _tick(progress_cb, label, lo)
        try:
            ctx.reset_path_counters()
        except Exception:
            ctx.disasm_used = 0
            ctx.cfg_used = 0
        rec: dict[str, Any] = {
            **{k: api.get(k) for k in ("id", "kind", "handler", "codes", "method", "title", "budget")},
            "verdict": "unknown",
            "summary": "",
            "followed": [],
            "unresolved": [],
            "blocked": [],
            "findings": [],
            "rounds": 0,
            "tool_call_count": 0,
        }
        try:
            result = run_tool_loop(
                system=PATH_SYSTEM,
                user=_path_user(
                    title=title,
                    pe=pe,
                    sys_name=sys_name,
                    api=api,
                    scores=scores,
                    findings=findings,
                    followed=followed_names,
                ),
                tools=tools,
                job_id=job_id,
                budget=budget,
                require_json=True,
                progress_cb=progress_cb,
                progress_label=label,
                pct_start=lo,
                pct_end=max(lo + 1, hi),
                nudge=PATH_HARDENED_NUDGE if short else PATH_NUDGE,
                done_ok=_path_done_ok,
            )
            parsed = result.parsed if isinstance(result.parsed, dict) else None
            if parsed is None:
                parsed = {"verdict": "unknown", "summary": (result.text or "")[:1500], "findings": []}
            rec["verdict"] = parsed.get("verdict") or "unknown"
            rec["summary"] = str(parsed.get("summary") or "")[:1500]
            rec["followed"] = parsed.get("followed") if isinstance(parsed.get("followed"), list) else []
            rec["unresolved"] = parsed.get("unresolved") if isinstance(parsed.get("unresolved"), list) else []
            rec["blocked"] = parsed.get("blocked") if isinstance(parsed.get("blocked"), list) else []
            rec["findings"] = parsed.get("findings") if isinstance(parsed.get("findings"), list) else []
            rec["rounds"] = result.rounds
            rec["tool_call_count"] = result.calls
            rec["tool_calls"] = (result.tool_log or [])[-6:]
            _finalize_budget(rec, max_rounds=budget.max_rounds, max_calls=budget.max_tool_calls)
        except LLMError as e:
            rec["error"] = str(e)
            rec["summary"] = f"模型调用失败: {e}"
            agents.append(rec)
            if _is_quota_error(str(e)):
                quota_error = str(e)
                _publish_partial(
                    job_id=job_id,
                    work=work,
                    artifacts=artifacts,
                    hunt_apis=hunt_apis,
                    classified=classified,
                    obs=obs,
                    agents=agents,
                    scores=scores,
                    surface=surface,
                    error=quota_error,
                )
                break
        else:
            agents.append(rec)
        _publish_partial(
            job_id=job_id,
            work=work,
            artifacts=artifacts,
            hunt_apis=hunt_apis,
            classified=classified,
            obs=obs,
            agents=agents,
            scores=scores,
            surface=surface,
            error=quota_error,
        )
    return _pack_llm(agents, classified, artifacts, error=quota_error)


def _pick_disasm_names(scores: list[dict[str, Any]], *, limit: int = 18) -> list[str]:
    ranked = [r for r in scores if r.get("risk") in {"high", "medium"} and r.get("name")]
    names = [str(r["name"]) for r in ranked]
    if len(names) < limit:
        for r in scores:
            n = str(r.get("name") or "")
            if n and n not in names and r.get("risk") not in {"wrapper"}:
                names.append(n)
            if len(names) >= limit:
                break
    return names[:limit]


def _callee_follow_names(
    scores: list[dict[str, Any]],
    blocks: list[dict[str, Any]],
    already: list[str],
    *,
    limit: int = 12,
) -> list[str]:
    known = {str(n) for n in already if n}
    out: list[str] = []

    def add(name: str) -> None:
        n = str(name or "").strip()
        if not _interesting_callee(n) or n in known:
            return
        known.add(n)
        out.append(n)

    for row in scores:
        if row.get("risk") not in {"high", "medium"}:
            continue
        for c in row.get("top_calls") or []:
            add(c)
            if len(out) >= limit:
                return out
    for block in blocks:
        side = block.get("new") or block.get("old") or {}
        for c in side.get("calls") or []:
            add(c)
            if len(out) >= limit:
                return out
    return out


def _merge_blocks(base: list[dict[str, Any]], extra: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by = {str(b.get("name") or ""): b for b in base if b.get("name")}
    for b in extra:
        n = str(b.get("name") or "")
        if n and n not in by:
            by[n] = b
            base.append(b)
    return base


def _offline_report(
    title: str,
    pe: dict[str, Any],
    surface: dict[str, Any],
    scores: list[dict[str, Any]],
    classified: dict[str, Any],
    obs: list[dict[str, Any]],
    err: str | None,
    agents: list[dict[str, Any]] | None = None,
    hunt_apis: list[dict[str, Any]] | None = None,
) -> str:
    high = [r for r in scores if r.get("risk") == "high"]
    med = [r for r in scores if r.get("risk") == "medium"]
    suspects = [f for f in (classified.get("findings") or []) if f.get("status") == "suspect"]
    agent_rows = list(agents or [])
    done_n = sum(1 for a in agent_rows if _agent_complete(a))
    err_n = sum(1 for a in agent_rows if a.get("error"))
    hunt_n = len(hunt_apis or collect_hunt_apis(surface, scores))
    conclusion = (
        f"单文件审计，无补丁对照。样本 `{pe.get('original_filename') or ''}` "
        f"{pe.get('file_version') or ''}。表面图 status={surface.get('status')}，"
        f"处理函数 {surface.get('handler_count')}，high={len(high)} medium={len(med)}，"
        f"可跟入口 {hunt_n}，已跟完 {done_n}/{max(hunt_n, len(agent_rows) or hunt_n)}，"
        f"确定性 verdict={classified.get('verdict')}。"
        " high/medium 与 suspect 仅为静态启发式，需隔离环境人工核对。"
    )
    if err:
        prefix = "模型额度不足，已停后续入口。" if _is_quota_error(err) else "模型调用失败。"
        conclusion = f"{prefix} 已保留 {done_n} 条跟链结果" + (f"，{err_n} 条失败。" if err_n else "。") + f" {conclusion}"
    lines = [
        f"# {title} · 内核审计",
        "",
        "## 1. 结论",
        conclusion,
        "",
        "## 2. 用户入口（IOCTL / FastIo / MajorFunction）",
        f"- DeviceControl: {(surface.get('dispatch') or {}).get('handler')} "
        f"槽={(surface.get('dispatch') or {}).get('limit')}",
        f"- Immediate: {(surface.get('immediate') or {}).get('symbol')} "
        f"已填={(surface.get('immediate') or {}).get('filled')}",
        f"- FastIo 直接调用: {len(((surface.get('fastio') or {}).get('callees') or []))}",
    ]
    major = surface.get("major_functions") or {}
    if major:
        bits = [f"{k}=`{(v or {}).get('handler')}`" for k, v in major.items()]
        lines.append(f"- MajorFunction: {', '.join(bits)}")
    else:
        lines.append("- MajorFunction: 未从符号解析到 Create/Close/Cleanup 等入口")
    if agent_rows:
        lines.append(f"- 入口 agent: {done_n}/{max(hunt_n, len(agent_rows))} 已跟完")
        for a in agent_rows[:24]:
            bits = f"- `{a.get('handler')}` · {a.get('verdict') or '—'} · {a.get('rounds') or 0} 轮"
            if a.get("error"):
                bits += " · 失败"
            elif a.get("blocked"):
                bits += f" · blocked {len(a.get('blocked') or [])}"
            summary = str(a.get("summary") or "")[:120]
            if summary:
                bits += f" — {summary}"
            lines.append(bits)
    lines += ["", "## 3. 处理函数打分"]
    for r in (high + med)[:16]:
        lines.append(f"- `{r.get('name')}` · {r.get('risk')} · {'; '.join(r.get('why') or [])}")
    if not high and not med:
        lines.append("- 无 high/medium。多数处理函数为 hardened / wrapper / buffered。")
    lines += ["", "## 4. 缺陷类证据"]
    if suspects:
        for f in suspects[:20]:
            lines.append(
                f"- `{f.get('function')}` · {f.get('pattern')} · {f.get('severity')} — {f.get('evidence')}"
            )
    else:
        lines.append("- 确定性扫描未给出 suspect。并不代表没有漏洞。")
    lines += ["", "## 5. 隔离 VM 观察清单"]
    for o in obs[:12]:
        lines.append(f"- `{o.get('function')}` {o.get('bp') or ''} — {o.get('watch')}（{o.get('why')}）")
    if not obs:
        lines.append("- 无 high/medium/suspect，不生成观察点。")
    lines.append("")
    lines.append("禁止 exploit / PoC / 逐步触发。")
    return "\n".join(lines)


def _merge_llm_findings(base: list[dict[str, Any]], extra: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    by: dict[tuple[str, str], dict[str, Any]] = {}
    for row in base:
        by[(str(row.get("function") or ""), str(row.get("pattern") or ""))] = dict(row)
    for row in extra or []:
        if not isinstance(row, dict):
            continue
        key = (str(row.get("function") or ""), str(row.get("pattern") or row.get("bug_class") or ""))
        if not key[0]:
            continue
        cur = by.get(key) or {}
        merged = {**cur, **{k: row[k] for k in row if row.get(k) not in (None, "")}}
        by[key] = merged
    return list(by.values())


def run_kernel_audit(
    sys_path: Path,
    work: Path,
    title: str,
    *,
    job_id: str = "",
    run_llm: bool = True,
    resume: bool = False,
    progress_cb: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    sys_path = Path(sys_path)
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    pdb_dir = work / "pdb"
    pdb_dir.mkdir(parents=True, exist_ok=True)
    pdb_path = pdb_dir / "audit.pdb"

    def tick(msg: str, pct: int) -> None:
        check_cancel(job_id=job_id)
        _tick(progress_cb, msg, pct)

    tick("提取 PE 元数据", 8)
    pe = extract_pe(sys_path)
    (work / "pe.json").write_text(json.dumps(pe, ensure_ascii=False, indent=2), encoding="utf-8")

    pdb_error = None
    tick("下载 / 复用 PDB", 22)
    try:
        fetch_pdb(pe, pdb_path)
    except Exception as e:
        pdb_error = str(e)
        pdb_path = Path()

    have_pdb = pdb_ok(pdb_path)
    tick("解析 IOCTL / FastIo / MajorFunction 表面图", 40)
    surface = build_surface_map(sys_path, pdb_path if have_pdb else None)
    scores = list(surface.get("scores") or [])
    (work / "surface_map.json").write_text(json.dumps(surface, ensure_ascii=False, indent=2), encoding="utf-8")
    (work / "handler_scores.json").write_text(json.dumps(scores, ensure_ascii=False, indent=2), encoding="utf-8")

    tick("反汇编高优先级处理函数", 58)
    names = _pick_disasm_names(scores)
    blocks: list[dict[str, Any]] = []
    if names:
        try:
            blocks = disassemble_functions(
                sys_path,
                sys_path,
                pdb_path if have_pdb else Path(),
                pdb_path if have_pdb else Path(),
                names,
            )
        except Exception:
            blocks = []
    extra_names = _callee_follow_names(scores, blocks, names)
    if extra_names:
        tick("反汇编处理函数的本模块子函数", 64)
        try:
            extra_blocks = disassemble_functions(
                sys_path,
                sys_path,
                pdb_path if have_pdb else Path(),
                pdb_path if have_pdb else Path(),
                extra_names,
            )
            blocks = _merge_blocks(blocks, extra_blocks)
            names = names + [n for n in extra_names if n not in names]
        except Exception:
            extra_names = []
    if blocks:
        (work / "audit_disasm.json").write_text(
            json.dumps(
                [{"name": b.get("name"), "rva": (b.get("new") or {}).get("rva"), "size": (b.get("new") or {}).get("size")} for b in blocks],
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    tick("确定性缺陷类扫描", 70)
    classified = classify_audit(scores, blocks)
    obs = observations_from_audit(classified.get("findings") or [], scores)
    hunt_apis = collect_hunt_apis(surface, scores)
    llm_pack: dict[str, Any] | None = None
    report = ""
    llm_error = None

    artifacts: dict[str, Any] = {
        "kind": "kernel_audit",
        "paths": {
            "sys": str(sys_path),
            "new_sys": str(sys_path),
            "old_sys": str(sys_path),
            "new_pdb": str(pdb_path) if have_pdb else "",
            "old_pdb": str(pdb_path) if have_pdb else "",
            "work": str(work),
        },
        "new_pe": pe,
        "old_pe": pe,
        "surface_map": surface,
        "handler_scores": scores,
        "disassembly": blocks,
        "hotspot_names": names,
        "observations": obs,
        "kernel_audit": {
            "kind": "kernel_audit",
            "verdict": classified.get("verdict") or "none",
            "bug_classes": classified.get("bug_classes") or [],
            "findings": classified.get("findings") or [],
            "observations": obs,
            "hunt_apis": hunt_apis,
        },
        "labels": {"old": pe.get("original_filename") or sys_path.name, "new": "单文件审计"},
    }

    if run_llm:
        if not llm_configured():
            llm_error = "LLM API key 未配置；已保留表面图与确定性扫描"
            tick("跳过 LLM，仅输出确定性结果", 88)
        else:
            tick(f"按入口跟链 · {len(hunt_apis)} 个 agent", 76)
            followed = [b.get("name") for b in blocks if b.get("name")]
            if hunt_apis:
                ctx = AnalysisToolbox(
                    artifacts,
                    old_sys=sys_path,
                    new_sys=sys_path,
                    work=work,
                    disasm_budget=AUDIT_SHARED_DISASM,
                    cfg_budget=AUDIT_SHARED_CFG,
                )
                try:
                    llm_pack = _run_path_agents(
                        apis=hunt_apis,
                        ctx=ctx,
                        artifacts=artifacts,
                        title=title,
                        pe=pe,
                        sys_name=sys_path.name,
                        scores=scores,
                        classified=classified,
                        followed_names=[str(n) for n in followed if n],
                        job_id=job_id,
                        work=work,
                        hunt_apis=hunt_apis,
                        obs=obs,
                        surface=surface,
                        progress_cb=progress_cb,
                        resume=resume,
                    )
                    classified["findings"] = _merge_llm_findings(
                        list(classified.get("findings") or []),
                        llm_pack.get("findings") if isinstance(llm_pack.get("findings"), list) else [],
                    )
                    if llm_pack.get("verdict") in {"likely", "suspects", "none", "unknown"}:
                        classified["verdict"] = llm_pack.get("verdict") or classified.get("verdict")
                    obs = observations_from_audit(classified.get("findings") or [], scores)
                    if llm_pack.get("error"):
                        llm_error = str(llm_pack.get("error"))
                except PipelineCancelled:
                    raise
                except LLMError as e:
                    llm_error = str(e)
                    saved = _load_agent_checkpoint(work)
                    llm_pack = _pack_llm(saved, classified, artifacts, error=llm_error)
            else:
                llm_pack = {
                    "mode": "per_api_agents",
                    "agent_count": 0,
                    "agents": [],
                    "verdict": classified.get("verdict") or "none",
                    "summary": "表面图未给出可跟的用户入口",
                    "findings": [],
                }

            agent_rows = list((llm_pack or {}).get("agents") or []) if isinstance(llm_pack, dict) else []
            skip_writer = _is_quota_error(llm_error) or _is_quota_error(
                str((llm_pack or {}).get("error") or "") if isinstance(llm_pack, dict) else ""
            )
            tick("撰写审计短报告", 92)
            if skip_writer:
                report = _offline_report(
                    title, pe, surface, scores, classified, obs, llm_error,
                    agents=agent_rows, hunt_apis=hunt_apis,
                )
            else:
                try:
                    check_cancel(job_id=job_id)
                    llm = make_chat(max_tokens=6000, temperature=0.1)
                    user_w = (
                        f"任务: {title}\n\n"
                        f"## 样本\n{_clip({k: pe.get(k) for k in ('original_filename', 'file_version', 'machine', 'size', 'sha256')}, 1500)}\n\n"
                        f"## 表面图\n{_clip({k: surface.get(k) for k in ('status', 'dispatch', 'immediate', 'fastio', 'major_functions', 'handler_count')}, 5000)}\n\n"
                        f"## 入口 agent（{len(hunt_apis)}）\n{_clip(hunt_apis, 2500)}\n\n"
                        f"## 打分 high/medium\n{_clip([r for r in scores if r.get('risk') in ('high', 'medium')][:20], 3500)}\n\n"
                        f"## 缺陷类\n{_clip(classified, 4000)}\n\n"
                        f"## 各入口跟链\n{_clip(agent_rows or llm_pack or {'skipped': True}, 6000)}\n\n"
                        f"## 已加载模块\n{_clip(artifacts.get('loaded_modules') or [], 2000)}\n\n"
                        "按五节模板写中文。按入口写清跟到了哪一跳、哪一跳因缺模块/符号停下。"
                        "引用工具里出现过的函数名。禁止 exploit。"
                    )
                    resp = llm.invoke([SystemMessage(content=WRITER_SYSTEM), HumanMessage(content=user_w)])
                    content = getattr(resp, "content", "") or ""
                    if isinstance(content, list):
                        content = "".join(str(x) for x in content)
                    report = str(content).strip()
                except Exception as e:
                    llm_error = llm_error or str(e)
                    report = _offline_report(
                        title, pe, surface, scores, classified, obs, llm_error,
                        agents=agent_rows, hunt_apis=hunt_apis,
                    )

    if not report:
        report = _offline_report(
            title,
            pe,
            surface,
            scores,
            classified,
            obs,
            llm_error,
            agents=(llm_pack or {}).get("agents") if isinstance(llm_pack, dict) else None,
            hunt_apis=hunt_apis,
        )

    pack = {
        "kind": "kernel_audit",
        "status": "completed",
        "verdict": classified.get("verdict") or "none",
        "bug_classes": classified.get("bug_classes") or [],
        "findings": classified.get("findings") or [],
        "observations": obs,
        "surface": surface,
        "scores": scores,
        "hunt_apis": hunt_apis,
        "agents": (llm_pack or {}).get("agents") if isinstance(llm_pack, dict) else [],
        "llm": bool(llm_pack),
        "llm_review": llm_pack,
        "loaded_modules": artifacts.get("loaded_modules") or [],
        "pdb": have_pdb,
        "pdb_error": pdb_error,
        "disasm_names": names,
        "report": report,
        "error": llm_error,
    }
    artifacts["kernel_audit"] = pack
    artifacts["observations"] = obs
    artifacts["llm_report"] = report
    artifacts["llm_error"] = llm_error
    artifacts["agent_notes"] = {"root_cause": (llm_pack or {}).get("summary") or report[:1800]}

    (work / "kernel_audit.json").write_text(json.dumps(pack, ensure_ascii=False, indent=2), encoding="utf-8")
    (work / "report.md").write_text(report, encoding="utf-8")
    tick("内核审计完成", 100)
    return artifacts
