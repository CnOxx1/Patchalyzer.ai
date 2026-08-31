"""Deterministic tool nodes + LLM specialist agents (CVE-2026-68820 同套方法)."""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..services.analyzer import (
    byte_diff_code,
    cfg_diff_functions,
    compare_symbols,
    disassemble_functions,
    extract_pe,
    fetch_pdb,
    pdb_ok,
    select_control_names,
    select_hotspot_names,
    size_timeline,
    trace_feature_symbols,
    write_cfg_html,
    write_disasm_files,
    write_verify_pack,
    disasm_relpath,
)
from ..services.pipeline import (
    assess_quality,
    byte_diff_brief,
    extract_conclusions,
    function_slices,
    load_extra_hotspots,
    pe_brief_for_llm,
    plan_hotspots,
    report_progress,
    route_agents,
    unwrap_markdown_fence,
)
from ..services.llm_service import LLMError
from ..services.ioc import build_ioc_pack, ensure_ioc_section
from ..services.patch_review import (
    build_bypass_pack,
    build_residual_pack,
    ensure_bypass_section,
    ensure_residual_section,
    merge_review_pack,
)
from ..services.vuln_hunt import build_hunt_brief, call_index, prefix_pool_names, select_hunt_names
from ..services.threat_intel import (
    attach_analyst_notes,
    ensure_threat_section,
    extract_cve,
    lookup_threat_intel,
)
from .llm import agent_system_prompt, llm_configured, report_structure_prompt
from .state import PatchState, append_trace, make_trace
from ..config import agent_enabled as _agent_on
from ..services.agent_tools import run_specialist, tool_trace_suffix

_INTERESTING = re.compile(
    r"Feature_|SpinLock|ExFreePool|TdiCopy|AfdGlobalData|cmpxchg|"
    r"0xf0|0xec|0x38|0x170|0xf8|KeAcquire|KeRelease|ExEnterCritical|ExReleaseResource",
    re.I,
)


def _pe_brief(pe: dict[str, Any] | None) -> dict[str, Any]:
    pe = pe or {}
    return {
        "original_filename": pe.get("original_filename"),
        "file_version": pe.get("file_version"),
        "machine": pe.get("machine"),
        "size": pe.get("size"),
        "size_of_image": pe.get("size_of_image"),
        "timestamp_utc": pe.get("timestamp_utc"),
        "md5": pe.get("md5"),
        "sha1": pe.get("sha1"),
        "sha256": pe.get("sha256"),
        "debug": [
            {k: d.get(k) for k in ("pdb_filename", "guid", "age", "symbol_url") if d.get(k)}
            for d in (pe.get("debug") or [])[:2]
        ],
    }


def _feature_brief(trace: dict[str, Any] | None) -> list[dict[str, Any]]:
    out = []
    for f in (trace or {}).get("features") or []:
        out.append(
            {
                "feature_id": f.get("feature_id"),
                "featureState_rva": f.get("featureState_rva"),
                "on_disk_dword": f.get("on_disk_dword"),
                "enable_semantics": f.get("enable_semantics"),
                "xrefs": f.get("xrefs") or [],
                "default_note": f.get("default_note"),
                "isEnabled_disasm": (f.get("isEnabled_disasm") or [])[:24],
            }
        )
    return out


def _call_diff_brief(blocks: list | None) -> list[dict[str, Any]]:
    rows = []
    for b in blocks or []:
        o, n = b.get("old") or {}, b.get("new") or {}
        rows.append(
            {
                "name": b.get("name"),
                "old_rva": o.get("rva"),
                "new_rva": n.get("rva"),
                "old_size": o.get("size"),
                "new_size": n.get("size"),
                "delta": (n.get("size") or 0) - (o.get("size") or 0) if o or n else None,
                "calls_added": b.get("calls_added") or [],
                "calls_removed": b.get("calls_removed") or [],
            }
        )
    rows.sort(key=lambda x: abs(x.get("delta") or 0), reverse=True)
    return rows


def extract_vuln_chain(report: str = "", root_notes: str = "") -> dict[str, Any]:
    """Pull §6 漏洞链 (or root-cause draft) into a UI-friendly structure."""
    text = report or ""
    source = "report"
    body = ""
    m = re.search(r"(?ms)^##\s*6\.\s*漏洞链\s*\n(.*?)(?=^##\s*\d+\.|\Z)", text)
    if m:
        body = m.group(1).strip()
    else:
        source = "root_cause"
        m2 = re.search(r"(?ms)^#{2,3}\s*漏洞链[^\n]*\n(.*?)(?=^#{2,3}\s|\Z)", root_notes or "")
        if m2:
            body = m2.group(1).strip()
        elif root_notes and "漏洞链" in root_notes:
            body = (root_notes or "").strip()
            source = "root_cause_full"
    if not body:
        return {"present": False, "source": None, "markdown": "", "steps": [], "summary": ""}

    def _extract_apis(blob: str) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()

        def push(name: str) -> None:
            n = (name or "").strip().strip("`'\"").rstrip("()")
            if not n or len(n) < 2 or len(n) > 64:
                return
            if re.match(r"^(等|无|或|and|or|N/A|NULL|mation|tion|name)$", n, re.I):
                return
            if not re.match(r"^[A-Za-z_][\w]*$", n):
                return
            key = n.lower()
            if key in seen:
                return
            seen.add(key)
            userish = bool(
                re.match(
                    r"^(socket|bind|listen|accept|connect|closesocket|getsockopt|setsockopt|recvfrom|sendto|WSA)",
                    n,
                    re.I,
                )
            )
            found.append(f"{n}()" if userish else n)

        for tick in re.findall(r"`([^`]+)`", blob or ""):
            for part in re.split(r"[,，、;/|]+", tick):
                chunk = part.strip()
                if not chunk:
                    continue
                ident = re.sub(r"\(\)$", "", chunk).strip()
                if re.match(r"^[A-Za-z_][\w.]*$", ident):
                    push(ident)
                    continue
                if re.search(r"(?:^|[\s,，、])(?:或|\bor\b)(?:$|[\s,，、])", chunk, re.I):
                    for piece in re.split(r"\s*(?:或|\bor\b)\s*", chunk, flags=re.I):
                        tok = re.search(r"[A-Za-z_][\w]{1,}", piece)
                        if tok:
                            push(tok.group(0))
                else:
                    tok = re.search(r"[A-Za-z_][\w.]{1,}", chunk)
                    if tok:
                        push(tok.group(0))
        for tok in re.findall(
            r"\b((?:Afd|Nt|Zw|Ke|Ex|Io|Mm|Ob|Rtl|Ps|Se|Hal|WSA)[A-Za-z][\w]*|"
            r"(?:socket|bind|listen|accept|connect|closesocket|getsockopt|setsockopt|"
            r"recvfrom|sendto|DeviceIoControl|CreateFile(?:W|A)?))\b",
            blob or "",
        ):
            push(tok)
        return found[:6]

    def _noise(text: str) -> bool:
        t = re.sub(r"[*`_]", "", text or "").strip()
        return bool(
            re.match(r"^(原语类型|对象所在池|影响路径|不编写|UAF\s*读|UAF\s*写|步骤\s*\d+\s*切断)", t)
            or "仅描述概念" in t
        )

    steps: list[dict[str, Any]] = []
    # Prefer overview table rows: | n | 位置 | 动作 | 涉及函数/API | ...
    for line in body.splitlines():
        s = line.strip()
        if not re.match(r"^\|\s*\d+\s*\|", s) or re.match(r"^\|\s*-+", s):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if not cells or not cells[0].isdigit():
            continue
        location = cells[1] if len(cells) > 1 else ""
        action = cells[2] if len(cells) > 2 else ""
        api_cell = cells[3] if len(cells) > 3 else ""
        obj = cells[4] if len(cells) > 4 else ""
        result = cells[5] if len(cells) > 5 else ""
        evidence = cells[6] if len(cells) > 6 else ""
        apis = _extract_apis(f"{api_cell} {action}")
        title = (apis[0] if apis else (action or location))[:120]
        thread = "A" if re.search(r"线程\s*A", action) else ("B" if re.search(r"线程\s*B", action) else "")
        steps.append(
            {
                "n": int(cells[0]),
                "location": location,
                "action": action,
                "title": title,
                "detail": action or result,
                "result": result,
                "object": obj,
                "evidence": evidence,
                "thread": thread,
                "apis": apis,
                "raw": s,
            }
        )

    if len(steps) < 2:
        steps = []
        for line in body.splitlines():
            s = line.strip()
            mstep = re.match(r"^(?:[-*+]|\d+[.)、]|步骤\s*\d+[.:：]?)\s*(.+)$", s)
            if not mstep:
                continue
            content = mstep.group(1).strip()
            if content.startswith("---") or content.startswith("|") or _noise(content):
                continue
            apis = _extract_apis(content)
            if not apis and len(content) < 8:
                continue
            steps.append(
                {
                    "n": len(steps) + 1,
                    "location": "",
                    "action": content[:160],
                    "title": (apis[0] if apis else content)[:120],
                    "detail": content,
                    "apis": apis,
                    "raw": s,
                }
            )

    # Deduplicate / cap
    seen: set[str] = set()
    uniq: list[dict[str, Any]] = []
    for st in steps:
        key = (st.get("apis") or [None])[0] or st["title"]
        if key in seen:
            continue
        seen.add(key)
        uniq.append(st)
    steps = uniq[:12]
    for i, st in enumerate(steps, 1):
        st["n"] = i

    diagrams = []
    for m in re.finditer(r"```mermaid\s*([\s\S]*?)```", body, re.I):
        code = m.group(1).strip()
        if code:
            diagrams.append(code)

    summary = ""
    for line in body.splitlines():
        t = line.strip()
        if t and not t.startswith("#") and not t.startswith("|") and not t.startswith("```"):
            summary = t[:220]
            break
    return {
        "present": True,
        "source": source,
        "markdown": body,
        "steps": steps,
        "diagrams": diagrams,
        "summary": summary,
    }


def _json_snip(obj: Any, limit: int = 8000) -> str:
    text = json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    if len(text) > limit:
        return text[:limit] + "\n...[truncated]..."
    return text


def _filter_lines(lines: list[str], window: int = 2) -> list[str]:
    keep = set()
    for i, ln in enumerate(lines):
        if _INTERESTING.search(ln):
            for j in range(max(0, i - window), min(len(lines), i + window + 1)):
                keep.add(j)
    if not keep:
        return lines[:80] + (["..."] if len(lines) > 80 else [])
    return [lines[i] for i in sorted(keep)]


def _disasm_for_llm(blocks: list, *, full_if_under: int = 500) -> str:
    lines = []
    for block in blocks or []:
        name = block.get("name")
        lines.append(f"## {name}")
        if block.get("calls_added"):
            lines.append("calls_added: " + ", ".join(block["calls_added"]))
        if block.get("calls_removed"):
            lines.append("calls_removed: " + ", ".join(block["calls_removed"]))
        for side in ("old", "new"):
            d = block.get(side) or {}
            if not d:
                lines.append(f"### {side}: MISSING")
                continue
            asm = d.get("disasm") or []
            lines.append(f"### {side} rva={d.get('rva')} size={d.get('size')} insns={len(asm)}")
            if len(asm) <= full_if_under:
                lines.extend(asm)
            else:
                lines.append("; 全文已写入 disasm/*.asm；下列为同步/池/Feature 相关片段")
                lines.extend(_filter_lines(asm))
        lines.append("")
    return "\n".join(lines) or "(empty)"


def node_pe_extract(state: PatchState) -> dict:
    jobs = [("old_pe", state["old_sys"]), ("new_pe", state["new_sys"])]
    if state.get("mid_sys"):
        jobs.append(("mid_pe", state["mid_sys"]))
    out: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futs = {key: pool.submit(extract_pe, path) for key, path in jobs}
        for key, fut in futs.items():
            out[key] = fut.result()
    traces = [make_trace("PEExtractor", "tool", "已并行提取漏洞版/修复版 PE", 8)]
    if out.get("mid_pe"):
        traces.append(make_trace("PEExtractor", "tool", "已提取第三份（更早/预览）样本 PE，用于时间线", 10))
    out["traces"] = traces
    return out


def _fetch_one(pe: dict, dest: Path) -> tuple[str, str | None]:
    try:
        return str(fetch_pdb(pe, dest)), None
    except Exception as e:
        return "", str(e)


def node_pdb_symbols(state: PatchState) -> dict:
    work = Path(state["work_dir"])
    pdb_dir = work / "pdb"
    report_progress(state, "正在下载 / 命中 PDB 缓存…", 12)
    tasks = [
        ("old_pdb", state.get("old_pe") or {}, pdb_dir / "old.pdb"),
        ("new_pdb", state.get("new_pe") or {}, pdb_dir / "new.pdb"),
    ]
    if state.get("mid_pe") and state.get("mid_sys"):
        tasks.append(("mid_pdb", state.get("mid_pe") or {}, pdb_dir / "mid.pdb"))
    errors: dict[str, str] = {}
    out: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futs = {key: pool.submit(_fetch_one, pe, dest) for key, pe, dest in tasks}
        for key, fut in futs.items():
            path, err = fut.result()
            out[key] = path
            if err:
                errors[key] = err
    old_pdb = Path(out.get("old_pdb") or "")
    new_pdb = Path(out.get("new_pdb") or "")
    sym = compare_symbols(Path(state["old_sys"]), Path(state["new_sys"]), old_pdb, new_pdb)
    if errors:
        sym["pdb_errors"] = errors
    out["symbol_diff"] = sym
    n = len(sym.get("functions_resized") or [])
    q = sym.get("quality") or "pdb"
    msg = f"符号完成（{q}）；.pdata 尺寸变化函数 {n} 个"
    if errors:
        msg = f"PDB 部分失败，已用导出表/.pdata 降级；尺寸变化 {n} 个"
    out["traces"] = append_trace(state, "SymbolDiffer", "tool", msg, 24)
    return out


def node_pick_hotspots(state: PatchState) -> dict:
    work = Path(state.get("work_dir") or "")
    extra = list(state.get("extra_hotspots") or [])
    if work:
        extra = list(dict.fromkeys(extra + load_extra_hotspots(work)))
    plan = plan_hotspots(
        state.get("symbol_diff") or {},
        byte_diff=state.get("byte_diff"),
        feature_trace=state.get("feature_trace"),
        extra_names=extra,
    )
    quality = assess_quality({**state, "hotspot_plan": plan})
    if work:
        (work / "hotspot_plan.json").write_text(
            json.dumps({"plan": plan, "quality": quality}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    uncovered = plan.get("uncovered") or []
    msg = f"热点 {len(plan.get('selected') or [])} 个（Feature 强制 {len(plan.get('feature_forced') or [])}）"
    if uncovered:
        msg += f"；未覆盖 {len(uncovered)}"
    return {
        "hotspot_names": plan.get("selected") or [],
        "hotspot_plan": plan,
        "evidence_quality": quality,
        "extra_hotspots": extra,
        "traces": append_trace(state, "HotspotPicker", "tool", msg, 36),
    }


def node_join_tools(state: PatchState) -> dict:
    return {
        "traces": append_trace(state, "JoinTools", "tool", "工具阶段汇合，开始专家解读", 64),
    }


def node_route_agents(state: PatchState) -> dict:
    plan = route_agents(state)
    routed = plan.get("routed_agents")
    n = len(routed) if isinstance(routed, list) else 11
    skipped = plan.get("skip_reasons") if isinstance(plan.get("skip_reasons"), dict) else {}
    mode = plan.get("routing_mode") or "auto"
    if mode == "manual":
        msg = "手动编制：按勾选运行专家"
    else:
        msg = f"自动编制：运行 {n} 个专家"
        if skipped:
            msg += f"，跳过 {len(skipped)} 个"
    work = Path(state.get("work_dir") or "")
    if work:
        (work / "routing.json").write_text(
            json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    return {
        "routing_mode": mode,
        "routed_agents": routed,
        "skip_reasons": skipped,
        "prompt_depth": plan.get("prompt_depth") or {},
        "routing_signals": plan.get("routing_signals") or {},
        "traces": append_trace(state, "AgentRouter", "tool", msg, 65),
    }


def node_timeline(state: PatchState) -> dict:
    names = list(state.get("hotspot_names") or [])
    if not names:
        names = select_hotspot_names(
            state.get("symbol_diff") or {},
            feature_trace=state.get("feature_trace"),
            byte_diff=state.get("byte_diff"),
        )
    samples = [
        (state.get("old_label") or "old", Path(state["old_sys"]), Path(state.get("old_pdb") or "")),
        (state.get("new_label") or "new", Path(state["new_sys"]), Path(state.get("new_pdb") or "")),
    ]
    if state.get("mid_sys"):
        samples.insert(
            0,
            (state.get("mid_label") or "mid", Path(state["mid_sys"]), Path(state.get("mid_pdb") or "")),
        )
    tl = size_timeline(samples, names)
    Path(state["work_dir"]).joinpath("size_timeline.json").write_text(
        json.dumps(tl, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return {
        "size_timeline": tl,
        "traces": append_trace(
            state, "SizeTimeline", "tool", f"函数尺寸时间线 {len(samples)} 个构建 × {len(names)} 函数", 44
        ),
    }


def node_byte_diff(state: PatchState) -> dict:
    diff = byte_diff_code(
        Path(state["old_sys"]),
        Path(state["new_sys"]),
        Path(state.get("old_pdb") or ""),
        Path(state.get("new_pdb") or ""),
    )
    Path(state["work_dir"]).joinpath("byte_diff.json").write_text(
        json.dumps(diff, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return {
        "byte_diff": diff,
        "traces": append_trace(
            state,
            "ByteDiffer",
            "tool",
            f"代码节变化 {diff['total_bytes']} 字节 / {diff['functions_with_byte_changes']} 个函数（含重定位噪声）",
            48,
        ),
    }


def node_disasm(state: PatchState) -> dict:
    sym = state.get("symbol_diff") or {}
    changed_names = list(state.get("hotspot_names") or [])
    if not changed_names:
        changed_names = select_hotspot_names(
            sym,
            byte_diff=state.get("byte_diff"),
            feature_trace=state.get("feature_trace"),
            extra_hints=state.get("extra_hotspots") or [],
            max_hotspots=16,
        )
    control_names = select_control_names(sym, changed_names)
    old_sys, new_sys = Path(state["old_sys"]), Path(state["new_sys"])
    old_pdb, new_pdb = Path(state.get("old_pdb") or ""), Path(state.get("new_pdb") or "")
    changed = disassemble_functions(old_sys, new_sys, old_pdb, new_pdb, changed_names, max_lines=None)
    control = disassemble_functions(old_sys, new_sys, old_pdb, new_pdb, control_names, max_lines=None)
    work = Path(state["work_dir"])
    write_disasm_files(work, changed)
    write_disasm_files(work, control)

    def lite(blocks):
        out = []
        for b in blocks:
            item = {
                "name": b["name"],
                "calls_added": b.get("calls_added") or [],
                "calls_removed": b.get("calls_removed") or [],
            }
            for side in ("old", "new"):
                d = b.get(side)
                if not d:
                    item[side] = None
                    continue
                item[side] = {
                    "rva": d.get("rva"),
                    "size": d.get("size"),
                    "calls": d.get("calls") or [],
                    "disasm_lines": len(d.get("disasm") or []),
                    "truncated": False,
                    "on_disk": disasm_relpath(side, b["name"]),
                }
            out.append(item)
        return out

    call_diff = [
        {
            "name": b["name"],
            "old_rva": (b.get("old") or {}).get("rva"),
            "new_rva": (b.get("new") or {}).get("rva"),
            "old_size": (b.get("old") or {}).get("size"),
            "new_size": (b.get("new") or {}).get("size"),
            "calls_added": b.get("calls_added") or [],
            "calls_removed": b.get("calls_removed") or [],
        }
        for b in changed
    ]
    (work / "bind_func_diff.json").write_text(json.dumps(call_diff, indent=2, ensure_ascii=False), encoding="utf-8")
    (work / "call_index.json").write_text(
        json.dumps(call_index(changed + control), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (work / "symbol_diff.json").write_text(
        json.dumps(state.get("symbol_diff") or {}, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (work / "hotspots.json").write_text(
        json.dumps({"hotspots": changed_names, "controls": control_names}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return {
        "disassembly": changed,
        "control_disasm": lite(control),
        "hotspot_names": changed_names,
        "control_names": control_names,
        "traces": append_trace(
            state,
            "DisasmWorker",
            "tool",
            f"全文反汇编：热点 {len(changed)} + 对照 {len(control)}，已写 disasm/*.asm",
            60,
        ),
    }


def _cfg_names(state: PatchState) -> list[str]:
    plan = state.get("hotspot_plan") if isinstance(state.get("hotspot_plan"), dict) else {}
    names = list(plan.get("cfg_names") or state.get("hotspot_names") or [])
    if names:
        return names[:12]
    return select_hotspot_names(
        state.get("symbol_diff") or {},
        byte_diff=state.get("byte_diff"),
        feature_trace=state.get("feature_trace"),
        extra_hints=state.get("extra_hotspots") or [],
        max_hotspots=12,
    )


def node_cfg(state: PatchState) -> dict:
    names = _cfg_names(state)
    cfg = cfg_diff_functions(
        Path(state["old_sys"]),
        Path(state["new_sys"]),
        Path(state.get("old_pdb") or ""),
        Path(state.get("new_pdb") or ""),
        names,
    )
    work = Path(state["work_dir"])
    (work / "cfg_diff.json").write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    write_cfg_html(work, cfg, state.get("old_label") or "old", state.get("new_label") or "new")
    summary = {
        "note": cfg.get("note"),
        "html": "cfg_diff.html",
        "functions": [{k: v for k, v in f.items() if k not in ("old_blocks", "new_blocks")} for f in cfg["functions"]],
    }
    return {
        "cfg_diff": summary,
        "traces": append_trace(state, "CfgDiffer", "tool", f"基本块 diff {len(names)} 个函数，已写 cfg_diff.html", 61),
    }


def node_feature(state: PatchState) -> dict:
    try:
        trace = trace_feature_symbols(
            Path(state["new_sys"]),
            Path(state.get("new_pdb") or ""),
            state.get("symbol_diff") or {},
        )
    except Exception as e:
        trace = {"count": 0, "features": [], "error": str(e)}
    Path(state["work_dir"]).joinpath("feature_trace.json").write_text(
        json.dumps(trace, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return {
        "feature_trace": trace,
        "traces": append_trace(
            state,
            "FeatureTracer",
            "tool",
            f"跟踪 {trace.get('count', 0)} 组新增 Feature_* 与 featureState xref",
            28,
        ),
    }


def node_verify_pack(state: PatchState) -> dict:
    pack = write_verify_pack(
        Path(state["work_dir"]),
        state.get("title") or "patch-job",
        old_pe=state.get("old_pe") if isinstance(state.get("old_pe"), dict) else {},
        new_pe=state.get("new_pe") if isinstance(state.get("new_pe"), dict) else {},
        feature_trace=state.get("feature_trace") if isinstance(state.get("feature_trace"), dict) else {},
        disassembly=state.get("disassembly") if isinstance(state.get("disassembly"), list) else [],
        hotspot_names=state.get("hotspot_names") if isinstance(state.get("hotspot_names"), list) else [],
    )
    Path(state["work_dir"]).joinpath("verify_pack.json").write_text(
        json.dumps(pack, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    driver = pack.get("driver") or "driver.sys"
    return {
        "verify_pack": pack,
        "traces": append_trace(
            state,
            "VerifyPack",
            "tool",
            f"已生成 {driver} 的 VM Verifier / WinDbg 验证包（服务器不执行）",
            63,
        ),
    }


def _keep_notes(text: str | None) -> bool:
    t = (text or "").strip()
    return bool(t) and not t.startswith("（跳过") and not t.startswith("（失败")


def _agent_enabled(state: PatchState, name: str) -> bool:
    return _agent_on(
        state.get("enabled_agents"),
        name,
        run_llm=bool(state.get("run_llm")),
        routed=state.get("routed_agents"),
    )


def _skip_reason(state: PatchState, name: str) -> str:
    reasons = state.get("skip_reasons") if isinstance(state.get("skip_reasons"), dict) else {}
    return str(reasons.get(name) or "未选择该 Agent")


def _tool_traces(state: PatchState, name: str, log: list[dict], pct: int) -> list[dict]:
    traces: list[dict] = []
    for item in log or []:
        tool = item.get("tool")
        if not tool:
            continue
        args = item.get("args") or {}
        hint = args.get("name") or args.get("query") or args.get("key") or args.get("side") or ""
        traces.extend(
            append_trace(state, name, "tool", f"{tool}({hint})" if hint else str(tool), pct)
        )
    return traces


def _rewrite_last_agent(result: dict, message: str) -> None:
    traces = list(result.get("traces") or [])
    for i in range(len(traces) - 1, -1, -1):
        if traces[i].get("role") in {"agent", "error"}:
            traces[i] = {**traces[i], "message": message}
            result["traces"] = traces
            return
    if traces:
        traces[-1] = {**traces[-1], "message": message}
        result["traces"] = traces


def _safe_agent(state: PatchState, name: str, notes_key: str, system: str, user: str, pct_ok: int, pct_skip: int) -> dict:
    """Run one LLM specialist; on failure keep pipeline alive with llm_error."""
    if not _agent_enabled(state, name):
        existing = state.get(notes_key) or ""
        if _keep_notes(existing if isinstance(existing, str) else ""):
            return {
                "traces": append_trace(state, name, "agent", f"沿用已有 {name}", pct_skip),
            }
        why = _skip_reason(state, name)
        return {
            notes_key: f"（跳过：{why}）",
            "traces": append_trace(state, name, "agent", f"跳过 {name}：{why}", pct_skip),
        }
    if not llm_configured():
        return {
            notes_key: "（跳过：未启用 LLM 或未配置 API）",
            "traces": append_trace(state, name, "agent", f"跳过 {name}", pct_skip),
        }
    try:
        notes, log = run_specialist(name, system, user, state)
        traces = _tool_traces(state, name, log, pct_ok)
        traces.extend(
            append_trace(state, name, "agent", f"完成 {name}{tool_trace_suffix(log)}", pct_ok)
        )
        return {
            notes_key: notes,
            "traces": traces,
        }
    except LLMError as e:
        err = str(e)
        return {
            notes_key: f"（失败：{err}）",
            "llm_error": err,
            "traces": append_trace(state, name, "error", f"{name} 失败: {err}", pct_ok),
        }


def node_pe_analyst(state: PatchState) -> dict:
    user = (
        f"任务: {state.get('title')}\n"
        f"标签: {state.get('old_label')} vs {state.get('new_label')}"
        + (f" ；第三样本 {state.get('mid_label')}" if state.get("mid_pe") else "")
        + f"\nOld PE:\n{_json_snip(pe_brief_for_llm(state.get('old_pe')), 2500)}\n\nNew PE:\n{_json_snip(pe_brief_for_llm(state.get('new_pe')), 2500)}\n"
    )
    if state.get("mid_pe"):
        user += f"\nMid PE:\n{_json_snip(pe_brief_for_llm(state.get('mid_pe')), 1800)}\n"
    user += (
        "判断是否同架构、导入表是否实质变化、是否像同分支小版本对比还是跨大版本。"
        "跨大版本不能把差异全部归因于单一 CVE。"
    )
    return _safe_agent(
        state,
        "PEAnalyst",
        "pe_notes",
        agent_system_prompt("PEAnalyst"),
        user,
        66,
        64,
    )


def node_symbol_analyst(state: PatchState) -> dict:
    sym = state.get("symbol_diff") or {}
    user = (
        f"任务: {state.get('title')}\n"
        f"计数 old={sym.get('old')} new={sym.get('new')}\n"
        f"时间线:\n{_json_snip(state.get('size_timeline'), 4000)}\n"
        f"字节差（仅噪声摘要，禁止当主证据）:\n{_json_snip(byte_diff_brief(state.get('byte_diff')), 1800)}\n"
        f"Feature 新增: {_json_snip(sym.get('feature_symbols_added') or [], 1500)}\n"
        f"尺寸变化函数:\n{_json_snip((sym.get('functions_resized') or [])[:20], 5000)}\n"
        f"可能的改名配对: {_json_snip(sym.get('renames') or [], 1500)}\n"
        f"尺寸变化函数: {_json_snip(sym.get('functions_resized') or [], 8000)}\n"
        "补丁热点以 .pdata 尺寸变化为准；时间线若更早样本与漏洞版尺寸相同、仅修复版变化，则补丁落在最后一跳。"
    )
    return _safe_agent(
        state,
        "SymbolAnalyst",
        "symbol_notes",
        agent_system_prompt("SymbolAnalyst"),
        user,
        73,
        70,
    )


def node_disasm_analyst(state: PatchState) -> dict:
    sym = state.get("symbol_diff") or {}
    user = (
        f"任务: {state.get('title')}\n"
        f"热点函数: {(state.get('hotspot_names') or [])[:16]}\n"
        f"未覆盖热点: {((state.get('hotspot_plan') or {}).get('uncovered') or [])[:12]}\n"
        f"按函数切片（尺寸+调用差+关键指令）:\n{function_slices(state)}\n"
        "逐函数对比：自旋锁、资源锁、Feature、ExFreePoolWithTag、TdiCopyMdlToBuffer、"
        "缓冲指针字段。不要编造未出现的 RVA。"
    )
    return _safe_agent(
        state,
        "DisasmAnalyst",
        "disasm_notes",
        agent_system_prompt("DisasmAnalyst"),
        user,
        82,
        78,
    )


def node_feature_analyst(state: PatchState) -> dict:
    lite = []
    for f in (state.get("feature_trace") or {}).get("features") or []:
        lite.append(
            {
                "feature_id": f.get("feature_id"),
                "featureState_rva": f.get("featureState_rva"),
                "on_disk_dword": f.get("on_disk_dword"),
                "enable_semantics": f.get("enable_semantics"),
                "xrefs": f.get("xrefs") or [],
                "isEnabled_disasm": (f.get("isEnabled_disasm") or [])[:40],
                "default_note": f.get("default_note"),
            }
        )
    cfg_sum = (state.get("cfg_diff") or {}).get("functions") or []
    user = (
        f"任务: {state.get('title')}\n"
        f"CFG 摘要:\n{_json_snip(cfg_sum, 4000)}\n"
        f"Feature 跟踪:\n{_json_snip(lite, 8000)}\n"
        "解释 WIL 缓存位 0x10 与启用位 0x1；说明映像内 0 不等于关闭。"
        "不要编造未出现的 xref RVA。"
    )
    return _safe_agent(
        state,
        "FeatureAnalyst",
        "feature_notes",
        agent_system_prompt("FeatureAnalyst"),
        user,
        85,
        84,
    )


def node_control_analyst(state: PatchState) -> dict:
    resized = {f["name"] for f in ((state.get("symbol_diff") or {}).get("functions_resized") or [])}
    control_names = state.get("control_names") or []
    hits = [n for n in control_names if n in resized]
    summary = []
    for b in state.get("control_disasm") or []:
        o, n = b.get("old") or {}, b.get("new") or {}
        summary.append(
            {
                "name": b["name"],
                "old_size": o.get("size"),
                "new_size": n.get("size"),
                "old_rva": o.get("rva"),
                "new_rva": n.get("rva"),
                "size_changed": o.get("size") != n.get("size"),
                "calls_added": b.get("calls_added") or [],
                "calls_removed": b.get("calls_removed") or [],
            }
        )
    user = (
        f"任务: {state.get('title')}\n"
        f"对照函数列表出现在尺寸变化中: {hits or '无'}\n"
        f"对照函数尺寸/调用:\n{_json_snip(summary, 8000)}\n"
        "按既有方法：尺寸不变则逻辑等价（仅重定位），排除为本次 CVE 修复点。"
        "若名称含 Notify/Cleanup/Lock，重点判断是否被改。"
    )
    return _safe_agent(
        state,
        "ControlPathAnalyst",
        "control_notes",
        agent_system_prompt("ControlPathAnalyst"),
        user,
        88,
        86,
    )


def node_root_cause(state: PatchState) -> dict:
    user = (
        f"任务: {state.get('title')}\n"
        f"PE:\n{state.get('pe_notes')}\n\n符号/时间线:\n{state.get('symbol_notes')}\n\n"
        f"反汇编:\n{state.get('disasm_notes')}\n\nFeature:\n{state.get('feature_notes')}\n\n对照:\n{state.get('control_notes')}\n"
        "综合漏洞类型、读/写路径 vs 释放路径、锁域、Feature 修复。冲突以反汇编为准。\n\n"
        "必须先写两行：\n"
        "根因一句话：…\n"
        "补丁切断点：…（哪一跳构建、哪个函数、切断了链上哪一步）\n\n"
        "输出末尾必须包含 Markdown 小节「### 漏洞链草稿」，"
        "用有序列表写出 5–8 步完整链路（触发→分配→并发/异步→释放→无保护使用→原语→影响），"
        "每步写函数名；该草稿将直接进入最终报告 §6。"
    )
    return _safe_agent(
        state,
        "RootCauseAnalyst",
        "root_cause",
        agent_system_prompt("RootCauseAnalyst"),
        user,
        94,
        92,
    )


def node_detection_analyst(state: PatchState) -> dict:
    draft_chain = extract_vuln_chain("", state.get("root_cause") or "")
    pack = build_ioc_pack(
        title=state.get("title") or "",
        old_pe=state.get("old_pe"),
        new_pe=state.get("new_pe"),
        mid_pe=state.get("mid_pe"),
        symbol_diff=state.get("symbol_diff"),
        feature_trace=state.get("feature_trace"),
        disassembly=state.get("disassembly"),
        vuln_chain=draft_chain,
        patch_resolve=state.get("patch_resolve") if isinstance(state.get("patch_resolve"), dict) else {},
        labels={
            "old": state.get("old_label"),
            "new": state.get("new_label"),
            "mid": state.get("mid_label"),
        },
    )
    user = (
        f"任务: {state.get('title')}\n"
        f"样本标签: {state.get('old_label')} → {state.get('new_label')}\n\n"
        f"## IOC 包（哈希与版本必须原样使用）\n{_json_snip(pack, 9000)}\n\n"
        f"## 漏洞链草稿\n{state.get('root_cause') or '（无）'}\n\n"
        f"## Feature 摘要\n{_json_snip(_feature_brief(state.get('feature_trace')), 4000)}\n\n"
        "为安全运营写检测方法：资产清点、行为 hunt、补丁核验、误报。"
        "禁止编造哈希，禁止 exploit / PoC。"
    )
    result = _safe_agent(
        state,
        "DetectionAnalyst",
        "detection_notes",
        agent_system_prompt("DetectionAnalyst"),
        user,
        96,
        95,
    )
    result["ioc_pack"] = {**pack, "detection_notes": result.get("detection_notes") or ""}
    notes = (result.get("detection_notes") or "").strip()
    if notes.startswith("（跳过") or notes.startswith("（失败"):
        result["ioc_pack"]["detection_notes"] = ""
        result["ioc_pack"]["has_detection"] = False
    else:
        result["ioc_pack"]["has_detection"] = bool(notes)
    return result


def node_threat_intel(state: PatchState) -> dict:
    existing = state.get("threat_intel") if isinstance(state.get("threat_intel"), dict) else {}
    if not _agent_enabled(state, "ThreatIntelAnalyst"):
        why = _skip_reason(state, "ThreatIntelAnalyst")
        pack = existing if existing.get("fetched_at") or existing.get("search_hits") else {
            "status": "skipped",
            "search_hits": [],
            "fetched_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "summary": why,
        }
        skip = _safe_agent(state, "ThreatIntelAnalyst", "threat_notes", "", "", 97, 96)
        skip["threat_intel"] = pack
        return skip
    cve = extract_cve(
        state.get("title") or "",
        state.get("patch_resolve") if isinstance(state.get("patch_resolve"), dict) else {},
        state.get("ioc_pack") if isinstance(state.get("ioc_pack"), dict) else {},
    )
    pe = state.get("old_pe") if isinstance(state.get("old_pe"), dict) else {}
    pr = state.get("patch_resolve") if isinstance(state.get("patch_resolve"), dict) else {}
    component = str(pr.get("old_file") or pe.get("original_filename") or "")
    pack = lookup_threat_intel(cve, title=state.get("title") or "", component=component)
    hits = pack.get("search_hits") or []
    user = (
        f"任务: {state.get('title')}\n"
        f"搜索词: {cve} APT\n\n"
        f"## 搜索前两页（有结果就根据这里写；没有或明显无关则改用下面的目录）\n"
        f"{_json_snip(hits, 10000) if hits else '（无搜索结果）'}\n\n"
        f"## 目录对照（搜索无结果时使用）：CISA KEV / NVD / EPSS\n"
        f"{_json_snip({k: pack.get(k) for k in ('in_kev', 'kev', 'nvd', 'epss')}, 4000)}\n\n"
        "根据搜索结果总结是否有 APT/组织在利用该 CVE。"
        "组织名必须出现在搜索结果里才可写。不要写 exploit 步骤。"
        "搜索为空或无关时，改写目录对照结论。"
    )
    result = _safe_agent(
        state,
        "ThreatIntelAnalyst",
        "threat_notes",
        agent_system_prompt("ThreatIntelAnalyst"),
        user,
        97,
        96,
    )
    pack = attach_analyst_notes(pack, result.get("threat_notes") or "")
    result["threat_intel"] = pack
    msg = pack.get("summary") or "已完成公开检索"
    _rewrite_last_agent(result, f"ThreatIntelAnalyst · 检索 {len(hits)} 条 · {msg}")
    return result


def _control_brief(state: PatchState) -> list[dict[str, Any]]:
    rows = []
    for b in state.get("control_disasm") or []:
        o, n = b.get("old") or {}, b.get("new") or {}
        rows.append(
            {
                "name": b.get("name"),
                "old_size": o.get("size"),
                "new_size": n.get("size"),
                "old_rva": o.get("rva"),
                "new_rva": n.get("rva"),
                "size_changed": o.get("size") != n.get("size"),
                "calls_added": b.get("calls_added") or [],
                "calls_removed": b.get("calls_removed") or [],
            }
        )
    return rows


def _unchanged_siblings(state: PatchState, limit: int = 24) -> list[str]:
    hot = [n for n in (state.get("hotspot_names") or []) if n]
    prefixes = set()
    for name in hot:
        m = re.match(r"^([A-Za-z]+)", name)
        if m:
            prefixes.add(m.group(1))
    resized = {f.get("name") for f in ((state.get("symbol_diff") or {}).get("functions_resized") or []) if f.get("name")}
    hot_set = set(hot)
    out: list[str] = []
    for name in (state.get("symbol_diff") or {}).get("code_symbols") or []:
        if not name or name in resized or name in hot_set:
            continue
        if prefixes and not any(str(name).startswith(p) for p in prefixes):
            continue
        out.append(name)
        if len(out) >= limit:
            break
    extra = [n for n in (state.get("control_names") or []) if n and n not in out and n not in resized]
    return (out + extra)[:limit]


_HUNT_AGENTS = (
    "BypassAnalyst",
    "ResidualVulnAnalyst",
    "AliasSiteAnalyst",
    "FeatureOffAnalyst",
)


def _hunt_cfg_diff(state: PatchState) -> dict[str, Any]:
    """State cfg_diff strips basic blocks; HuntPrep needs the on-disk full JSON."""
    work = Path(state.get("work_dir") or "")
    path = work / "cfg_diff.json"
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("functions"):
                return data
        except Exception:
            pass
    cfg = state.get("cfg_diff")
    return cfg if isinstance(cfg, dict) else {}


def _hunt_size_timeline(state: PatchState, extra_names: list[str]) -> dict[str, Any]:
    names = list(dict.fromkeys([n for n in extra_names if n]))[:40]
    fallback = state.get("size_timeline") if isinstance(state.get("size_timeline"), dict) else {}
    if not names or not state.get("old_sys") or not state.get("new_sys"):
        return fallback
    samples = [
        (state.get("old_label") or "old", Path(state["old_sys"]), Path(state.get("old_pdb") or "")),
        (state.get("new_label") or "new", Path(state["new_sys"]), Path(state.get("new_pdb") or "")),
    ]
    if state.get("mid_sys"):
        samples.insert(
            0,
            (state.get("mid_label") or "mid", Path(state["mid_sys"]), Path(state.get("mid_pdb") or "")),
        )
    try:
        return size_timeline(samples, names)
    except Exception:
        return fallback


def _build_hunt_brief(state: PatchState, extra_blocks: list[dict[str, Any]], hunt_names: list[str]) -> dict[str, Any]:
    pool = prefix_pool_names(state.get("symbol_diff") or {}, list(state.get("hotspot_names") or []))
    return build_hunt_brief(
        symbol_diff=state.get("symbol_diff") or {},
        hotspot_names=list(state.get("hotspot_names") or []),
        control_names=list(state.get("control_names") or []),
        disassembly=list(state.get("disassembly") or []),
        hunt_blocks=extra_blocks,
        feature_trace=state.get("feature_trace") if isinstance(state.get("feature_trace"), dict) else {},
        cfg_diff=_hunt_cfg_diff(state),
        size_timeline=_hunt_size_timeline(state, list(hunt_names) + pool),
    )


def _disasm_named(state: PatchState, names: list[str], known: set[str]) -> list[dict[str, Any]]:
    extra = [n for n in names if n and n not in known]
    if not extra or not state.get("old_sys") or not state.get("new_sys"):
        return []
    try:
        blocks = disassemble_functions(
            Path(state["old_sys"]),
            Path(state["new_sys"]),
            Path(state.get("old_pdb") or ""),
            Path(state.get("new_pdb") or ""),
            extra,
            max_lines=None,
        )
        work = Path(state.get("work_dir") or "")
        if work and blocks:
            write_disasm_files(work, blocks)
        return blocks
    except Exception as e:
        report_progress(state, f"狩猎反汇编降级：{e}", 90)
        return []


def node_hunt_prep(state: PatchState) -> dict:
    """Independent hunt pipeline: extra disasm of unpatched siblings for new-vuln discovery."""
    need = any(_agent_enabled(state, n) for n in _HUNT_AGENTS)
    if not need:
        return {
            "hunt_brief": {},
            "hunt_names": [],
            "traces": append_trace(state, "HuntPrep", "tool", "跳过狩猎准备（未启用狩猎专家）", 90),
        }
    names = select_hunt_names(
        state.get("symbol_diff") or {},
        list(state.get("hotspot_names") or []),
        list(state.get("control_names") or []),
        limit=18,
    )
    known = {b.get("name") for b in (state.get("disassembly") or []) if b.get("name")}
    extra_blocks = _disasm_named(state, names, known)
    known |= {b.get("name") for b in extra_blocks if b.get("name")}
    brief = _build_hunt_brief(state, extra_blocks, names)
    more = [n for n in (brief.get("expand_names") or []) if n not in known][:8]
    if more:
        report_progress(state, f"狩猎第二轮：补反汇编 {len(more)} 个调用点/入口", 90)
        round2 = _disasm_named(state, more, known)
        extra_blocks = extra_blocks + round2
        names = list(dict.fromkeys(list(names) + more))
        brief = _build_hunt_brief(state, extra_blocks, names)
    work = Path(state.get("work_dir") or "")
    if work:
        (work / "hunt_brief.json").write_text(
            json.dumps(brief, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    high = brief.get("high_priority") or []
    alias_n = len(brief.get("alias_sites") or [])
    clone_n = len(brief.get("clone_sites") or [])
    gap_n = len(brief.get("cfg_gaps") or [])
    win_n = len(brief.get("skip_windows") or [])
    extras = []
    if high:
        extras.append(f"高优先级 {len(high)}")
    if alias_n:
        extras.append(f"未改调用点 {alias_n}")
    if clone_n:
        extras.append(f"调用克隆 {clone_n}")
    if gap_n:
        extras.append(f"CFG缺口 {gap_n}")
    if win_n:
        extras.append(f"跳过窗口 {win_n}")
    report_progress(
        state,
        f"狩猎准备：{len(brief.get('candidates') or [])} 个候选"
        + (("，" + "，".join(extras)) if extras else ""),
        90,
    )
    return {
        "hunt_names": names,
        "hunt_brief": brief,
        "traces": append_trace(
            state,
            "HuntPrep",
            "tool",
            f"候选 {len(brief.get('candidates') or [])}，补反汇编 {len(extra_blocks)}"
            + (("，" + "，".join(extras)) if extras else ""),
            90,
        ),
    }


def node_bypass_analyst(state: PatchState) -> dict:
    hunt = state.get("hunt_brief") or {}
    user = (
        f"任务: {state.get('title')}\n"
        f"样本: {state.get('old_label')} → {state.get('new_label')}\n\n"
        f"## 根因与漏洞链草稿\n{state.get('root_cause') or '（无）'}\n\n"
        f"## 热点调用差\n{_json_snip(_call_diff_brief(state.get('disassembly')), 6000)}\n\n"
        f"## Feature 门控\n{_json_snip(_feature_brief(state.get('feature_trace')), 4000)}\n\n"
        f"## 狩猎简报（未改兄弟函数 vs 补丁模式）\n{_json_snip(hunt, 7000)}\n\n"
        f"## CFG 检查覆盖缺口 cfg_gaps（已修补函数内热点块仍缺新检查）\n{_json_snip(hunt.get('cfg_gaps') or [], 5000)}\n\n"
        f"## 检查-使用窗口 skip_windows\n{_json_snip(hunt.get('skip_windows') or [], 4000)}\n\n"
        f"## 对照路径\n{_json_snip(_control_brief(state), 4000)}\n\n"
        "这是独立的补丁完整性流水线。请深挖：同一漏洞是否还能从 Feature 关闭路径、"
        "未改调用点、错误返回、锁与使用之间的窗口到达。"
        "优先看 cfg_gaps 与 skip_windows：它们只是启发式扫描，不是残留证明；没有对应汇编行不得 residual。"
        "high_priority 与 missing_lock_vs_patch 是启发式，必须对照汇编确认。"
        "禁止按函数名推断职责或调用关系。没有汇编/调用差的函数 status 只能 unknown，禁止 residual。"
        "目标是发现不完整补丁，不是写利用。"
        "先 JSON 再中文。禁止 exploit / PoC / 逐步绕过步骤。"
    )
    result = _safe_agent(
        state,
        "BypassAnalyst",
        "bypass_notes",
        agent_system_prompt("BypassAnalyst"),
        user,
        93,
        92,
    )
    pack = build_bypass_pack(result.get("bypass_notes") or "")
    result["bypass_pack"] = pack
    _rewrite_last_agent(
        result,
        f"BypassAnalyst · {pack.get('verdict') or 'unknown'} · {len(pack.get('findings') or [])} 条",
    )
    return result


def node_residual_analyst(state: PatchState) -> dict:
    hunt = state.get("hunt_brief") or {}
    user = (
        f"任务: {state.get('title')}\n"
        f"已修补热点: {_json_snip(state.get('hotspot_names') or [], 2000)}\n"
        f"尺寸已变函数: {_json_snip([f.get('name') for f in ((state.get('symbol_diff') or {}).get('functions_resized') or [])][:20], 2000)}\n\n"
        f"## 根因（要匹配的缺陷模式）\n{state.get('root_cause') or '（无）'}\n\n"
        f"## 狩猎简报（未改函数汇编摘要）\n{_json_snip(hunt, 8000)}\n\n"
        f"## 调用画像克隆 clone_sites（调用集仍像漏洞版热点）\n{_json_snip(hunt.get('clone_sites') or [], 5000)}\n\n"
        f"## 对照函数尺寸/调用\n{_json_snip(_control_brief(state), 4000)}\n\n"
        "这是独立的残留漏洞发现流水线。对每个 candidates[]：对照 patched_pattern，"
        "判断是否仍缺锁/Feature/释放防护/边界检查。high_priority 与 clone_sites 优先写。"
        "why 含 call_clone / timeline_stable 的候选要单独表态。"
        "目标是发现同类新漏洞嫌疑，不是利用方法。"
        "没有可靠证据就写 none。先 JSON 再中文。禁止 exploit / PoC。"
    )
    result = _safe_agent(
        state,
        "ResidualVulnAnalyst",
        "residual_notes",
        agent_system_prompt("ResidualVulnAnalyst"),
        user,
        93,
        92,
    )
    pack = build_residual_pack(result.get("residual_notes") or "")
    result["residual_pack"] = pack
    _rewrite_last_agent(
        result,
        f"ResidualVulnAnalyst · {pack.get('verdict') or 'unknown'} · {len(pack.get('findings') or [])} 条",
    )
    return result


def node_alias_site_analyst(state: PatchState) -> dict:
    hunt = state.get("hunt_brief") or {}
    user = (
        f"任务: {state.get('title')}\n"
        f"已修补热点: {_json_snip(state.get('hotspot_names') or [], 2000)}\n\n"
        f"## 根因\n{state.get('root_cause') or '（无）'}\n\n"
        f"## 热点调用差\n{_json_snip(_call_diff_brief(state.get('disassembly')), 5000)}\n\n"
        f"## 未改调用点 alias_sites\n{_json_snip(hunt.get('alias_sites') or [], 6000)}\n\n"
        f"## 调用画像克隆 clone_sites\n{_json_snip(hunt.get('clone_sites') or [], 4000)}\n\n"
        f"## 热点的调用者 callers_of_hotspots\n{_json_snip(hunt.get('callers_of_hotspots') or {}, 4000)}\n\n"
        f"## 补丁模式 patched_pattern\n{_json_snip(hunt.get('patched_pattern') or {}, 3000)}\n\n"
        f"## 全部狩猎候选\n{_json_snip(hunt.get('candidates') or [], 8000)}\n\n"
        "这是独立的调用点覆盖流水线。核心问题：补丁是否只打在部分 CALL 点。"
        "对每个 alias_sites / unpatched_caller / calls_new_helper / call_clone："
        "对照 patched_pattern 判断该调用者是否仍缺锁/Feature/Probe。"
        "有汇编或调用表证据写 suspect/likely；只有名字写 similar；对不上写 cleared。"
        "目标是发现「同一检查没打全」的残留点，不是写利用。"
        "先 JSON：verdict(none|suspects|likely|unknown)、confidence、summary、"
        "findings[{function,pattern,severity,status(suspect|similar|cleared),evidence}]。"
        "再中文（只用 ###）。禁止 exploit / PoC。禁止编造未提供的函数名。"
    )
    result = _safe_agent(
        state,
        "AliasSiteAnalyst",
        "alias_notes",
        agent_system_prompt("AliasSiteAnalyst"),
        user,
        93,
        92,
    )
    pack = build_residual_pack(result.get("alias_notes") or "")
    result["alias_pack"] = pack
    _rewrite_last_agent(
        result,
        f"AliasSiteAnalyst · {pack.get('verdict') or 'unknown'} · {len(pack.get('findings') or [])} 条",
    )
    return result


def node_feature_off_analyst(state: PatchState) -> dict:
    hunt = state.get("hunt_brief") or {}
    user = (
        f"任务: {state.get('title')}\n"
        f"样本: {state.get('old_label')} → {state.get('new_label')}\n\n"
        f"## 根因\n{state.get('root_cause') or '（无）'}\n\n"
        f"## Feature 门控\n{_json_snip(_feature_brief(state.get('feature_trace')), 8000)}\n\n"
        f"## Feature 关闭候选 feature_off_sites\n{_json_snip(hunt.get('feature_off_sites') or [], 5000)}\n\n"
        f"## 热点调用差\n{_json_snip(_call_diff_brief(state.get('disassembly')), 5000)}\n\n"
        f"## 补丁模式\n{_json_snip(hunt.get('patched_pattern') or {}, 3000)}\n\n"
        "这是独立的 Feature 关闭路径流水线。"
        "必须回答：Feature 为关/未启用时，是否回到漏洞版逻辑。"
        "逐项看：xref 函数、IsEnabled 测试、失败返回、else 分支是否跳过新锁/Probe。"
        "没有 Feature 证据则 verdict=unknown 并说明。"
        "先 JSON：verdict(closed|partial|bypassable|unknown)、confidence、summary、"
        "findings[{method,target,status(closed|residual|unknown),likelihood,evidence,hardening}]。"
        "再中文（只用 ###）。禁止 exploit / PoC / 逐步绕过。禁止编造 Feature ID。"
    )
    result = _safe_agent(
        state,
        "FeatureOffAnalyst",
        "feature_off_notes",
        agent_system_prompt("FeatureOffAnalyst"),
        user,
        93,
        92,
    )
    pack = build_bypass_pack(result.get("feature_off_notes") or "")
    result["feature_off_pack"] = pack
    _rewrite_last_agent(
        result,
        f"FeatureOffAnalyst · {pack.get('verdict') or 'unknown'} · {len(pack.get('findings') or [])} 条",
    )
    return result


def node_report_writer(state: PatchState) -> dict:
    if not _agent_enabled(state, "ReportWriter"):
        existing = state.get("report") or ""
        why = _skip_reason(state, "ReportWriter")
        return {
            "report": existing if isinstance(existing, str) else "",
            "traces": append_trace(state, "ReportWriter", "agent", f"跳过 ReportWriter：{why}", 98),
        }
    if not llm_configured():
        return {
            "llm_error": "LLM API key 未配置，请在设置页填写",
            "report": "",
            "traces": append_trace(state, "ReportWriter", "agent", "缺少 API Key", 98),
        }
    try:
        sym = state.get("symbol_diff") or {}
        resized = sym.get("functions_resized") or []
        call_rows = _call_diff_brief(state.get("disassembly"))
        top_names = [r["name"] for r in call_rows[:8] if r.get("name")]
        if not top_names:
            top_names = [f.get("name") for f in resized[:8] if f.get("name")]
        disasm_blocks = [b for b in (state.get("disassembly") or []) if b.get("name") in set(top_names)]
        if not disasm_blocks:
            disasm_blocks = (state.get("disassembly") or [])[:6]

        user = (
            "【输出格式·不可违反】直接写报告正文。第一个一级标题必须是「## 1. 执行摘要」。"
            "必须按序写满 §1–§15。禁止只写 §16–§19。禁止以「我将先补充」「先读取证据」开头。"
            "§16–§19 各留一行短导语即可，表格由系统覆盖，不要粘贴 IOC/情报 JSON。\n\n"
            f"任务标题: {state.get('title')}\n"
            f"样本标签: {state.get('old_label')} / {state.get('new_label')}"
            + (f" / {state.get('mid_label')}" if state.get("mid_sys") else "")
            + "\n"
            f"工作目录产物（附录请引用）: symbol_diff.json, size_timeline.json, byte_diff.json, "
            f"bind_func_diff.json, hotspots.json, cfg_diff.html, feature_trace.json, verify/, disasm/\n\n"
            f"## 工具证据 · PE\n旧版:\n{_json_snip(_pe_brief(state.get('old_pe')), 2500)}\n\n"
            f"新版:\n{_json_snip(_pe_brief(state.get('new_pe')), 2500)}\n"
            + (
                f"\n更早样本:\n{_json_snip(_pe_brief(state.get('mid_pe')), 2000)}\n"
                if state.get("mid_pe")
                else ""
            )
            + f"\n## 工具证据 · 热点/对照\n"
            f"hotspots: {_json_snip(state.get('hotspot_names') or [], 2000)}\n"
            f"controls: {_json_snip(state.get('control_names') or [], 3000)}\n\n"
            f"## 工具证据 · 尺寸变化 functions_resized\n{_json_snip(resized, 9000)}\n\n"
            f"## 工具证据 · 时间线\n{_json_snip(state.get('size_timeline'), 6000)}\n\n"
            f"## 工具证据 · 字节 diff 摘要\n{_json_snip(state.get('byte_diff'), 4500)}\n\n"
            f"## 工具证据 · 调用差（热点）\n{_json_snip(call_rows[:20], 6000)}\n\n"
            f"## 工具证据 · Feature\n{_json_snip(_feature_brief(state.get('feature_trace')), 8000)}\n\n"
            f"## 工具证据 · CFG 摘要\n{_json_snip((state.get('cfg_diff') or {}).get('functions') or [], 5000)}\n\n"
            f"## 工具证据 · 热点反汇编（优先写入 §6）\n{_disasm_for_llm(disasm_blocks, full_if_under=420)}\n\n"
            f"## 专家笔记 · PE\n{state.get('pe_notes')}\n\n"
            f"## 专家笔记 · 符号\n{state.get('symbol_notes')}\n\n"
            f"## 专家笔记 · 反汇编\n{state.get('disasm_notes')}\n\n"
            f"## 专家笔记 · Feature\n{state.get('feature_notes')}\n\n"
            f"## 专家笔记 · 对照路径\n{state.get('control_notes')}\n\n"
            f"## 专家笔记 · 根因\n{state.get('root_cause')}\n\n"
            f"## 专家笔记 · DetectionAnalyst（运营检测方法）\n{state.get('detection_notes') or '（无）'}\n\n"
            f"## 专家笔记 · ThreatIntelAnalyst（在野利用）\n{state.get('threat_notes') or '（无）'}\n\n"
            f"## 专家笔记 · BypassAnalyst（补丁完整性狩猎）\n{state.get('bypass_notes') or '（无）'}\n\n"
            f"## 专家笔记 · FeatureOffAnalyst（Feature 关闭路径）\n{state.get('feature_off_notes') or '（无）'}\n\n"
            f"## 专家笔记 · ResidualVulnAnalyst（同类残留发现）\n{state.get('residual_notes') or '（无）'}\n\n"
            f"## 专家笔记 · AliasSiteAnalyst（调用点覆盖）\n{state.get('alias_notes') or '（无）'}\n\n"
            f"## 狩猎简报 hunt_brief（独立流水线证据）\n{_json_snip(state.get('hunt_brief') or {}, 8000)}\n\n"
            "写作要求：先消耗「工具证据」填表与 RVA，再用「专家笔记」组织叙事；"
            "数字冲突时以工具证据为准。"
            "必须单独写满「## 6. 漏洞链」（总览表 + IDA 风格函数调用图 + 原语/影响 + 补丁切断点）；"
            "§6.2 节点必须是真实函数名，边必须是 CALL；系统会用调用差覆盖该图。"
            "可直接扩写根因专家的「漏洞链草稿」，不得省略。"
            "各节只写本职：§1/§11/§12 交叉引用 §6，不要重复整条链。"
            "不要整段粘贴专家笔记，禁止另开一级标题。\n\n"
            f"{report_structure_prompt()}"
        )
        report, writer_log = run_specialist(
            "ReportWriter", agent_system_prompt("ReportWriter"), user, state
        )
        report = unwrap_markdown_fence(report)
        chain = extract_vuln_chain(report, state.get("root_cause") or "")
        pack = build_ioc_pack(
            title=state.get("title") or "",
            old_pe=state.get("old_pe"),
            new_pe=state.get("new_pe"),
            mid_pe=state.get("mid_pe"),
            symbol_diff=state.get("symbol_diff"),
            feature_trace=state.get("feature_trace"),
            disassembly=state.get("disassembly"),
            vuln_chain=chain,
            patch_resolve=state.get("patch_resolve") if isinstance(state.get("patch_resolve"), dict) else {},
            detection_notes=state.get("detection_notes") or "",
            labels={
                "old": state.get("old_label"),
                "new": state.get("new_label"),
                "mid": state.get("mid_label"),
            },
        )
        report = ensure_ioc_section(report, pack)
        intel = state.get("threat_intel") if isinstance(state.get("threat_intel"), dict) else {}
        if not intel.get("status") or "search_hits" not in intel:
            intel = lookup_threat_intel(
                extract_cve(state.get("title") or "", state.get("patch_resolve") or {}, pack),
                title=state.get("title") or "",
                component=str(
                    ((state.get("patch_resolve") or {}) if isinstance(state.get("patch_resolve"), dict) else {}).get("old_file")
                    or ((state.get("old_pe") or {}) if isinstance(state.get("old_pe"), dict) else {}).get("original_filename")
                    or ""
                ),
            )
            intel = attach_analyst_notes(intel, state.get("threat_notes") or "")
        report = ensure_threat_section(report, intel)
        bypass_pack = state.get("bypass_pack") if isinstance(state.get("bypass_pack"), dict) else {}
        if not bypass_pack.get("verdict"):
            bypass_pack = build_bypass_pack(state.get("bypass_notes") or "")
        fo_pack = state.get("feature_off_pack") if isinstance(state.get("feature_off_pack"), dict) else {}
        if not fo_pack.get("verdict"):
            fo_pack = build_bypass_pack(state.get("feature_off_notes") or "")
        bypass_pack = merge_review_pack(bypass_pack, fo_pack, kind="bypass", source="FeatureOffAnalyst")
        residual_pack = state.get("residual_pack") if isinstance(state.get("residual_pack"), dict) else {}
        if not residual_pack.get("verdict"):
            residual_pack = build_residual_pack(state.get("residual_notes") or "")
        alias_pack = state.get("alias_pack") if isinstance(state.get("alias_pack"), dict) else {}
        if not alias_pack.get("verdict"):
            alias_pack = build_residual_pack(state.get("alias_notes") or "")
        residual_pack = merge_review_pack(residual_pack, alias_pack, kind="residual", source="AliasSiteAnalyst")
        report = ensure_bypass_section(report, bypass_pack)
        report = ensure_residual_section(report, residual_pack)
        work = Path(state["work_dir"]) if state.get("work_dir") else None
        if work:
            (work / "vuln_chain.json").write_text(
                json.dumps(chain, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            (work / "ioc.json").write_text(
                json.dumps(pack, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            (work / "threat_intel.json").write_text(
                json.dumps(intel, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            (work / "bypass_review.json").write_text(
                json.dumps(bypass_pack, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            (work / "residual_review.json").write_text(
                json.dumps(residual_pack, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        traces = _tool_traces(state, "ReportWriter", writer_log, 100)
        traces.extend(
            append_trace(
                state,
                "ReportWriter",
                "agent",
                "已生成含漏洞链、IOC、在野利用、绕过面与残留漏洞的详尽报告" + tool_trace_suffix(writer_log),
                100,
            )
        )
        return {
            "report": report,
            "vuln_chain": chain,
            "traces": traces,
        }
    except LLMError as e:
        return {
            "llm_error": str(e),
            "report": "",
            "traces": append_trace(state, "ReportWriter", "agent", f"失败: {e}", 100),
        }
