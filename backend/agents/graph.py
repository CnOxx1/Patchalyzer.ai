"""LangGraph: tool pipeline then fan-out LLM specialists."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from langgraph.graph import END, START, StateGraph

from .nodes import (
    node_byte_diff,
    node_bypass_analyst,
    node_cfg,
    node_control_analyst,
    node_detection_analyst,
    node_disasm,
    node_disasm_analyst,
    node_feature,
    node_feature_analyst,
    node_hunt_prep,
    node_alias_site_analyst,
    node_feature_off_analyst,
    node_join_tools,
    node_pdb_symbols,
    node_pe_analyst,
    node_pe_extract,
    node_pick_hotspots,
    node_report_writer,
    node_residual_analyst,
    node_root_cause,
    node_route_agents,
    node_symbol_analyst,
    node_threat_intel,
    node_timeline,
    node_verify_pack,
    extract_vuln_chain,
)
from ..config import agent_enabled
from ..services.func_logic import build_func_logic, ensure_func_logic_section
from ..services.ioc import build_ioc_pack_from_artifacts, ensure_ioc_section
from ..services.report_complete import heal_artifacts_report
from ..services.patch_review import (
    build_bypass_pack,
    build_residual_pack,
    ensure_bypass_section,
    ensure_residual_section,
    merge_review_pack,
    sanitize_bypass_pack,
    sanitize_residual_pack,
)
from ..services.pipeline import (
    NODE_PCT,
    assess_quality,
    check_cancel,
    extract_conclusions,
    guarded,
    load_extra_hotspots,
    save_extra_hotspots,
    set_progress_hook,
    unwrap_markdown_fence,
)
from ..services.threat_intel import (
    attach_analyst_notes,
    component_from_artifacts,
    ensure_threat_section,
    lookup_threat_intel,
    resolve_cve_from_artifacts,
)
from .state import PatchState


def _analyst_edges(g: StateGraph, start: str) -> None:
    g.add_edge(start, "pe_analyst")
    g.add_edge(start, "symbol_analyst")
    g.add_edge(start, "disasm_analyst")
    g.add_edge(start, "feature_analyst")
    g.add_edge("pe_analyst", "control_analyst")
    g.add_edge("symbol_analyst", "control_analyst")
    g.add_edge("disasm_analyst", "control_analyst")
    g.add_edge("feature_analyst", "control_analyst")
    g.add_edge("control_analyst", "root_cause")
    g.add_edge("root_cause", "detection_analyst")
    g.add_edge("root_cause", "threat_intel")
    g.add_edge("root_cause", "hunt_prep")
    g.add_edge("hunt_prep", "bypass_analyst")
    g.add_edge("hunt_prep", "residual_analyst")
    g.add_edge("hunt_prep", "alias_site_analyst")
    g.add_edge("hunt_prep", "feature_off_analyst")
    g.add_edge("detection_analyst", "report_writer")
    g.add_edge("threat_intel", "report_writer")
    g.add_edge("bypass_analyst", "report_writer")
    g.add_edge("residual_analyst", "report_writer")
    g.add_edge("alias_site_analyst", "report_writer")
    g.add_edge("feature_off_analyst", "report_writer")
    g.add_edge("report_writer", END)


def _add_analyst_nodes(g: StateGraph) -> None:
    g.add_node("pe_analyst", guarded("pe_analyst", node_pe_analyst))
    g.add_node("symbol_analyst", guarded("symbol_analyst", node_symbol_analyst))
    g.add_node("disasm_analyst", guarded("disasm_analyst", node_disasm_analyst))
    g.add_node("feature_analyst", guarded("feature_analyst", node_feature_analyst))
    g.add_node("control_analyst", guarded("control_analyst", node_control_analyst))
    g.add_node("root_cause", guarded("root_cause", node_root_cause))
    g.add_node("hunt_prep", guarded("hunt_prep", node_hunt_prep))
    g.add_node("detection_analyst", guarded("detection_analyst", node_detection_analyst))
    g.add_node("threat_intel", guarded("threat_intel", node_threat_intel))
    g.add_node("bypass_analyst", guarded("bypass_analyst", node_bypass_analyst))
    g.add_node("residual_analyst", guarded("residual_analyst", node_residual_analyst))
    g.add_node("alias_site_analyst", guarded("alias_site_analyst", node_alias_site_analyst))
    g.add_node("feature_off_analyst", guarded("feature_off_analyst", node_feature_off_analyst))
    g.add_node("report_writer", guarded("report_writer", node_report_writer))


def build_graph():
    g = StateGraph(PatchState)
    g.add_node("pe_extract", guarded("pe_extract", node_pe_extract))
    g.add_node("pdb_symbols", guarded("pdb_symbols", node_pdb_symbols))
    g.add_node("feature", guarded("feature", node_feature))
    g.add_node("byte_diff", guarded("byte_diff", node_byte_diff))
    g.add_node("pick_hotspots", guarded("pick_hotspots", node_pick_hotspots))
    g.add_node("timeline", guarded("timeline", node_timeline))
    g.add_node("disasm", guarded("disasm", node_disasm))
    g.add_node("cfg", guarded("cfg", node_cfg))
    g.add_node("verify_pack", guarded("verify_pack", node_verify_pack))
    g.add_node("join_tools", guarded("join_tools", node_join_tools))
    g.add_node("route_agents", guarded("route_agents", node_route_agents))
    _add_analyst_nodes(g)

    g.add_edge(START, "pe_extract")
    g.add_edge("pe_extract", "pdb_symbols")
    g.add_edge("pdb_symbols", "feature")
    g.add_edge("pdb_symbols", "byte_diff")
    g.add_edge("feature", "pick_hotspots")
    g.add_edge("byte_diff", "pick_hotspots")
    g.add_edge("pick_hotspots", "timeline")
    g.add_edge("pick_hotspots", "disasm")
    g.add_edge("disasm", "cfg")
    g.add_edge("timeline", "join_tools")
    g.add_edge("cfg", "join_tools")
    g.add_edge("cfg", "verify_pack")
    g.add_edge("verify_pack", END)
    g.add_edge("join_tools", "route_agents")
    _analyst_edges(g, "route_agents")
    return g.compile()


def build_tail_graph(*, run_llm: bool = True):
    g = StateGraph(PatchState)
    g.add_node("pick_hotspots", guarded("pick_hotspots", node_pick_hotspots))
    g.add_node("timeline", guarded("timeline", node_timeline))
    g.add_node("disasm", guarded("disasm", node_disasm))
    g.add_node("cfg", guarded("cfg", node_cfg))
    g.add_node("verify_pack", guarded("verify_pack", node_verify_pack))
    g.add_node("join_tools", guarded("join_tools", node_join_tools))
    g.add_node("route_agents", guarded("route_agents", node_route_agents))
    g.add_edge(START, "pick_hotspots")
    g.add_edge("pick_hotspots", "timeline")
    g.add_edge("pick_hotspots", "disasm")
    g.add_edge("disasm", "cfg")
    g.add_edge("timeline", "join_tools")
    g.add_edge("cfg", "join_tools")
    g.add_edge("cfg", "verify_pack")
    g.add_edge("verify_pack", END)
    g.add_edge("join_tools", "route_agents")
    if run_llm:
        _add_analyst_nodes(g)
        _analyst_edges(g, "route_agents")
    else:
        g.add_edge("route_agents", END)
    return g.compile()


def build_llm_graph():
    g = StateGraph(PatchState)
    g.add_node("route_agents", guarded("route_agents", node_route_agents))
    _add_analyst_nodes(g)
    _analyst_edges(g, "route_agents")
    g.add_edge(START, "route_agents")
    return g.compile()


def _artifacts_from_state(state: PatchState) -> dict[str, Any]:
    return {
        "old_pe": state.get("old_pe"),
        "new_pe": state.get("new_pe"),
        "mid_pe": state.get("mid_pe"),
        "symbol_diff": state.get("symbol_diff"),
        "size_timeline": state.get("size_timeline"),
        "byte_diff": state.get("byte_diff"),
        "disassembly": state.get("disassembly"),
        "control_disasm": state.get("control_disasm"),
        "hotspot_names": state.get("hotspot_names") or [],
        "hunt_names": state.get("hunt_names") or [],
        "hunt_brief": state.get("hunt_brief") or {},
        "hotspot_plan": state.get("hotspot_plan") or {},
        "evidence_quality": state.get("evidence_quality") or {},
        "conclusions": state.get("conclusions") or {},
        "extra_hotspots": state.get("extra_hotspots") or [],
        "control_names": state.get("control_names") or [],
        "cfg_diff": state.get("cfg_diff"),
        "feature_trace": state.get("feature_trace"),
        "verify_pack": state.get("verify_pack"),
        "paths": {
            "old_pdb": state.get("old_pdb"),
            "new_pdb": state.get("new_pdb"),
            "mid_pdb": state.get("mid_pdb"),
            "work_dir": state.get("work_dir"),
            "disasm_dir": str(Path(state["work_dir"]) / "disasm") if state.get("work_dir") else None,
            "cfg_html": str(Path(state["work_dir"]) / "cfg_diff.html") if state.get("work_dir") else None,
        },
        "labels": {
            "old": state.get("old_label"),
            "new": state.get("new_label"),
            "mid": state.get("mid_label"),
        },
        "agent_notes": {
            "pe": state.get("pe_notes"),
            "symbol": state.get("symbol_notes"),
            "disasm": state.get("disasm_notes"),
            "feature": state.get("feature_notes"),
            "control": state.get("control_notes"),
            "root_cause": state.get("root_cause"),
            "detection": state.get("detection_notes"),
            "threat": state.get("threat_notes"),
            "bypass": state.get("bypass_notes"),
            "residual": state.get("residual_notes"),
            "alias": state.get("alias_notes"),
            "feature_off": state.get("feature_off_notes"),
        },
        "agent_traces": state.get("traces") or [],
        "llm_report": state.get("report") or "",
        "vuln_chain": state.get("vuln_chain") or {},
        "ioc_pack": state.get("ioc_pack") or {},
        "threat_intel": state.get("threat_intel") or {},
        "bypass_pack": state.get("bypass_pack") or {},
        "residual_pack": state.get("residual_pack") or {},
        "alias_pack": state.get("alias_pack") or {},
        "feature_off_pack": state.get("feature_off_pack") or {},
        "enabled_agents": state.get("enabled_agents"),
        "routing_mode": state.get("routing_mode") or "auto",
        "routed_agents": state.get("routed_agents"),
        "skip_reasons": state.get("skip_reasons") or {},
        "prompt_depth": state.get("prompt_depth") or {},
        "routing_signals": state.get("routing_signals") or {},
        "llm_error": state.get("llm_error"),
        "llm_skipped": not bool(state.get("run_llm")),
        "graph": "langgraph-cve-pipeline",
    }


def finalize_soc(artifacts: dict[str, Any], title: str, work_dir: Path | None) -> dict[str, Any]:
    if artifacts.get("llm_report"):
        artifacts["llm_report"] = unwrap_markdown_fence(artifacts["llm_report"])
    if not (artifacts.get("vuln_chain") or {}).get("present"):
        artifacts["vuln_chain"] = extract_vuln_chain(
            artifacts.get("llm_report") or "",
            (artifacts.get("agent_notes") or {}).get("root_cause") or "",
        )
    artifacts["title"] = title or artifacts.get("title") or ""
    pack = build_ioc_pack_from_artifacts(artifacts, title=artifacts["title"])
    artifacts["ioc_pack"] = pack
    intel = artifacts.get("threat_intel") if isinstance(artifacts.get("threat_intel"), dict) else {}
    threat_on = agent_enabled(
        artifacts.get("enabled_agents"),
        "ThreatIntelAnalyst",
        run_llm=not artifacts.get("llm_skipped"),
        routed=artifacts.get("routed_agents"),
    )
    want_cve = resolve_cve_from_artifacts(artifacts, artifacts["title"])
    have_cve = str(intel.get("cve") or "").upper()
    if threat_on and (not intel.get("fetched_at") or (want_cve and want_cve != have_cve) or "search_hits" not in intel):
        intel = lookup_threat_intel(
            want_cve,
            title=artifacts["title"],
            component=component_from_artifacts(artifacts),
        )
        intel = attach_analyst_notes(
            intel, (artifacts.get("agent_notes") or {}).get("threat") or intel.get("threat_notes") or ""
        )
    artifacts["threat_intel"] = intel
    bypass = artifacts.get("bypass_pack") if isinstance(artifacts.get("bypass_pack"), dict) else {}
    if not bypass.get("verdict"):
        bypass = build_bypass_pack((artifacts.get("agent_notes") or {}).get("bypass") or "")
    artifacts["bypass_pack"] = bypass
    residual = artifacts.get("residual_pack") if isinstance(artifacts.get("residual_pack"), dict) else {}
    if not residual.get("verdict"):
        residual = build_residual_pack((artifacts.get("agent_notes") or {}).get("residual") or "")
    alias = artifacts.get("alias_pack") if isinstance(artifacts.get("alias_pack"), dict) else {}
    if not alias.get("verdict"):
        alias = build_residual_pack((artifacts.get("agent_notes") or {}).get("alias") or "")
    residual = merge_review_pack(residual, alias, kind="residual", source="AliasSiteAnalyst")
    artifacts["residual_pack"] = sanitize_residual_pack(residual)
    artifacts["alias_pack"] = alias
    fo = artifacts.get("feature_off_pack") if isinstance(artifacts.get("feature_off_pack"), dict) else {}
    if not fo.get("verdict"):
        fo = build_bypass_pack((artifacts.get("agent_notes") or {}).get("feature_off") or "")
    bypass = merge_review_pack(bypass, fo, kind="bypass", source="FeatureOffAnalyst")
    artifacts["bypass_pack"] = sanitize_bypass_pack(bypass)
    artifacts["feature_off_pack"] = fo
    notes = artifacts.get("agent_notes") or {}
    artifacts["conclusions"] = extract_conclusions(
        notes.get("root_cause") or "",
        artifacts.get("llm_report") or "",
        artifacts.get("size_timeline") if isinstance(artifacts.get("size_timeline"), dict) else {},
    )
    if not artifacts.get("evidence_quality"):
        artifacts["evidence_quality"] = assess_quality(
            {
                "old_pdb": (artifacts.get("paths") or {}).get("old_pdb"),
                "new_pdb": (artifacts.get("paths") or {}).get("new_pdb"),
                "symbol_diff": artifacts.get("symbol_diff"),
                "hotspot_plan": artifacts.get("hotspot_plan"),
            }
        )
    logic = build_func_logic(artifacts)
    artifacts["func_logic"] = logic
    chain = artifacts.get("vuln_chain") if isinstance(artifacts.get("vuln_chain"), dict) else {}
    if chain:
        chain = {**chain, "func_logic": logic, "func_mermaid": logic.get("mermaid") or ""}
        artifacts["vuln_chain"] = chain
    if artifacts.get("llm_report"):
        artifacts["llm_report"] = ensure_ioc_section(artifacts["llm_report"], pack)
        artifacts["llm_report"] = ensure_threat_section(artifacts["llm_report"], intel)
        artifacts["llm_report"] = ensure_bypass_section(artifacts["llm_report"], bypass)
        artifacts["llm_report"] = ensure_residual_section(artifacts["llm_report"], residual)
        heal_artifacts_report(artifacts)
        artifacts["llm_report"] = ensure_func_logic_section(artifacts["llm_report"], logic)
    if work_dir:
        work_dir.mkdir(parents=True, exist_ok=True)
        (work_dir / "result.json").write_text(
            json.dumps(artifacts, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        if artifacts.get("llm_report"):
            (work_dir / "report.md").write_text(artifacts["llm_report"], encoding="utf-8")
        if artifacts.get("func_logic"):
            (work_dir / "func_logic.json").write_text(
                json.dumps(artifacts["func_logic"], ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        if artifacts.get("vuln_chain"):
            (work_dir / "vuln_chain.json").write_text(
                json.dumps(artifacts["vuln_chain"], ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        if artifacts.get("hunt_brief"):
            (work_dir / "hunt_brief.json").write_text(
                json.dumps(artifacts["hunt_brief"], ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        (work_dir / "ioc.json").write_text(
            json.dumps(pack, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (work_dir / "threat_intel.json").write_text(
            json.dumps(intel, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (work_dir / "bypass_review.json").write_text(
            json.dumps(bypass, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (work_dir / "residual_review.json").write_text(
            json.dumps(residual, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (work_dir / "alias_review.json").write_text(
            json.dumps(alias, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (work_dir / "feature_off_review.json").write_text(
            json.dumps(fo, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    return artifacts


def _stream(graph, initial: PatchState, progress_cb) -> PatchState:
    last_pct = 0
    final: PatchState = dict(initial)
    for event in graph.stream(initial, stream_mode="updates"):
        check_cancel(final)
        for node_name, delta in event.items():
            if not isinstance(delta, dict):
                continue
            new_traces = delta.get("traces")
            rest = {k: v for k, v in delta.items() if k != "traces"}
            if "llm_error" in rest and not rest["llm_error"]:
                rest.pop("llm_error", None)
            final = {**final, **rest}
            node_pct = NODE_PCT.get(node_name, last_pct)
            if new_traces:
                final["traces"] = list(final.get("traces") or []) + list(new_traces)
                last = new_traces[-1]
                msg = f"[{last.get('agent')}] {last.get('message')}"
                pct = last.get("percent") if last.get("percent") is not None else node_pct
                last_pct = max(int(pct or 0), int(node_pct or 0), last_pct)
                if progress_cb:
                    progress_cb(msg, int(last_pct))
            elif progress_cb:
                last_pct = max(last_pct, int(node_pct or 0))
                progress_cb(f"节点 {node_name}", last_pct)
    return final


def invoke_analysis_graph(
    old_sys: Path,
    new_sys: Path,
    work_dir: Path,
    title: str,
    *,
    run_llm: bool = True,
    mid_sys: Path | None = None,
    old_label: str = "漏洞版",
    new_label: str = "修复版",
    mid_label: str = "更早版本",
    progress_cb: Callable[[str, int], None] | None = None,
    enabled_agents: list[str] | None = None,
    resume: bool = False,
    extra_hotspots: list[str] | None = None,
    force_nodes: list[str] | None = None,
    routing_mode: str = "auto",
    patch_resolve: dict[str, Any] | None = None,
) -> dict[str, Any]:
    work_dir.mkdir(parents=True, exist_ok=True)
    extras = list(dict.fromkeys((extra_hotspots or []) + load_extra_hotspots(work_dir)))
    if extras:
        save_extra_hotspots(work_dir, extras)
    job_id = work_dir.name
    set_progress_hook(job_id, progress_cb)
    mode = "manual" if str(routing_mode or "").strip().lower() == "manual" else "auto"
    initial: PatchState = {
        "title": title,
        "old_sys": str(old_sys),
        "new_sys": str(new_sys),
        "mid_sys": str(mid_sys) if mid_sys else "",
        "old_label": old_label,
        "new_label": new_label,
        "mid_label": mid_label,
        "work_dir": str(work_dir),
        "run_llm": run_llm,
        "enabled_agents": enabled_agents,
        "routing_mode": mode,
        "traces": [],
        "resume": resume,
        "force_nodes": force_nodes or [],
        "extra_hotspots": extras,
        "patch_resolve": patch_resolve or {},
    }
    try:
        final = _stream(build_graph(), initial, progress_cb)
    finally:
        set_progress_hook(job_id, None)
    artifacts = finalize_soc(_artifacts_from_state(final), title, work_dir)
    if progress_cb:
        progress_cb("LangGraph 完成", 100)
    return artifacts


def invoke_hotspot_rerun(
    artifacts: dict[str, Any],
    title: str,
    extra_names: list[str],
    *,
    run_llm: bool = True,
    progress_cb: Callable[[str, int], None] | None = None,
    enabled_agents: list[str] | None = None,
) -> dict[str, Any]:
    paths = artifacts.get("paths") or {}
    work = Path(paths.get("work_dir") or "")
    if not work:
        raise ValueError("缺少工作目录，无法加选热点")
    extras = save_extra_hotspots(work, list(dict.fromkeys((artifacts.get("extra_hotspots") or []) + extra_names)))
    labels = artifacts.get("labels") or {}
    notes = artifacts.get("agent_notes") or {}
    job_id = work.name
    set_progress_hook(job_id, progress_cb)
    initial: PatchState = {
        "title": title,
        "old_sys": str(work / (Path(artifacts.get("old_pe") or {}).get("path") or "")).replace(str(work / ""), "") or "",
        "new_sys": "",
        "mid_sys": "",
        "work_dir": str(work),
        "run_llm": run_llm,
        "enabled_agents": enabled_agents if enabled_agents is not None else artifacts.get("enabled_agents"),
        "routing_mode": artifacts.get("routing_mode") or "auto",
        "hotspot_plan": artifacts.get("hotspot_plan") or {},
        "evidence_quality": artifacts.get("evidence_quality") or {},
        "patch_resolve": artifacts.get("patch_resolve") or {},
        "old_label": labels.get("old") or "漏洞版",
        "new_label": labels.get("new") or "修复版",
        "mid_label": labels.get("mid") or "更早版本",
        "traces": list(artifacts.get("agent_traces") or []),
        "old_pe": artifacts.get("old_pe") or {},
        "new_pe": artifacts.get("new_pe") or {},
        "mid_pe": artifacts.get("mid_pe") or {},
        "old_pdb": paths.get("old_pdb") or "",
        "new_pdb": paths.get("new_pdb") or "",
        "mid_pdb": paths.get("mid_pdb") or "",
        "symbol_diff": artifacts.get("symbol_diff") or {},
        "size_timeline": artifacts.get("size_timeline") or {},
        "byte_diff": artifacts.get("byte_diff") or {},
        "disassembly": artifacts.get("disassembly") or [],
        "control_disasm": artifacts.get("control_disasm") or [],
        "hotspot_names": artifacts.get("hotspot_names") or [],
        "control_names": artifacts.get("control_names") or [],
        "cfg_diff": artifacts.get("cfg_diff") or {},
        "feature_trace": artifacts.get("feature_trace") or {},
        "verify_pack": artifacts.get("verify_pack") or {},
        "extra_hotspots": extras,
        "force_nodes": ["pick_hotspots", "timeline", "disasm", "cfg", "verify_pack", "join_tools", "route_agents"],
        "resume": False,
        "pe_notes": notes.get("pe") or "",
        "symbol_notes": notes.get("symbol") or "",
        "disasm_notes": notes.get("disasm") or "",
        "feature_notes": notes.get("feature") or "",
        "control_notes": notes.get("control") or "",
        "root_cause": notes.get("root_cause") or "",
    }
    # Recover sample paths from the job folder.
    old_name = next((p.name for p in work.iterdir() if p.name.startswith("old_") and p.is_file()), "")
    new_name = next((p.name for p in work.iterdir() if p.name.startswith("new_") and p.is_file()), "")
    mid_name = next((p.name for p in work.iterdir() if p.name.startswith("mid_") and p.is_file()), "")
    initial["old_sys"] = str(work / old_name) if old_name else ""
    initial["new_sys"] = str(work / new_name) if new_name else ""
    initial["mid_sys"] = str(work / mid_name) if mid_name else ""
    try:
        final = _stream(build_tail_graph(run_llm=run_llm), initial, progress_cb)
    finally:
        set_progress_hook(job_id, None)
    merged = {**artifacts, **_artifacts_from_state(final)}
    return finalize_soc(merged, title, work)


def invoke_llm_phase(artifacts: dict[str, Any], title: str, enabled_agents: list[str] | None = None) -> dict[str, Any]:
    paths = artifacts.get("paths") or {}
    labels = artifacts.get("labels") or {}
    notes = artifacts.get("agent_notes") or {}
    selected = enabled_agents if enabled_agents is not None else artifacts.get("enabled_agents")
    initial: PatchState = {
        "title": title,
        "old_sys": "",
        "new_sys": "",
        "mid_sys": "",
        "work_dir": paths.get("work_dir") or "",
        "run_llm": True,
        "enabled_agents": selected,
        "routing_mode": artifacts.get("routing_mode") or "auto",
        "hotspot_plan": artifacts.get("hotspot_plan") or {},
        "evidence_quality": artifacts.get("evidence_quality") or {},
        "extra_hotspots": artifacts.get("extra_hotspots") or [],
        "old_label": labels.get("old") or "漏洞版",
        "new_label": labels.get("new") or "修复版",
        "mid_label": labels.get("mid") or "更早版本",
        "traces": list(artifacts.get("agent_traces") or []),
        "old_pe": artifacts.get("old_pe") or {},
        "new_pe": artifacts.get("new_pe") or {},
        "mid_pe": artifacts.get("mid_pe") or {},
        "old_pdb": paths.get("old_pdb") or "",
        "new_pdb": paths.get("new_pdb") or "",
        "mid_pdb": paths.get("mid_pdb") or "",
        "symbol_diff": artifacts.get("symbol_diff") or {},
        "size_timeline": artifacts.get("size_timeline") or {},
        "byte_diff": artifacts.get("byte_diff") or {},
        "disassembly": artifacts.get("disassembly") or [],
        "control_disasm": artifacts.get("control_disasm") or [],
        "hotspot_names": artifacts.get("hotspot_names") or [],
        "control_names": artifacts.get("control_names") or [],
        "cfg_diff": artifacts.get("cfg_diff") or {},
        "feature_trace": artifacts.get("feature_trace") or {},
        "verify_pack": artifacts.get("verify_pack") or {},
        "patch_resolve": artifacts.get("patch_resolve") or {},
        "pe_notes": notes.get("pe") or "",
        "symbol_notes": notes.get("symbol") or "",
        "disasm_notes": notes.get("disasm") or "",
        "feature_notes": notes.get("feature") or "",
        "control_notes": notes.get("control") or "",
        "root_cause": notes.get("root_cause") or "",
        "detection_notes": notes.get("detection") or "",
        "threat_notes": notes.get("threat") or "",
        "bypass_notes": notes.get("bypass") or "",
        "residual_notes": notes.get("residual") or "",
        "alias_notes": notes.get("alias") or "",
        "feature_off_notes": notes.get("feature_off") or "",
        "threat_intel": artifacts.get("threat_intel") or {},
        "bypass_pack": artifacts.get("bypass_pack") or {},
        "residual_pack": artifacts.get("residual_pack") or {},
        "alias_pack": artifacts.get("alias_pack") or {},
        "feature_off_pack": artifacts.get("feature_off_pack") or {},
        "hunt_brief": artifacts.get("hunt_brief") or {},
        "hunt_names": artifacts.get("hunt_names") or [],
    }
    work_dir = Path(paths.get("work_dir") or "")
    if work_dir and work_dir.exists():
        if not initial.get("old_sys"):
            old_name = next((p.name for p in work_dir.iterdir() if p.name.startswith("old_") and p.is_file()), "")
            if old_name:
                initial["old_sys"] = str(work_dir / old_name)
        if not initial.get("new_sys"):
            new_name = next((p.name for p in work_dir.iterdir() if p.name.startswith("new_") and p.is_file()), "")
            if new_name:
                initial["new_sys"] = str(work_dir / new_name)
        if not initial.get("mid_sys"):
            mid_name = next((p.name for p in work_dir.iterdir() if p.name.startswith("mid_") and p.is_file()), "")
            if mid_name:
                initial["mid_sys"] = str(work_dir / mid_name)
    final = _stream(build_llm_graph(), initial, None)
    merged = {**artifacts, **_artifacts_from_state(final)}
    merged["llm_skipped"] = False
    work = Path(paths["work_dir"]) if paths.get("work_dir") else None
    return finalize_soc(merged, title, work)
