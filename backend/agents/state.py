"""Shared LangGraph state for patch analysis."""
from __future__ import annotations

import operator
from datetime import datetime, timezone
from typing import Annotated, Any, TypedDict


def _keep_last_str(left: str | None, right: str | None) -> str:
    if right:
        return right
    return left or ""


def _keep_last(left: Any, right: Any) -> Any:
    """Last-write-wins for parallel nodes that may both touch the same pack key.

    LangGraph LastValue channels reject two updates in one superstep
    (INVALID_CONCURRENT_GRAPH_UPDATE). Prefer the richer dict when both exist.
    """
    if right is None:
        return left
    if left is None:
        return right
    if isinstance(left, dict) and isinstance(right, dict):
        if right and not left:
            return right
        if left and not right:
            return left
        left_hit = 1 if (left.get("verdict") or left.get("fetched_at") or left.get("has_detection")) else 0
        right_hit = 1 if (right.get("verdict") or right.get("fetched_at") or right.get("has_detection")) else 0
        if right_hit != left_hit:
            return right if right_hit > left_hit else left
        return right if len(right) >= len(left) else left
    return right


class PatchState(TypedDict, total=False):
    title: str
    old_sys: str
    new_sys: str
    mid_sys: str
    old_label: str
    new_label: str
    mid_label: str
    work_dir: str
    run_llm: bool
    # Parallel agents each emit trace deltas; reducer concatenates.
    traces: Annotated[list[dict[str, Any]], operator.add]
    old_pe: dict[str, Any]
    new_pe: dict[str, Any]
    mid_pe: dict[str, Any]
    old_pdb: str
    new_pdb: str
    mid_pdb: str
    symbol_diff: dict[str, Any]
    size_timeline: dict[str, Any]
    byte_diff: dict[str, Any]
    disassembly: list[dict[str, Any]]
    control_disasm: list[dict[str, Any]]
    hotspot_names: list[str]
    control_names: list[str]
    hunt_names: list[str]
    hunt_brief: dict[str, Any]
    cfg_diff: dict[str, Any]
    feature_trace: dict[str, Any]
    verify_pack: dict[str, Any]
    patch_resolve: dict[str, Any]
    pe_notes: str
    symbol_notes: str
    disasm_notes: str
    feature_notes: str
    control_notes: str
    root_cause: str
    detection_notes: str
    threat_notes: str
    bypass_notes: str
    residual_notes: str
    alias_notes: str
    feature_off_notes: str
    ioc_pack: Annotated[dict[str, Any], _keep_last]
    threat_intel: Annotated[dict[str, Any], _keep_last]
    bypass_pack: Annotated[dict[str, Any], _keep_last]
    residual_pack: Annotated[dict[str, Any], _keep_last]
    alias_pack: Annotated[dict[str, Any], _keep_last]
    feature_off_pack: Annotated[dict[str, Any], _keep_last]
    extra_hotspots: list[str]
    hotspot_plan: dict[str, Any]
    evidence_quality: dict[str, Any]
    conclusions: dict[str, Any]
    resume: bool
    force_nodes: list[str]
    enabled_agents: list[str]
    routing_mode: str
    routed_agents: list[str] | None
    skip_reasons: dict[str, str]
    prompt_depth: dict[str, str]
    routing_signals: dict[str, Any]
    report: str
    vuln_chain: dict[str, Any]
    llm_error: Annotated[str, _keep_last_str]
    error: str


def make_trace(agent: str, role: str, message: str, percent: int | None = None) -> dict[str, Any]:
    return {
        "agent": agent,
        "role": role,
        "message": message,
        "percent": percent,
        "at": datetime.now(timezone.utc).isoformat(),
    }


def append_trace(
    state: PatchState,
    agent: str,
    role: str,
    message: str,
    percent: int | None = None,
) -> list[dict[str, Any]]:
    """Return a one-item trace delta for Annotated[list, operator.add] reducers."""
    _ = state  # kept for call-site compatibility
    return [make_trace(agent, role, message, percent)]
