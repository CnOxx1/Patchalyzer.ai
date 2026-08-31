"""Hotspot planning, evidence quality, LLM slices, checkpoint / cancel."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..atomic_io import write_text_replace

INTERESTING_RE = re.compile(
    r"Feature_|SpinLock|ExFreePool|TdiCopy|AfdGlobalData|cmpxchg|"
    r"0xf0|0xec|0x38|0x170|0xf8|KeAcquire|KeRelease|ExEnterCritical|ExReleaseResource",
    re.I,
)

_MD_FENCE_OPEN = re.compile(r"^```(?:markdown|md|gfm)?[ \t]*\n", re.I)
_MD_FENCE_CLOSE = re.compile(r"\n```[ \t]*\s*$")


def unwrap_markdown_fence(text: str) -> str:
    """Strip a wrapping ```markdown fence so the report actually renders."""
    s = (text or "").lstrip("\ufeff").strip()
    m = _MD_FENCE_OPEN.match(s)
    if not m:
        return s
    s = s[m.end() :]
    s = _MD_FENCE_CLOSE.sub("", s)
    return s.strip()

NODE_PCT = {
    "pe_extract": 8,
    "pdb_symbols": 24,
    "feature": 32,
    "byte_diff": 32,
    "pick_hotspots": 36,
    "timeline": 44,
    "disasm": 56,
    "cfg": 61,
    "verify_pack": 63,
    "join_tools": 64,
    "route_agents": 65,
    "pe_analyst": 68,
    "symbol_analyst": 70,
    "disasm_analyst": 74,
    "feature_analyst": 76,
    "control_analyst": 80,
    "root_cause": 86,
    "hunt_prep": 90,
    "detection_analyst": 90,
    "threat_intel": 90,
    "bypass_analyst": 92,
    "residual_analyst": 92,
    "alias_site_analyst": 92,
    "feature_off_analyst": 92,
    "report_writer": 97,
}

_CANCELLED: set[str] = set()
_PROGRESS: dict[str, Callable[[str, int], None]] = {}


class PipelineCancelled(Exception):
    pass


def job_id_of(state: dict[str, Any] | None) -> str:
    work = Path((state or {}).get("work_dir") or "")
    return work.name if work.name else ""


def _job_dir(job_id: str) -> Path:
    from ..config import JOBS_DIR
    return JOBS_DIR / job_id


def _cancel_flag(job_id: str) -> Path:
    return _job_dir(job_id) / "cancel.flag"


def progress_file(job_id: str) -> Path:
    return _job_dir(job_id) / "progress.json"


def write_progress_file(job_id: str, message: str, percent: int) -> None:
    if not job_id:
        return
    path = progress_file(job_id)
    try:
        write_text_replace(
            path,
            json.dumps({"message": message, "percent": int(percent)}, ensure_ascii=False),
        )
    except OSError:
        return


def read_progress_file(job_id: str) -> dict[str, Any] | None:
    if not job_id:
        return None
    path = progress_file(job_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def clear_progress_file(job_id: str) -> None:
    if not job_id:
        return
    try:
        progress_file(job_id).unlink(missing_ok=True)
    except OSError:
        pass


def request_cancel(job_id: str) -> None:
    if not job_id:
        return
    _CANCELLED.add(job_id)
    flag = _cancel_flag(job_id)
    flag.parent.mkdir(parents=True, exist_ok=True)
    flag.write_text("1", encoding="utf-8")


def clear_cancel(job_id: str) -> None:
    _CANCELLED.discard(job_id)
    try:
        _cancel_flag(job_id).unlink(missing_ok=True)
    except OSError:
        pass


def is_cancelled(job_id: str) -> bool:
    if not job_id:
        return False
    if job_id in _CANCELLED:
        return True
    try:
        return _cancel_flag(job_id).is_file()
    except OSError:
        return False


def check_cancel(state: dict[str, Any] | None = None, job_id: str = "") -> None:
    jid = job_id or job_id_of(state)
    if is_cancelled(jid):
        raise PipelineCancelled("任务已取消")


def set_progress_hook(job_id: str, cb: Callable[[str, int], None] | None) -> None:
    if not job_id:
        return
    if cb:
        _PROGRESS[job_id] = cb
    else:
        _PROGRESS.pop(job_id, None)


def report_progress(state: dict[str, Any], message: str, percent: int) -> None:
    jid = job_id_of(state)
    cb = _PROGRESS.get(jid)
    if cb:
        cb(message, int(percent))


def routing_file(work_dir: str | Path) -> Path:
    return Path(work_dir) / "routing.json"


def load_routing_mode(work_dir: str | Path, default: str = "auto") -> str:
    p = routing_file(work_dir)
    if not p.exists():
        return "manual" if default == "manual" else "auto"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "manual" if default == "manual" else "auto"
    if isinstance(data, dict):
        mode = str(data.get("routing_mode") or default).strip().lower()
        return "manual" if mode == "manual" else "auto"
    return "manual" if default == "manual" else "auto"


def save_routing_mode(work_dir: str | Path, mode: str) -> str:
    mode = "manual" if str(mode or "").strip().lower() == "manual" else "auto"
    p = routing_file(work_dir)
    existing: dict[str, Any] = {}
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                existing = data
        except (OSError, json.JSONDecodeError):
            existing = {}
    existing["routing_mode"] = mode
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")
    return mode


def extra_hotspots_path(work_dir: str | Path) -> Path:
    return Path(work_dir) / "extra_hotspots.json"


def load_extra_hotspots(work_dir: str | Path) -> list[str]:
    p = extra_hotspots_path(work_dir)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, list):
        return [str(x) for x in data if x]
    if isinstance(data, dict):
        return [str(x) for x in (data.get("names") or []) if x]
    return []


def save_extra_hotspots(work_dir: str | Path, names: list[str]) -> list[str]:
    uniq = list(dict.fromkeys(n for n in names if n))
    p = extra_hotspots_path(work_dir)
    p.write_text(json.dumps({"names": uniq}, ensure_ascii=False, indent=2), encoding="utf-8")
    return uniq


def checkpoint_file(work_dir: str | Path, node: str) -> Path:
    return Path(work_dir) / "checkpoints" / f"{node}.json"


def save_checkpoint(work_dir: str | Path, node: str, payload: dict[str, Any]) -> None:
    if not work_dir or not node:
        return
    rest = {k: v for k, v in (payload or {}).items() if k != "traces"}
    path = checkpoint_file(work_dir, node)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rest, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (path.parent / "last.json").write_text(
        json.dumps({"node": node}, ensure_ascii=False), encoding="utf-8"
    )


def load_checkpoint(work_dir: str | Path, node: str) -> dict[str, Any] | None:
    path = checkpoint_file(work_dir, node)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


# Parallel specialists must not emit each other's LastValue keys, or LangGraph
# raises INVALID_CONCURRENT_GRAPH_UPDATE (e.g. two writers of bypass_pack).
_SHARED_NODE_KEYS = frozenset({"traces", "llm_error", "error"})
_NODE_OWNED_KEYS: dict[str, frozenset[str]] = {
    "pe_analyst": frozenset({"pe_notes"}),
    "symbol_analyst": frozenset({"symbol_notes"}),
    "disasm_analyst": frozenset({"disasm_notes"}),
    "feature_analyst": frozenset({"feature_notes"}),
    "control_analyst": frozenset({"control_notes"}),
    "root_cause": frozenset({"root_cause"}),
    "hunt_prep": frozenset({"hunt_brief", "hunt_names"}),
    "detection_analyst": frozenset({"detection_notes", "ioc_pack"}),
    "threat_intel": frozenset({"threat_notes", "threat_intel"}),
    "bypass_analyst": frozenset({"bypass_notes", "bypass_pack"}),
    "residual_analyst": frozenset({"residual_notes", "residual_pack"}),
    "alias_site_analyst": frozenset({"alias_notes", "alias_pack"}),
    "feature_off_analyst": frozenset({"feature_off_notes", "feature_off_pack"}),
    "report_writer": frozenset({"report", "vuln_chain"}),
}


def filter_node_output(node_name: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    allowed = _NODE_OWNED_KEYS.get(node_name)
    if allowed is None:
        return payload
    keep = allowed | _SHARED_NODE_KEYS
    return {k: v for k, v in payload.items() if k in keep}


def _make_trace(agent: str, role: str, message: str, percent: int | None = None) -> dict[str, Any]:
    return {
        "agent": agent,
        "role": role,
        "message": message,
        "percent": percent,
        "at": datetime.now(timezone.utc).isoformat(),
    }


def guarded(node_name: str, fn):
    """Cancel check + optional resume from per-node checkpoint."""

    def wrapped(state):
        check_cancel(state)
        pct = NODE_PCT.get(node_name, 0)
        report_progress(state, f"节点 {node_name}", pct)
        force = set(state.get("force_nodes") or [])
        if state.get("resume") and node_name not in force:
            cached = load_checkpoint(state.get("work_dir") or "", node_name)
            if cached is not None:
                cached = filter_node_output(node_name, cached)
                cached["traces"] = [
                    _make_trace("Checkpoint", "tool", f"从断点恢复 {node_name}", pct)
                ]
                return cached
        out = fn(state)
        if isinstance(out, dict):
            out = filter_node_output(node_name, out)
        try:
            save_checkpoint(state.get("work_dir") or "", node_name, out if isinstance(out, dict) else {})
        except Exception:
            pass
        return out

    wrapped.__name__ = getattr(fn, "__name__", node_name)
    return wrapped


def feature_xref_names(feature_trace: dict[str, Any] | None) -> list[str]:
    names: list[str] = []
    for feat in (feature_trace or {}).get("features") or []:
        for xref in feat.get("xrefs") or []:
            n = xref.get("in_function") or xref.get("function") or xref.get("name")
            if n and n not in names:
                names.append(n)
    return names


def plan_hotspots(
    symbol_diff: dict[str, Any] | None,
    *,
    byte_diff: dict[str, Any] | None = None,
    feature_trace: dict[str, Any] | None = None,
    extra_names: list[str] | None = None,
    max_hotspots: int = 16,
    max_feature_force: int = 8,
    max_cfg: int = 12,
) -> dict[str, Any]:
    """Feature xref is forced in; remaining slots filled by |Δsize|, then user extras, then byte-diff."""
    sym = symbol_diff or {}
    resized_rows = sorted(
        [f for f in (sym.get("functions_resized") or sym.get("functions_resized") or []) if f.get("name")],
        key=lambda x: abs(x.get("delta") if x.get("delta") is not None else (x.get("delta") or 0)),
        reverse=True,
    )
    resized_names = [f["name"] for f in resized_rows]
    feat_names = feature_xref_names(feature_trace)
    byte_names: list[str] = []
    for item in (byte_diff or {}).get("top") or []:
        n = item.get("label") or item.get("name")
        if n and n not in byte_names and "+" not in str(n):
            byte_names.append(n)

    selected: list[str] = []
    reasons: dict[str, str] = {}

    def add(name: str | None, reason: str) -> None:
        if name and name not in selected:
            selected.append(name)
            reasons[name] = reason

    forced_feat: list[str] = []
    for n in feat_names:
        if len(forced_feat) >= max_feature_force:
            break
        add(n, "feature")
        forced_feat.append(n)

    user_extra: list[str] = []
    for n in extra_names or []:
        add(n, "user")
        user_extra.append(n)

    for n in resized_names:
        if len(selected) >= max_hotspots:
            break
        add(n, "resized")

    for n in byte_names:
        if len(selected) >= max_hotspots:
            break
        add(n, "byte")

    protected = list(dict.fromkeys(forced_feat + user_extra))
    rest = [n for n in selected if n not in protected]
    cap = max(max_hotspots, len(protected))
    selected = (protected + rest)[:cap]
    uncovered_resized = [n for n in resized_names if n not in selected]
    uncovered_feature = [n for n in feat_names if n not in selected]
    cfg_names = []
    for n in forced_feat + [x for x in selected if x not in forced_feat]:
        if n not in cfg_names:
            cfg_names.append(n)
        if len(cfg_names) >= max_cfg:
            break

    return {
        "selected": selected,
        "cfg_names": cfg_names,
        "reasons": reasons,
        "feature_forced": forced_feat,
        "user_extra": user_extra,
        "uncovered_resized": uncovered_resized,
        "uncovered_feature": uncovered_feature,
        "uncovered": uncovered_resized + [n for n in uncovered_feature if n not in uncovered_resized],
        "resized_total": len(resized_names),
        "feature_total": len(feat_names),
        "max_hotspots": max_hotspots,
    }


def assess_quality(state: dict[str, Any] | None) -> dict[str, Any]:
    st = state or {}
    flags: list[str] = []
    level = "ok"

    def pdb_ok(p: str | None) -> bool:
        try:
            path = Path(p or "")
            return path.exists() and path.stat().st_size > 1024
        except OSError:
            return False

    if not pdb_ok(st.get("old_pdb")) or not pdb_ok(st.get("new_pdb")):
        flags.append("no_pdb")
        level = "unreliable"
    sym = st.get("symbol_diff") if isinstance(st.get("symbol_diff"), dict) else {}
    if (sym.get("quality") or "") in ("heuristic", "no_pdb", "degraded"):
        if "no_pdb" not in flags:
            flags.append("heuristic_names")
        level = "unreliable"
    plan = st.get("hotspot_plan") if isinstance(st.get("hotspot_plan"), dict) else {}
    if plan.get("uncovered_resized") or plan.get("uncovered_feature"):
        flags.append("hotspot_truncated")
        if level == "ok":
            level = "partial"
    labels = {
        "ok": "证据充足",
        "partial": "热点未覆盖完整",
        "unreliable": "结论不可靠",
    }
    return {
        "level": level,
        "flags": flags,
        "label": labels[level],
        "detail": "；".join(
            {
                "no_pdb": "PDB 不可用，函数名来自导出表 / .pdata",
                "heuristic_names": "符号匹配为启发式，可能漏掉改名函数",
                "hotspot_truncated": "部分尺寸变化或 Feature xref 未进入反汇编",
            }.get(f, f)
            for f in flags
        ),
    }


def _filter_asm(lines: list[str], window: int = 2, cap: int = 80) -> list[str]:
    keep: set[int] = set()
    for i, ln in enumerate(lines or []):
        if INTERESTING_RE.search(ln):
            for j in range(max(0, i - window), min(len(lines), i + window + 1)):
                keep.add(j)
    if not keep:
        return (lines or [])[:cap] + (["..."] if len(lines or []) > cap else [])
    return [lines[i] for i in sorted(keep)][:cap]


def function_slices(state: dict[str, Any], names: list[str] | None = None, per_fn: int = 1700) -> str:
    st = state or {}
    hot = names or (st.get("hotspot_names") or [])
    resized = {
        f.get("name"): f
        for f in ((st.get("symbol_diff") or {}).get("functions_resized") or [])
        if f.get("name")
    }
    blocks = {b.get("name"): b for b in (st.get("disassembly") or []) if b.get("name")}
    parts: list[str] = []
    for name in hot[:14]:
        lines = [f"## {name}"]
        sz = resized.get(name) or {}
        if sz:
            lines.append(
                f"size old={sz.get('old')} new={sz.get('new')} delta={sz.get('delta')} "
                f"rva {sz.get('old_rva')} -> {sz.get('new_rva')}"
            )
        block = blocks.get(name) or {}
        added = block.get("calls_added") or block.get("calls_added") or []
        removed = block.get("calls_removed") or block.get("calls_removed") or []
        if added:
            lines.append("calls_added: " + ", ".join(str(x) for x in added[:24]))
        if removed:
            lines.append("calls_removed: " + ", ".join(str(x) for x in removed[:24]))
        for side in ("old", "new"):
            d = block.get(side) or {}
            if not d:
                lines.append(f"### {side}: MISSING")
                continue
            asm = d.get("disasm") or []
            lines.append(f"### {side} rva={d.get('rva')} size={d.get('size')} insns={len(asm)}")
            if len(asm) <= 120:
                lines.extend(asm)
            else:
                lines.append("; 兴趣指令窗口")
                lines.extend(_filter_asm(asm))
        text = "\n".join(lines)
        if len(text) > per_fn:
            text = text[:per_fn] + "\n...[per-function slice]"
        parts.append(text)
    return "\n\n".join(parts) or "(no hotspot slices)"


def pe_brief_for_llm(pe: dict[str, Any] | None) -> dict[str, Any]:
    pe = pe or {}
    return {
        "original_filename": pe.get("original_filename"),
        "file_version": pe.get("file_version"),
        "machine": pe.get("machine"),
        "size": pe.get("size"),
        "size_of_image": pe.get("size_of_image"),
        "timestamp_utc": pe.get("timestamp_utc"),
        "sha256": pe.get("sha256"),
        "imports": pe.get("imports") or {},
        "export_count": len(pe.get("exports") or []),
        "debug": [
            {k: d.get(k) for k in ("pdb_filename", "guid_compact", "age", "symbol_url") if d.get(k)}
            for d in (pe.get("debug") or [])[:2]
        ],
    }


def byte_diff_brief(byte_diff: dict[str, Any] | None) -> dict[str, Any]:
    bd = byte_diff or {}
    top = []
    for item in (bd.get("top") or [])[:8]:
        top.append(
            {
                "name": item.get("label") or item.get("name"),
                "patch_bytes": item.get("patch_bytes"),
                "size_old": item.get("size_old"),
                "size_new": item.get("size_new"),
            }
        )
    return {
        "note": "字节差含 RIP 重定位噪声，不得单独作为补丁热点；以 .pdata 尺寸为准。",
        "total_bytes": bd.get("total_bytes"),
        "functions_with_byte_changes": bd.get("functions_with_byte_changes"),
        "top_noisy": top,
    }


def extract_conclusions(
    root_notes: str = "",
    report: str = "",
    timeline: dict[str, Any] | None = None,
) -> dict[str, str]:
    blob = f"{root_notes or ''}\n{report or ''}"
    one = ""
    cut = ""
    for pat in (r"根因一句话[^\n]*[：:]\s*(.+)", r"漏洞链一句话[^\n]*[：:]\s*(.+)"):
        m = re.search(pat, blob)
        if m:
            one = re.sub(r"[*`]", "", m.group(1)).strip()[:240]
            break
    for pat in (r"补丁切断点[^\n]*[：:]\s*(.+)", r"切断步骤[^\n]*[：:]\s*(.+)", r"补丁落在[^\n]*[：:]\s*(.+)"):
        m = re.search(pat, blob)
        if m:
            cut = re.sub(r"[*`]", "", m.group(1)).strip()[:240]
            break
    if not one:
        for line in (root_notes or "").splitlines():
            t = line.strip().lstrip("#").strip()
            if t and not t.startswith("|") and "漏洞链" not in t and len(t) > 12:
                one = t[:240]
                break
    tl = timeline or {}
    labels = list(tl.get("labels") or [])
    if not cut and len(labels) >= 2:
        rows = tl.get("rows") or []
        last, prev = labels[-1], labels[-2]
        hop = 0
        for r in rows:
            a, b = r.get(prev), r.get(last)
            if a is not None and b is not None and a != b:
                hop += 1
        if hop:
            if len(labels) >= 3:
                early = labels[0]
                same_early = sum(
                    1
                    for r in rows
                    if r.get(early) is not None and r.get(prev) is not None and r.get(early) == r.get(prev) != r.get(last)
                )
                if same_early:
                    cut = f"补丁落在最后一跳（{prev} → {last}），更早构建与漏洞版尺寸相同"
                else:
                    cut = f"尺寸变化集中在 {prev} → {last}（{hop} 个函数）"
            else:
                cut = f"补丁体现在 {prev} → {last}（{hop} 个函数尺寸变化）"
    return {"root_one_liner": one, "patch_cut": cut}


CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)

CORE_AGENTS = (
    "PEAnalyst",
    "SymbolAnalyst",
    "DisasmAnalyst",
    "RootCauseAnalyst",
)
REPORT_AGENTS = ("ReportWriter", "DetectionAnalyst")
ALL_ROUTED_AGENTS = (
    "PEAnalyst",
    "SymbolAnalyst",
    "DisasmAnalyst",
    "FeatureAnalyst",
    "ControlPathAnalyst",
    "RootCauseAnalyst",
    "DetectionAnalyst",
    "ThreatIntelAnalyst",
    "BypassAnalyst",
    "ResidualVulnAnalyst",
    "AliasSiteAnalyst",
    "FeatureOffAnalyst",
    "ReportWriter",
)


def _user_allows(enabled: list[str] | None, name: str) -> bool:
    if enabled is None:
        return True
    return name in enabled


def _has_feature_evidence(state: dict[str, Any]) -> bool:
    ft = state.get("feature_trace") if isinstance(state.get("feature_trace"), dict) else {}
    feats = ft.get("features") or []
    if feats:
        return True
    if int(ft.get("count") or 0) > 0:
        return True
    if feature_xref_names(ft):
        return True
    sym = state.get("symbol_diff") if isinstance(state.get("symbol_diff"), dict) else {}
    added = sym.get("feature_symbols_added") or []
    if added:
        return True
    for n in state.get("hotspot_names") or []:
        if "Feature_" in str(n):
            return True
    return False


def _has_control_evidence(state: dict[str, Any]) -> bool:
    if state.get("control_names"):
        return True
    return bool(state.get("control_disasm"))


def _has_cve_signal(state: dict[str, Any]) -> bool:
    parts = [str(state.get("title") or "")]
    pr = state.get("patch_resolve")
    if isinstance(pr, dict):
        parts.append(str(pr.get("cve") or ""))
        parts.append(str(pr.get("title") or ""))
    work = Path(state.get("work_dir") or "")
    resolve = work / "resolve.json"
    if resolve.exists():
        try:
            data = json.loads(resolve.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                parts.append(str(data.get("cve") or ""))
                parts.append(str(data.get("title") or ""))
        except (OSError, json.JSONDecodeError):
            pass
    return bool(CVE_RE.search(" ".join(parts)))


def _want_ops_depth(state: dict[str, Any]) -> bool:
    if state.get("mid_sys"):
        return True
    plan = state.get("hotspot_plan") if isinstance(state.get("hotspot_plan"), dict) else {}
    if plan.get("uncovered") or plan.get("uncovered_resized") or plan.get("uncovered_feature"):
        return True
    q = state.get("evidence_quality") if isinstance(state.get("evidence_quality"), dict) else {}
    return (q.get("level") or "") in ("partial", "unreliable")


def route_agents(state: dict[str, Any] | None) -> dict[str, Any]:
    """Rule-based roster after tools. Does not invent new agent personas."""
    st = state or {}
    mode = str(st.get("routing_mode") or "auto").strip().lower()
    if mode not in ("auto", "manual"):
        mode = "auto"
    enabled = st.get("enabled_agents")
    if isinstance(enabled, list) and not enabled:
        # Empty explicit selection already means LLM off at job create;
        # still record a roster so traces stay consistent.
        pass
    signals = {
        "has_feature": _has_feature_evidence(st),
        "has_control": _has_control_evidence(st),
        "has_cve": _has_cve_signal(st),
        "ops_depth": _want_ops_depth(st),
        "run_llm": bool(st.get("run_llm")),
    }
    if mode == "manual" or not signals["run_llm"]:
        reasons = {}
        if not signals["run_llm"]:
            reasons = {n: "未启用 LLM" for n in ALL_ROUTED_AGENTS}
        return {
            "routing_mode": "manual" if mode == "manual" else mode,
            "routed_agents": None if signals["run_llm"] and mode == "manual" else [],
            "skip_reasons": reasons,
            "prompt_depth": {},
            "routing_signals": signals,
        }

    wanted: list[str] = []
    reasons: dict[str, str] = {}
    depth: dict[str, str] = {}

    def want(name: str, reason_if_skip: str | None = None) -> None:
        if reason_if_skip:
            if not _user_allows(enabled, name):
                reasons[name] = "未在勾选上限内"
            else:
                reasons[name] = reason_if_skip
            return
        if not _user_allows(enabled, name):
            reasons[name] = "未在勾选上限内"
            return
        if name not in wanted:
            wanted.append(name)
            depth[name] = "full"

    for name in CORE_AGENTS:
        want(name)
    for name in REPORT_AGENTS:
        want(name)
    if signals["has_feature"]:
        want("FeatureAnalyst")
    else:
        want("FeatureAnalyst", "无 Feature xref / Feature_* 符号")
    if signals["has_control"]:
        want("ControlPathAnalyst")
    else:
        want("ControlPathAnalyst", "无对照函数")
    if signals["has_cve"]:
        want("ThreatIntelAnalyst")
    else:
        want("ThreatIntelAnalyst", "标题/元数据中无 CVE")
    want("BypassAnalyst")
    want("ResidualVulnAnalyst")
    want("AliasSiteAnalyst")
    if signals["has_feature"]:
        want("FeatureOffAnalyst")
    else:
        want("FeatureOffAnalyst", "无 Feature xref / Feature_* 符号")

    for name in ALL_ROUTED_AGENTS:
        if name not in wanted and name not in reasons:
            reasons[name] = "路由未选中"

    return {
        "routing_mode": "auto",
        "routed_agents": wanted,
        "skip_reasons": reasons,
        "prompt_depth": depth,
        "routing_signals": signals,
    }
