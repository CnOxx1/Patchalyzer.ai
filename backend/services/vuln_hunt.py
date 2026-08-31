"""Deterministic evidence for independent bypass / residual hunt pipelines.

Goal: surface incomplete patches and similar unfixed functions.
Does not produce exploits, PoCs, or attack steps.
"""
from __future__ import annotations

import re
from typing import Any

_LOCK = re.compile(
    r"SpinLock|KeAcquire|KeRelease|ExAcquire|ExRelease|ExEnterCritical|"
    r"cmpxchg|lock cmp|QueuedSpin|CancelSpinLock",
    re.I,
)
_FEATURE = re.compile(r"Feature_\w+|WilFeature|Feature_IsEnabled|RtlQueryFeature", re.I)
_FREE = re.compile(r"ExFreePool|ExFreeToPaged|IoFreeMdl|ObfDereference|AfdDereference", re.I)
_PROBE = re.compile(
    r"ProbeFor|MmProbe|RtlCopy|memcpy|memmove|RtlStringCch|RtlUnicodeStringCopy|"
    r"TdiCopy|RtlCopyMemory",
    re.I,
)
_ENTRY = re.compile(
    r"Dispatch|Ioctl|DeviceControl|FastIo|IrpMj|InternalDevice|MajorFunction|"
    r"HandleRequest|DevCtrl|IoControl",
    re.I,
)
_RISK_NAME = re.compile(
    r"Bind|Accept|Connect|Listen|Join|Cleanup|Close|Free|Transmit|"
    r"Receive|Send|Poll|Event|Create|Open|Irp|Request|Endpoint|"
    r"Address|Super|San|Tdi|Disconnect|Cancel",
    re.I,
)
_INTEREST_LINE = re.compile(
    r"call|lock |cmpxchg|test |jz |jnz |je |jne |spinlock|feature_|free|"
    r"probe|mdl|acquire|release",
    re.I,
)


def _prefix(name: str) -> str:
    m = re.match(r"^([A-Z][a-zA-Z]{1,16})", name or "")
    return m.group(1) if m else (name or "")[:4]


def _asm_lines(block: dict[str, Any] | None, side: str = "new") -> list[str]:
    d = (block or {}).get(side) or {}
    return list(d.get("disasm") or [])


def _snip_asm(lines: list[str], cap: int = 80) -> list[str]:
    keep: list[str] = []
    for ln in lines:
        if _INTEREST_LINE.search(ln):
            keep.append(ln)
        if len(keep) >= cap:
            break
    if keep:
        return keep
    return lines[: min(12, len(lines))]


def _flags(text: str) -> dict[str, bool]:
    t = text or ""
    return {
        "has_lock": bool(_LOCK.search(t)),
        "has_feature": bool(_FEATURE.search(t)),
        "has_free": bool(_FREE.search(t)),
        "has_probe": bool(_PROBE.search(t)),
    }


def feature_xref_fns(trace: dict[str, Any] | None) -> list[str]:
    names: list[str] = []
    for feat in (trace or {}).get("features") or []:
        for x in feat.get("xrefs") or []:
            n = x.get("in_function") or x.get("function") or x.get("name")
            if n and n not in names:
                names.append(str(n))
    return names


def call_index(blocks: list[dict[str, Any]] | None) -> dict[str, dict[str, list[str]]]:
    callees: dict[str, list[str]] = {}
    callers: dict[str, list[str]] = {}
    for b in blocks or []:
        name = str(b.get("name") or "")
        if not name:
            continue
        calls = [str(c) for c in ((b.get("new") or {}).get("calls") or []) if c]
        callees[name] = calls
        for c in calls:
            callers.setdefault(c, []).append(name)
    return {"callees": callees, "callers": callers}


_JZ = re.compile(r"\b(jz|jnz|je|jne|ja|jbe|jb|jae|js|jns|jg|jl)\b", re.I)


def _jaccard(a: list[str] | set[str], b: list[str] | set[str]) -> float:
    sa, sb = {x for x in a if x}, {x for x in b if x}
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def call_clones(
    blocks: list[dict[str, Any]] | None,
    hotspot_names: list[str],
    resized: set[str],
    *,
    min_sim: float = 0.4,
    min_calls: int = 4,
) -> list[dict[str, Any]]:
    """Unpatched functions whose call set still looks like the vuln-edition hotspot."""
    hot = set(hotspot_names or [])
    old_profiles: list[tuple[str, set[str]]] = []
    new_profiles: list[tuple[str, set[str]]] = []
    for b in blocks or []:
        name = str(b.get("name") or "")
        if name not in hot:
            continue
        old_profiles.append((name, set((b.get("old") or {}).get("calls") or [])))
        new_profiles.append((name, set((b.get("new") or {}).get("calls") or [])))
    out: list[dict[str, Any]] = []
    for b in blocks or []:
        name = str(b.get("name") or "")
        if not name or name in hot or name in resized:
            continue
        calls = set((b.get("new") or {}).get("calls") or [])
        if len(calls) < min_calls:
            continue
        best_old = max((_jaccard(calls, p) for _, p in old_profiles), default=0.0)
        best_new = max((_jaccard(calls, p) for _, p in new_profiles), default=0.0)
        if best_old < min_sim:
            continue
        out.append(
            {
                "name": name,
                "like_old_hotspot": round(best_old, 3),
                "like_new_hotspot": round(best_new, 3),
                "closer_to_vuln_edition": best_old > best_new + 0.05,
                "shared_calls": sorted(calls)[:16],
            }
        )
    out.sort(key=lambda r: (-float(r["like_old_hotspot"]), r["name"]))
    return out[:16]


def cfg_check_gaps(
    cfg_diff: dict[str, Any] | None,
    hotspot_names: list[str],
    pattern: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Patched functions: hot basic blocks that still lack the newly added check."""
    markers = [str(c).lower() for c in ((pattern or {}).get("calls_added") or [])[:16] if c]
    hot = set(hotspot_names or [])
    gaps: list[dict[str, Any]] = []
    for fn in (cfg_diff or {}).get("functions") or []:
        name = str(fn.get("name") or "")
        if hot and name not in hot:
            continue
        new_blocks = fn.get("new_blocks") or []
        if len(new_blocks) < 2:
            continue
        with_check = 0
        without: list[dict[str, Any]] = []
        for blk in new_blocks:
            blob = "\n".join(blk.get("lines") or [])
            low = blob.lower()
            has = bool(markers and any(m in low for m in markers))
            has = has or bool(_LOCK.search(blob) or _FEATURE.search(blob) or _PROBE.search(blob))
            if has:
                with_check += 1
            elif blk.get("hot"):
                without.append(
                    {
                        "start": blk.get("start"),
                        "snip": (blk.get("lines") or [])[:8],
                    }
                )
        if with_check and without:
            gaps.append(
                {
                    "name": name,
                    "checked_blocks": with_check,
                    "hot_blocks_without_new_check": without[:8],
                    "total_new_blocks": len(new_blocks),
                }
            )
    return gaps[:12]


def skip_windows(
    disassembly: list[dict[str, Any]] | None,
    hotspot_names: list[str],
    pattern: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Heuristic: new check is followed by a conditional jump before free/probe/copy."""
    hot = set(hotspot_names or [])
    added = [str(c) for c in ((pattern or {}).get("calls_added") or [])[:12] if c]
    out: list[dict[str, Any]] = []
    for b in disassembly or []:
        name = str(b.get("name") or "")
        if hot and name not in hot:
            continue
        lines = _asm_lines(b, "new")
        check_i = None
        for i, ln in enumerate(lines):
            if _FEATURE.search(ln) or _LOCK.search(ln) or any(c.lower() in ln.lower() for c in added):
                check_i = i
                break
        if check_i is None:
            continue
        has_jz = any(_JZ.search(ln) for ln in lines[check_i : check_i + 12])
        use_i = None
        for i, ln in enumerate(lines[check_i + 1 :], check_i + 1):
            if _FREE.search(ln) or _PROBE.search(ln):
                use_i = i
                break
        if has_jz and use_i is not None and 1 < (use_i - check_i) <= 48:
            out.append(
                {
                    "name": name,
                    "check_line": lines[check_i],
                    "use_line": lines[use_i],
                    "insns_between": use_i - check_i,
                    "conditional_after_check": True,
                }
            )
    return out[:12]


def timeline_stable_names(size_timeline: dict[str, Any] | None, hotspot_names: list[str], resized: set[str]) -> list[str]:
    """Only meaningful with 3+ builds: never resized in the whole series."""
    labels = (size_timeline or {}).get("labels") or []
    if len(labels) < 3:
        return []
    hot = set(hotspot_names or [])
    names: list[str] = []
    for row in (size_timeline or {}).get("rows") or []:
        n = str(row.get("name") or "")
        if not n or n in hot or n in resized:
            continue
        if row.get("unchanged_across_samples"):
            names.append(n)
        if len(names) >= 16:
            break
    return names


def prefix_pool_names(
    symbol_diff: dict[str, Any] | None,
    hotspot_names: list[str],
    *,
    limit: int = 28,
) -> list[str]:
    prefixes = {_prefix(n) for n in list(hotspot_names or [])[:8] if n}
    resized = {f.get("name") for f in ((symbol_diff or {}).get("functions_resized") or []) if f.get("name")}
    hot = set(hotspot_names or [])
    out: list[str] = []
    for name in (symbol_diff or {}).get("code_symbols") or []:
        n = str(name)
        if not n or n in hot or n in resized:
            continue
        if prefixes and not any(n.startswith(p) for p in prefixes if p):
            continue
        out.append(n)
        if len(out) >= limit:
            break
    return out


def patched_pattern(disassembly: list[dict[str, Any]], hotspot_names: list[str]) -> dict[str, Any]:
    hot = set(hotspot_names or [])
    added: list[str] = []
    removed: list[str] = []
    new_text: list[str] = []
    for b in disassembly or []:
        if hot and b.get("name") not in hot:
            continue
        added.extend(b.get("calls_added") or [])
        removed.extend(b.get("calls_removed") or [])
        new_text.extend(_asm_lines(b, "new"))
    blob = "\n".join(added + new_text)
    flags = _flags(blob)
    return {
        "calls_added": list(dict.fromkeys(added))[:40],
        "calls_removed": list(dict.fromkeys(removed))[:40],
        "lock_added": flags["has_lock"] and any(_LOCK.search(c or "") for c in added),
        "feature_gated": flags["has_feature"] or any(_FEATURE.search(c or "") for c in added),
        "free_path_changed": any(_FREE.search(c or "") for c in added + removed),
        "probe_added": flags["has_probe"] and any(_PROBE.search(c or "") for c in added),
        **flags,
    }


def score_candidate(name: str, prefixes: set[str], control_names: list[str]) -> int:
    if not name:
        return -1
    score = 0
    if any(name.startswith(p) for p in prefixes if p):
        score += 4
    if _RISK_NAME.search(name):
        score += 3
    if _ENTRY.search(name):
        score += 4
    if name in set(control_names or []):
        score += 1
    if re.search(r"(Helper|Worker|pInternal|Stub)$", name):
        score -= 1
    return score


def select_hunt_names(
    symbol_diff: dict[str, Any] | None,
    hotspot_names: list[str],
    control_names: list[str],
    limit: int = 18,
) -> list[str]:
    sym = symbol_diff or {}
    resized = {f.get("name") for f in (sym.get("functions_resized") or []) if f.get("name")}
    hot = set(hotspot_names or [])
    prefixes = {_prefix(n) for n in list(hot)[:8] if n}
    scored: list[tuple[int, str]] = []
    for name in sym.get("code_symbols") or []:
        if not name or name in resized or name in hot:
            continue
        s = score_candidate(str(name), prefixes, control_names or [])
        if s >= 3:
            scored.append((s, str(name)))
    scored.sort(key=lambda x: (-x[0], x[1]))
    names = [n for _, n in scored[:limit]]
    for extra in control_names or []:
        if extra not in names and extra not in hot and extra not in resized:
            names.append(extra)
        if len(names) >= limit:
            break
    return names[:limit]


def expand_hunt_names(
    *,
    symbol_diff: dict[str, Any] | None,
    hotspot_names: list[str],
    control_names: list[str],
    blocks: list[dict[str, Any]],
    feature_trace: dict[str, Any] | None,
    pattern: dict[str, Any] | None,
    already: list[str],
    limit: int = 24,
) -> list[str]:
    """Second-round names from call graph, Feature xref, and entry points."""
    reasons = expand_reasons(
        symbol_diff=symbol_diff,
        hotspot_names=hotspot_names,
        control_names=control_names,
        blocks=blocks,
        feature_trace=feature_trace,
        pattern=pattern,
    )
    have = set(already or [])
    ranked = sorted(reasons.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    out: list[str] = []
    for name, why in ranked:
        if name in have:
            continue
        out.append(name)
        if len(have) + len(out) >= limit:
            break
    return out


def expand_reasons(
    *,
    symbol_diff: dict[str, Any] | None,
    hotspot_names: list[str],
    control_names: list[str],
    blocks: list[dict[str, Any]],
    feature_trace: dict[str, Any] | None,
    pattern: dict[str, Any] | None,
) -> dict[str, list[str]]:
    sym = symbol_diff or {}
    resized = {f.get("name") for f in (sym.get("functions_resized") or []) if f.get("name")}
    hot = set(hotspot_names or [])
    prefixes = {_prefix(n) for n in list(hot)[:8] if n}
    idx = call_index(blocks)
    reasons: dict[str, list[str]] = {}

    def add(name: str, tag: str) -> None:
        if not name or name in resized or name in hot:
            return
        bag = reasons.setdefault(str(name), [])
        if tag not in bag:
            bag.append(tag)

    for name in select_hunt_names(sym, list(hot), control_names or [], limit=18):
        add(name, "sibling")
    for h in hot:
        for caller in idx["callers"].get(h, []):
            add(caller, "unpatched_caller")
    for helper in (pattern or {}).get("calls_added") or []:
        for caller in idx["callers"].get(helper, []):
            add(caller, "calls_new_helper")
    interesting = {
        c
        for h in hot
        for c in idx["callees"].get(h, [])
        if _LOCK.search(c) or _FEATURE.search(c) or _FREE.search(c) or _PROBE.search(c)
    }
    for fn, calls in idx["callees"].items():
        if interesting and interesting & set(calls):
            add(fn, "shared_helper")
    for n in feature_xref_fns(feature_trace):
        add(n, "feature_xref")
    for name in sym.get("code_symbols") or []:
        if _ENTRY.search(str(name)) and any(str(name).startswith(p) for p in prefixes if p):
            add(str(name), "entry_point")
    for extra in control_names or []:
        add(str(extra), "control")
    return reasons


def candidate_row(name: str, block: dict[str, Any] | None, pattern: dict[str, Any]) -> dict[str, Any]:
    b = block or {}
    pattern = pattern or {}
    old = b.get("old") or {}
    new = b.get("new") or {}
    new_asm = _asm_lines(b, "new")
    old_asm = _asm_lines(b, "old")
    calls = list(new.get("calls") or [])
    text = "\n".join((b.get("calls_added") or []) + calls + new_asm)
    flags = _flags(text)
    observable = bool(new_asm or old_asm or calls or (b.get("calls_added") or []))
    # Only "patch newly added X" counts; pre-existing locks on the hotspot must not
    # mark every sibling as missing_lock.
    miss_lock = observable and bool(pattern.get("lock_added")) and not flags["has_lock"]
    miss_feat = observable and bool(pattern.get("feature_gated")) and not flags["has_feature"]
    miss_probe = observable and bool(pattern.get("probe_added")) and not flags["has_probe"]
    return {
        "name": name,
        "old_rva": old.get("rva"),
        "new_rva": new.get("rva"),
        "old_size": old.get("size"),
        "new_size": new.get("size"),
        "size_changed": bool(old.get("size") and new.get("size") and old.get("size") != new.get("size")),
        "calls": calls[:20],
        "calls_added": (b.get("calls_added") or [])[:16],
        **flags,
        "asm_available": observable,
        "missing_lock_vs_patch": miss_lock,
        "missing_feature_vs_patch": miss_feat,
        "missing_probe_vs_patch": miss_probe,
        "snippet": _snip_asm(new_asm or old_asm),
        "priority": (
            "high"
            if miss_lock
            else "medium"
            if miss_feat or miss_probe
            else "low"
        ),
        "why": [],
    }


def build_hunt_brief(
    *,
    symbol_diff: dict[str, Any] | None,
    hotspot_names: list[str],
    control_names: list[str],
    disassembly: list[dict[str, Any]],
    hunt_blocks: list[dict[str, Any]],
    feature_trace: dict[str, Any] | None = None,
    cfg_diff: dict[str, Any] | None = None,
    size_timeline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pattern = patched_pattern(disassembly or [], hotspot_names or [])
    all_blocks = list(disassembly or []) + list(hunt_blocks or [])
    by_name = {b.get("name"): b for b in all_blocks if b.get("name")}
    resized = {f.get("name") for f in ((symbol_diff or {}).get("functions_resized") or []) if f.get("name")}
    reasons = expand_reasons(
        symbol_diff=symbol_diff,
        hotspot_names=hotspot_names or [],
        control_names=control_names or [],
        blocks=all_blocks,
        feature_trace=feature_trace,
        pattern=pattern,
    )
    clones = call_clones(all_blocks, hotspot_names or [], resized)
    for c in clones:
        bag = reasons.setdefault(c["name"], [])
        if "call_clone" not in bag:
            bag.append("call_clone")
    for n in timeline_stable_names(size_timeline, hotspot_names or [], resized):
        bag = reasons.setdefault(n, [])
        if "timeline_stable" not in bag:
            bag.append("timeline_stable")
    def _why_rank(why: list[str]) -> int:
        order = (
            "unpatched_caller",
            "calls_new_helper",
            "call_clone",
            "feature_xref",
            "shared_helper",
            "entry_point",
            "timeline_stable",
            "sibling",
            "control",
        )
        ranks = [order.index(t) if t in order else 9 for t in (why or ["sibling"])]
        return min(ranks) if ranks else 9

    names = sorted(reasons.keys(), key=lambda n: (_why_rank(reasons.get(n) or []), n))[:24]
    if not names:
        names = select_hunt_names(symbol_diff, hotspot_names or [], control_names or [], limit=18)
    rows = []
    for n in names:
        row = candidate_row(n, by_name.get(n), pattern)
        why = reasons.get(n) or ["sibling"]
        row["why"] = why
        if "unpatched_caller" in why or "calls_new_helper" in why:
            if row.get("priority") == "low":
                row["priority"] = "medium"
        if "unpatched_caller" in why and (row.get("missing_lock_vs_patch") or row.get("missing_feature_vs_patch")):
            row["priority"] = "high"
        if "call_clone" in why and row.get("priority") == "low":
            row["priority"] = "medium"
        if "call_clone" in why and (row.get("missing_lock_vs_patch") or row.get("missing_feature_vs_patch")):
            row["priority"] = "high"
        rows.append(row)
    high = [r["name"] for r in rows if r.get("priority") == "high"]
    alias = [r for r in rows if "unpatched_caller" in (r.get("why") or []) or "calls_new_helper" in (r.get("why") or [])]
    feat = [r for r in rows if "feature_xref" in (r.get("why") or []) or r.get("missing_feature_vs_patch")]
    expand = expand_hunt_names(
        symbol_diff=symbol_diff,
        hotspot_names=hotspot_names or [],
        control_names=control_names or [],
        blocks=all_blocks,
        feature_trace=feature_trace,
        pattern=pattern,
        already=names,
        limit=24,
    )
    idx = call_index(all_blocks)
    gaps = cfg_check_gaps(cfg_diff, hotspot_names or [], pattern)
    windows = skip_windows(all_blocks, hotspot_names or [], pattern)
    have = set(names) | set(expand)
    for n in timeline_stable_names(size_timeline, hotspot_names or [], resized):
        if n not in have:
            expand.append(n)
            have.add(n)
        if len(expand) >= 24:
            break
    for c in clones:
        n = c.get("name")
        if n and n not in have:
            expand.append(n)
            have.add(n)
        if len(expand) >= 24:
            break
    return {
        "goal": "find_incomplete_patch_and_similar_unfixed_bugs",
        "patched_pattern": pattern,
        "candidates": rows,
        "high_priority": high,
        "alias_sites": [
            {"name": r["name"], "why": r.get("why"), "priority": r.get("priority"), "calls": r.get("calls")}
            for r in alias[:16]
        ],
        "feature_off_sites": [
            {"name": r["name"], "why": r.get("why"), "missing_feature_vs_patch": r.get("missing_feature_vs_patch")}
            for r in feat[:12]
        ],
        "clone_sites": clones[:12],
        "cfg_gaps": gaps,
        "skip_windows": windows,
        "callers_of_hotspots": {
            h: (idx["callers"].get(h) or [])[:12] for h in list(hotspot_names or [])[:8]
        },
        "expand_names": expand,
        "notes": (
            "候选来自：同前缀兄弟、未改调用点、调用画像克隆、新 helper 的其他调用者、"
            "Feature xref、入口函数、跨构建尺寸未变。"
            "cfg_gaps / skip_windows 描述已修补函数内部是否仍有未打检查的基本块或条件跳过。"
            "missing_*_vs_patch 为启发式，必须对照汇编确认。"
            "禁止据此写 exploit / PoC。"
        ),
    }
