"""IDA-style function logic chain from disassembly CALL / RIP xrefs."""
from __future__ import annotations

import re
from typing import Any

_INTEREST = re.compile(
    r"Feature_|SpinLock|ExFree|ExAllocate|ExEnter|ExRelease|TdiCopy|"
    r"KeAcquire|KeRelease|IoComplete|ProbeFor|Obf|MmProbe|RtlCopy|"
    r"^Afd|^Nt|^Zw|cmpxchg|Interlocked",
    re.I,
)
_SKIP = re.compile(
    r"^(memcpy|memmove|memset|memcmp|memchr|_guard_|__security|__chkstk|"
    r"__GSHandlerCheck|__C_specific_handler|__report_rangecheckfailure)",
    re.I,
)
_JUNK = re.compile(
    r"^(?:\?\?|WPP_|__imp_|const_|`string)",
    re.I,
)
_LABEL_SAFE = re.compile(r"[^\w.]")
_ID_SAFE = re.compile(r"[^\w]")
_RESERVED = {
    "end",
    "graph",
    "subgraph",
    "flowchart",
    "class",
    "classdef",
    "style",
    "click",
    "linkstyle",
    "interpolate",
    "default",
}


def _nid(name: str) -> str:
    raw = _ID_SAFE.sub("_", name or "fn")
    raw = re.sub(r"_+", "_", raw).strip("_")[:40] or "fn"
    if raw[0].isdigit():
        raw = "n_" + raw
    if raw.lower() in _RESERVED:
        raw = "fn_" + raw
    return "F_" + raw


def _label(name: str, delta: int | None = None) -> str:
    s = _LABEL_SAFE.sub("_", name or "fn")
    s = re.sub(r"_+", "_", s).strip("_")[:40] or "fn"
    if isinstance(delta, int) and delta:
        s += f" plus{delta}" if delta > 0 else f" minus{abs(delta)}"
    return s


def _is_junk(name: str) -> bool:
    n = (name or "").strip()
    if not n or n.isdigit() or _JUNK.match(n) or "??_C@" in n or "?$" in n:
        return True
    return False


def _delta(block: dict[str, Any]) -> int | None:
    o, n = block.get("old") or {}, block.get("new") or {}
    if o.get("size") is None or n.get("size") is None:
        return None
    return int(n["size"]) - int(o["size"])


def build_func_logic(artifacts: dict[str, Any] | None) -> dict[str, Any]:
    """Call graph: hotspot functions → their CALLs. Independent of the LLM."""
    art = artifacts or {}
    resized = {
        f.get("name"): f
        for f in (art.get("symbol_diff") or {}).get("functions_resized") or []
        if f.get("name")
    }
    blocks = list(art.get("disassembly") or [])
    control = list(art.get("control_disasm") or [])
    by_name = {}
    for b in blocks + control:
        name = b.get("name")
        if name:
            by_name[name] = b
    hotspot = {b.get("name") for b in blocks if b.get("name")}
    raw_edges: list[tuple[str, str, str]] = []

    def keep_callee(caller: str, callee: str) -> bool:
        if not callee or callee == caller or _is_junk(callee):
            return False
        if _SKIP.search(callee):
            return False
        if callee in hotspot or callee in by_name:
            return True
        if _INTEREST.search(callee):
            return True
        return False

    ranked = sorted(
        (b for b in blocks if b.get("name") and not _is_junk(b.get("name") or "")),
        key=lambda b: abs(_delta(b) or 0),
        reverse=True,
    )[:8]
    for b in ranked:
        caller = b.get("name")
        if not caller:
            continue
        old_c = set((b.get("old") or {}).get("calls") or [])
        new_c = set((b.get("new") or {}).get("calls") or [])
        kept = []
        extra = []
        for callee in sorted(old_c | new_c):
            if not keep_callee(caller, callee):
                extra.append(callee)
                continue
            kept.append(callee)
            if callee in old_c and callee in new_c:
                ch = "both"
            elif callee in new_c:
                ch = "added"
            else:
                ch = "removed"
            raw_edges.append((caller, callee, ch))
        for callee in extra[:3]:
            if _is_junk(callee) or _SKIP.search(callee):
                continue
            if callee in old_c and callee in new_c:
                ch = "both"
            elif callee in new_c:
                ch = "added"
            else:
                ch = "removed"
            raw_edges.append((caller, callee, ch))

    nodes: dict[str, dict[str, Any]] = {}
    for caller, callee, _ch in raw_edges:
        for name in (caller, callee):
            if name in nodes or _is_junk(name):
                continue
            b = by_name.get(name) or {}
            d = _delta(b) if b else (resized.get(name) or {}).get("delta")
            kind = "hotspot" if name in hotspot or name in resized else "callee"
            if str(name).startswith("Feature") or str(name).startswith("Wil"):
                kind = "feature"
            nodes[name] = {
                "id": name,
                "kind": kind,
                "delta": d,
                "old_rva": (b.get("old") or {}).get("rva") or (resized.get(name) or {}).get("old_rva"),
                "new_rva": (b.get("new") or {}).get("rva") or (resized.get(name) or {}).get("new_rva"),
            }

    edge_map: dict[tuple[str, str], str] = {}
    rank = {"removed": 2, "added": 2, "both": 1}
    for a, b, ch in raw_edges:
        key = (a, b)
        prev = edge_map.get(key)
        if prev is None or rank[ch] >= rank.get(prev, 0):
            edge_map[key] = ch
    edges = [
        {"from": a, "to": b, "change": ch}
        for (a, b), ch in edge_map.items()
        if not _is_junk(a) and not _is_junk(b)
    ][:48]
    keep = {e["from"] for e in edges} | {e["to"] for e in edges}
    node_list = [nodes[k] for k in nodes if k in keep]
    raw = {"nodes": node_list, "edges": edges}
    shaped = _shape_vuln_chain(raw, art)
    return {
        "nodes": shaped["nodes"],
        "edges": shaped["edges"],
        "all_nodes": node_list,
        "all_edges": edges,
        "mermaid": func_logic_mermaid(shaped),
    }


def _step_functions(artifacts: dict[str, Any]) -> list[tuple[str, str]]:
    chain = artifacts.get("vuln_chain") if isinstance(artifacts.get("vuln_chain"), dict) else {}
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for st in chain.get("steps") or []:
        kind = st.get("kind") or ""
        loc = f"{st.get('location') or ''} {st.get('result') or ''} {st.get('action') or ''}"
        if not kind:
            if re.search(r"用户态|user", loc, re.I):
                kind = "user"
            elif re.search(r"UAF|原语", loc, re.I):
                kind = "prim"
            elif re.search(r"补丁|切断", loc, re.I):
                kind = "patch"
            else:
                kind = "hotspot"
        for api in st.get("apis") or []:
            name = str(api).replace("()", "").strip()
            if not name or _is_junk(name):
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append((name, kind))
            if len(out) >= 10:
                return out
    return out


def _shape_vuln_chain(raw: dict[str, Any], artifacts: dict[str, Any]) -> dict[str, Any]:
    step_fns = _step_functions(artifacts)
    call_edges = list(raw.get("edges") or [])
    node_meta = {n.get("id"): n for n in raw.get("nodes") or [] if n.get("id")}
    by_from: dict[str, list[dict[str, Any]]] = {}
    for e in call_edges:
        by_from.setdefault(e.get("from") or "", []).append(e)
    out_nodes: dict[str, dict[str, Any]] = {}
    out_edges: list[dict[str, Any]] = []

    def add_node(name: str, kind: str | None = None) -> None:
        if not name or _is_junk(name):
            return
        if name in out_nodes:
            if kind and kind != "callee":
                out_nodes[name]["kind"] = kind
            return
        meta = dict(node_meta.get(name) or {"id": name, "kind": "callee"})
        if kind:
            meta["kind"] = kind
        if meta.get("kind") not in ("hotspot", "callee", "feature", "user", "prim", "patch"):
            meta["kind"] = "hotspot"
        meta["id"] = name
        out_nodes[name] = meta

    def add_edge(a: str, b: str, ch: str) -> None:
        if not a or not b or a == b or len(out_edges) >= 16:
            return
        if any(e["from"] == a and e["to"] == b for e in out_edges):
            return
        add_node(a)
        add_node(b)
        out_edges.append({"from": a, "to": b, "change": ch or "both"})

    def find_call(a: str, b: str) -> dict[str, Any] | None:
        for e in call_edges:
            if e.get("from") == a and e.get("to") == b:
                return e
        return None

    names = [n for n, _k in step_fns]
    kinds = {n: k for n, k in step_fns}
    if len(names) >= 2:
        for i, fn in enumerate(names):
            add_node(fn, kinds.get(fn) or (node_meta.get(fn) or {}).get("kind") or "hotspot")
            if i:
                real = find_call(names[i - 1], fn)
                add_edge(names[i - 1], fn, (real or {}).get("change") or "both")
        for fn in names:
            nside = 0
            for e in by_from.get(fn) or []:
                if nside >= 2 or e.get("to") in names:
                    continue
                add_node(e.get("to") or "", (node_meta.get(e.get("to")) or {}).get("kind") or "callee")
                add_edge(fn, e.get("to") or "", e.get("change") or "both")
                nside += 1
    else:
        callers: list[str] = []
        for e in call_edges:
            src = e.get("from") or ""
            if src and src not in callers:
                callers.append(src)
            if len(callers) >= 4:
                break
        for c in callers:
            add_node(c, "hotspot")
            nside = 0
            for e in by_from.get(c) or []:
                if nside >= 3:
                    break
                add_node(e.get("to") or "", (node_meta.get(e.get("to")) or {}).get("kind") or "callee")
                add_edge(c, e.get("to") or "", e.get("change") or "both")
                nside += 1
        if not out_edges and names:
            add_node(names[0], kinds.get(names[0]) or "hotspot")
    return {"nodes": list(out_nodes.values()), "edges": out_edges}


def func_logic_mermaid(graph: dict[str, Any]) -> str:
    lines = ["flowchart TB"]
    used: set[str] = set()
    id_of: dict[str, str] = {}
    for n in graph.get("nodes") or []:
        name = n.get("id") or ""
        if not name:
            continue
        nid = _nid(name)
        if nid in used:
            continue
        used.add(nid)
        id_of[name] = nid
        lines.append(f'  {nid}["{_label(name, n.get("delta"))}"]')
    n_edge = 0
    for e in graph.get("edges") or []:
        a = id_of.get(e.get("from") or "")
        b = id_of.get(e.get("to") or "")
        if not a or not b or a == b:
            continue
        ch = e.get("change") or "both"
        if ch == "added":
            lines.append(f"  {a} ==> {b}")
        elif ch == "removed":
            lines.append(f"  {a} -.-> {b}")
        else:
            lines.append(f"  {a} --> {b}")
        n_edge += 1
        if n_edge >= 16:
            break
    return "\n".join(lines)


def func_logic_markdown(graph: dict[str, Any]) -> str:
    by_caller: dict[str, list[dict[str, Any]]] = {}
    for e in graph.get("edges") or []:
        by_caller.setdefault(e.get("from") or "", []).append(e)
    nodes = {n.get("id"): n for n in graph.get("nodes") or [] if n.get("id")}
    lines: list[str] = []
    for caller, kids in by_caller.items():
        if not caller:
            continue
        n = nodes.get(caller) or {}
        d = n.get("delta")
        delta = f" ({d:+d})" if isinstance(d, int) and d else ""
        lines.append(f"- `{caller}`{delta}")
        for e in kids:
            mark = "+" if e.get("change") == "added" else ("−" if e.get("change") == "removed" else "·")
            lines.append(f"  - `[{mark}]` `{e.get('to')}`")
    return "\n".join(lines)


def ensure_func_logic_section(report: str, graph: dict[str, Any] | None) -> str:
    """Replace §6.2 with the Mermaid function-logic vuln chain."""
    mermaid = (graph or {}).get("mermaid") or ""
    if not mermaid.strip() or not (graph or {}).get("nodes"):
        return report or ""
    block = (
        "### 6.2 函数逻辑链\n\n"
        "节点是函数，箭头按漏洞链顺序。"
        "实线为链路顺序或两版都有的 CALL，粗箭头为修复版新增，虚线为漏洞版已去掉。\n\n"
        f"```mermaid\n{mermaid}\n```\n"
    )
    text = (report or "").replace("\r\n", "\n")
    if re.search(r"^###\s*6\.2\b", text, re.M):
        return re.sub(
            r"^###\s*6\.2\b[\s\S]*?(?=^###\s*6\.\d|^##\s*\d+\.|\Z)",
            block + "\n",
            text,
            count=1,
            flags=re.M,
        )
    if re.search(r"^##\s*6\.\s*漏洞链", text, re.M):
        return re.sub(
            r"(^##\s*6\.\s*漏洞链[^\n]*\n)",
            r"\1\n" + block + "\n",
            text,
            count=1,
            flags=re.M,
        )
    return text
