"""Whitelisted analysis tools + bounded tool-call loop for all specialist agents.

Shared by the LangGraph pipeline and the isolated HuntLab. No shell, no exploit,
no payloads. Unknown tool names are rejected.
"""
from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from ..agents.llm import compose_system, make_chat, run_agent
from ..services.analyzer import (
    cfg_diff_functions,
    disassemble_functions,
    named_function_sizes,
    pe_import_table,
    write_disasm_files,
)
from ..services.llm_service import LLMError
from ..services.pipeline import PipelineCancelled, check_cancel
from ..services.vuln_hunt import _snip_asm, call_index, patched_pattern

TOOL_RESULT_CAP = 7000
_NAME_OK = re.compile(r"^[A-Za-z0-9_@$?]+$")
_JSON_OBJ = re.compile(r"\{[\s\S]*\}")
_BINARY_LOCKS_GUARD = threading.Lock()
_BINARY_LOCKS: dict[str, threading.Lock] = {}


def _binary_lock(*parts: object) -> threading.Lock:
    """Serialize pefile/capstone on the same files; different jobs can proceed in parallel."""
    key = "|".join(str(p) for p in parts)
    with _BINARY_LOCKS_GUARD:
        return _BINARY_LOCKS.setdefault(key, threading.Lock())

SAFETY = (
    "禁止 exploit / PoC / payload / shellcode / 逐步攻击或绕过利用步骤。"
    "只能调用白名单工具取证。没有工具返回就标 unknown / none，禁止编造函数名、RVA、Feature ID。"
)

TOOL_PREAMBLE = (
    "你可以按需调用白名单工具（不是必须凑满次数）："
    "pe_info, list_symbols, function_meta, disasm, cfg_blocks, call_neighbors, xrefs, "
    "patched_pattern, feature_info, read_evidence, compare_calls, ioctl_table, handler_score, "
    "list_imports, load_module。"
    "disasm 返回兴趣指令 + 函数头尾，不是全文。xrefs 合并 disasm 写出的 call_index.json、已反汇编集合和 HuntPrep，不是全镜像扫描。"
    "disasm / cfg_blocks 预算有限。call_neighbors 只覆盖已经反汇编过的函数。"
    "read_evidence 的 key 还可为 surface / handler_scores / findings / observations。"
    "没有工具结果不要编造调用关系、RVA、Feature ID。禁止按函数名推断职责。"
    "证据已够时直接写本职输出。"
    + SAFETY
)

PIPELINE_NUDGE = (
    "若证据已够，直接写本职分析；否则继续调用白名单工具。"
    "没有工具结果不要编造。禁止 exploit。"
)

WRITE_NUDGE = (
    "不要再调用工具。根据已有证据和工具返回，直接写出完整中文正文。"
    "禁止只回复确认、提纲或空行。禁止 exploit。"
)

HUNT_LAB_NUDGE = "若证据已够，输出 done JSON；否则继续调用工具。不要写 exploit。"

AUDIT_NUDGE = (
    "unresolved 非空时禁止 done：对那些符号继续 disasm，或对导入的 .sys/.dll 调用 load_module。"
    "只有跟完、或把无法继续的跳写进 blocked（附原因）才能输出 done JSON。"
    "不要凑工具次数。禁止 exploit。"
)

PATH_NUDGE = (
    "你只跟当前这一条入口。unresolved 非空时禁止 done："
    "对本路径上的符号继续 disasm，跨模块先 load_module。"
    "跟完或把无法继续的跳写进 blocked（附原因）才能输出 done JSON。"
    "不要切换到其它 IOCTL。禁止 exploit。"
)

PATH_HARDENED_NUDGE = (
    "本入口静态已标 hardened（有 Probe/MDL）。只确认 Probe/MDL 仍罩住用户缓冲即可 done（cleared）。"
    "不要为凑轮次继续跟。禁止 exploit。"
)


@dataclass(frozen=True)
class ToolBudget:
    max_rounds: int = 4
    max_tool_calls: int = 6
    disasm_budget: int = 4
    cfg_budget: int = 2
    max_tokens: int | None = None
    temperature: float | None = 0.1


@dataclass
class LoopResult:
    text: str
    parsed: dict[str, Any] | None
    tool_log: list[dict[str, Any]]
    calls: int
    rounds: int


HUNT_LAB_BUDGET = ToolBudget(max_rounds=8, max_tool_calls=16, disasm_budget=10, cfg_budget=3, max_tokens=4000, temperature=0.1)
AUDIT_BUDGET = ToolBudget(max_rounds=24, max_tool_calls=64, disasm_budget=40, cfg_budget=12, max_tokens=8192, temperature=0.1)
# One agent per user-reachable API; shared toolbox caches disasm across agents.
PATH_BUDGET = ToolBudget(max_rounds=14, max_tool_calls=32, disasm_budget=16, cfg_budget=6, max_tokens=6000, temperature=0.1)
PATH_HARDENED_BUDGET = ToolBudget(max_rounds=5, max_tool_calls=12, disasm_budget=8, cfg_budget=3, max_tokens=4000, temperature=0.1)
AUDIT_SHARED_DISASM = 96
AUDIT_SHARED_CFG = 24

_AGENT_BUDGETS: dict[str, ToolBudget] = {
    "PEAnalyst": ToolBudget(max_rounds=3, max_tool_calls=4, disasm_budget=1, cfg_budget=0),
    "SymbolAnalyst": ToolBudget(max_rounds=4, max_tool_calls=6, disasm_budget=2, cfg_budget=0),
    "DisasmAnalyst": ToolBudget(max_rounds=5, max_tool_calls=8, disasm_budget=6, cfg_budget=3),
    "FeatureAnalyst": ToolBudget(max_rounds=3, max_tool_calls=5, disasm_budget=2, cfg_budget=0),
    "ControlPathAnalyst": ToolBudget(max_rounds=5, max_tool_calls=8, disasm_budget=6, cfg_budget=3),
    "RootCauseAnalyst": ToolBudget(max_rounds=5, max_tool_calls=8, disasm_budget=6, cfg_budget=3),
    "DetectionAnalyst": ToolBudget(max_rounds=3, max_tool_calls=4, disasm_budget=2, cfg_budget=0),
    "ThreatIntelAnalyst": ToolBudget(max_rounds=3, max_tool_calls=3, disasm_budget=1, cfg_budget=0),
    "BypassAnalyst": ToolBudget(max_rounds=5, max_tool_calls=8, disasm_budget=6, cfg_budget=3),
    "ResidualVulnAnalyst": ToolBudget(max_rounds=5, max_tool_calls=8, disasm_budget=6, cfg_budget=3),
    "AliasSiteAnalyst": ToolBudget(max_rounds=5, max_tool_calls=8, disasm_budget=6, cfg_budget=3),
    "FeatureOffAnalyst": ToolBudget(max_rounds=4, max_tool_calls=6, disasm_budget=4, cfg_budget=2),
    "ReportWriter": ToolBudget(max_rounds=4, max_tool_calls=4, disasm_budget=2, cfg_budget=1, max_tokens=16384, temperature=0.15),
}

DEFAULT_PIPELINE_BUDGET = ToolBudget()


def budget_for(agent_name: str) -> ToolBudget:
    return _AGENT_BUDGETS.get(agent_name, DEFAULT_PIPELINE_BUDGET)


class QueryArgs(BaseModel):
    query: str = Field(description="子串，匹配符号名")
    limit: int = Field(default=24, description="最多返回条数")
    module: str = Field(default="", description="可选。已 load_module 的文件名，如 netio.sys")


class NameArgs(BaseModel):
    name: str = Field(description="函数符号名")
    module: str = Field(default="", description="可选模块文件名")


class DisasmArgs(BaseModel):
    name: str = Field(description="函数符号名")
    side: str = Field(default="both", description="old / new / both")
    module: str = Field(default="", description="可选。空则先查当前样本，再查已加载模块")


class SideArgs(BaseModel):
    side: str = Field(default="both", description="old / new / both")


class LoadModuleArgs(BaseModel):
    filename: str = Field(description="要跟进的 PE 文件名，如 netio.sys / ntoskrnl.exe / fltmgr.sys")


class ModuleQueryArgs(BaseModel):
    filename: str = Field(default="", description="模块文件名；空则看当前样本")


class EvidenceArgs(BaseModel):
    key: str = Field(description="pe | symbols | notes | root_cause | hunt_brief | hotspots | features | candidates | surface | handler_scores | findings | observations")


def _clip(obj: Any, cap: int = TOOL_RESULT_CAP) -> str:
    text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, default=str)
    if len(text) <= cap:
        return text
    return text[: cap - 1] + "…"


def _extract_json(text: str) -> dict[str, Any] | None:
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        pass
    matches = list(_JSON_OBJ.finditer(text or ""))
    for m in reversed(matches):
        try:
            data = json.loads(m.group(0))
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            continue
    return None


def _clean_name(name: str) -> str:
    n = (name or "").strip()
    if not n or not _NAME_OK.match(n) or ".." in n:
        raise ValueError(f"非法函数名: {name!r}")
    return n


def _pe_slim(pe: Any) -> dict[str, Any]:
    if not isinstance(pe, dict):
        return {}
    imports = pe.get("imports") if isinstance(pe.get("imports"), dict) else {}
    return {
        k: pe.get(k)
        for k in (
            "original_filename",
            "file_version",
            "machine",
            "size",
            "size_of_image",
            "timestamp_utc",
            "md5",
            "sha256",
        )
    } | {
        "import_dll_count": len(imports),
        "import_dlls": dict(list(imports.items())[:40]),
    }


def _asm_view(lines: list[str] | None) -> dict[str, Any]:
    rows = list(lines or [])
    interest = _snip_asm(rows, cap=96)
    head = rows[:16]
    tail = rows[-8:] if len(rows) > 24 else []
    return {
        "line_count": len(rows),
        "interest": interest,
        "head": head,
        "tail": tail,
    }


def _import_delta(old_pe: dict[str, Any] | None, new_pe: dict[str, Any] | None) -> dict[str, Any]:
    old_imp = (old_pe or {}).get("imports") if isinstance((old_pe or {}).get("imports"), dict) else {}
    new_imp = (new_pe or {}).get("imports") if isinstance((new_pe or {}).get("imports"), dict) else {}
    od, nd = set(old_imp), set(new_imp)
    changed = [
        {"dll": dll, "old": old_imp.get(dll), "new": new_imp.get(dll)}
        for dll in sorted(od & nd)
        if old_imp.get(dll) != new_imp.get(dll)
    ]
    return {
        "added_dlls": sorted(nd - od)[:30],
        "removed_dlls": sorted(od - nd)[:30],
        "count_changed": changed[:30],
    }


@lru_cache(maxsize=8)
def _cached_sizes(sys_s: str, pdb_s: str) -> dict[str, dict[str, Any]]:
    try:
        with _binary_lock("sizes", sys_s, pdb_s):
            return named_function_sizes(Path(sys_s), Path(pdb_s) if pdb_s else None)
    except Exception:
        return {}


class AnalysisToolbox:
    """Per-agent sandbox: whitelist tools + local disasm/CFG budgets."""

    def __init__(
        self,
        artifacts: dict[str, Any],
        *,
        old_sys: Path,
        new_sys: Path,
        work: Path,
        disasm_budget: int = 4,
        cfg_budget: int = 2,
    ):
        self.artifacts = artifacts or {}
        self.old_sys = old_sys
        self.new_sys = new_sys
        paths = self.artifacts.get("paths") or {}
        self.old_pdb = Path(paths.get("old_pdb") or "")
        self.new_pdb = Path(paths.get("new_pdb") or "")
        self.work = work
        self.disasm_budget = int(disasm_budget)
        self.cfg_budget = int(cfg_budget)
        self.blocks = list(self.artifacts.get("disassembly") or []) + list(
            self.artifacts.get("control_disasm") or []
        )
        self._by_name = {b.get("name"): b for b in self.blocks if b.get("name")}
        self.disasm_used = 0
        self.cfg_used = 0
        self._cfg_full: dict[str, Any] | None = None
        self._disk_index: dict[str, Any] | None = None
        self.extra: dict[str, dict[str, Any]] = {}
        for rec in self.artifacts.get("loaded_modules") or []:
            if isinstance(rec, dict) and rec.get("filename") and rec.get("path"):
                self.extra[str(rec["filename"]).lower()] = rec

    def reset_path_counters(self) -> None:
        """Per-entry agent: cached disasm still hits; only new functions count."""
        self.disasm_used = 0
        self.cfg_used = 0

    def _sizes(self, side: str) -> dict[str, dict[str, Any]]:
        sys_path = self.old_sys if side == "old" else self.new_sys
        pdb_path = self.old_pdb if side == "old" else self.new_pdb
        return _cached_sizes(str(sys_path), str(pdb_path) if pdb_path else "")

    def _load_disk_index(self) -> dict[str, Any]:
        if self._disk_index is not None:
            return self._disk_index
        path = Path(self.work) / "call_index.json" if self.work else Path()
        data: dict[str, Any] = {}
        if path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
            except Exception:
                data = {}
        self._disk_index = data
        return data

    def _merged_call_index(self) -> dict[str, dict[str, list[str]]]:
        live = call_index(self.blocks)
        disk = self._load_disk_index()
        if not disk:
            return live
        callees = {str(k): list(v) for k, v in (disk.get("callees") or {}).items()}
        callers = {str(k): list(v) for k, v in (disk.get("callers") or {}).items()}
        for name, dests in (live.get("callees") or {}).items():
            callees[name] = list(dict.fromkeys(list(callees.get(name) or []) + list(dests)))
        for name, srcs in (live.get("callers") or {}).items():
            callers[name] = list(dict.fromkeys(list(callers.get(name) or []) + list(srcs)))
        return {"callees": callees, "callers": callers}

    def _cfg_file(self) -> dict[str, Any]:
        if self._cfg_full is None:
            path = self.work / "cfg_diff.json"
            if path.is_file():
                try:
                    self._cfg_full = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    self._cfg_full = {}
            else:
                self._cfg_full = self.artifacts.get("cfg_diff") or {}
        return self._cfg_full or {}

    def _module_key(self, module: str = "") -> str:
        return str(module or "").strip().lower()

    def _module_rec(self, module: str = "") -> dict[str, Any] | None:
        key = self._module_key(module)
        if not key:
            return None
        return self.extra.get(key)

    def _module_paths(self, module: str = "") -> tuple[Path, Path, Path, Path]:
        rec = self._module_rec(module)
        if rec:
            p = Path(rec.get("path") or "")
            pdb = Path(rec.get("pdb") or "")
            return p, p, pdb, pdb
        return self.old_sys, self.new_sys, self.old_pdb, self.new_pdb

    def _sizes_of(self, module: str = "", side: str = "new") -> dict[str, dict[str, Any]]:
        old_sys, new_sys, old_pdb, new_pdb = self._module_paths(module)
        sys_path = old_sys if side == "old" else new_sys
        pdb_path = old_pdb if side == "old" else new_pdb
        return _cached_sizes(str(sys_path), str(pdb_path) if pdb_path else "")

    def _block_key(self, name: str, module: str = "") -> str:
        key = self._module_key(module)
        return f"{key}|{name}" if key else name

    def _persist_modules(self) -> None:
        rows = []
        for rec in self.extra.values():
            rows.append(
                {
                    "filename": rec.get("filename"),
                    "path": str(rec.get("path") or ""),
                    "pdb": str(rec.get("pdb") or ""),
                    "source": rec.get("source"),
                    "version": rec.get("version"),
                    "pdb_error": rec.get("pdb_error"),
                }
            )
        self.artifacts["loaded_modules"] = rows
        if self.work and Path(self.work).is_dir():
            try:
                (Path(self.work) / "loaded_modules.json").write_text(
                    json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
                )
            except Exception:
                pass

    def load_module(self, filename: str) -> str:
        from .module_resolve import MAX_EXTRA_MODULES, resolve_audit_module
        from .patch_resolver import PatchResolveError, sanitize_filename

        try:
            name = sanitize_filename(filename)
        except Exception as e:
            return _clip({"error": str(e)})
        key = name.lower()
        if key in self.extra:
            rec = self.extra[key]
            return _clip(
                {
                    "filename": rec.get("filename"),
                    "already": True,
                    "source": rec.get("source"),
                    "version": rec.get("version"),
                    "pdb": bool(rec.get("pdb")),
                    "imports": rec.get("imports") or {},
                }
            )
        primary = (self.artifacts.get("new_pe") or {}).get("original_filename") or self.new_sys.name
        if name.lower() == str(primary).lower() or name.lower() == self.new_sys.name.lower():
            return _clip({"filename": name, "already": True, "note": "这是当前样本，直接 disasm / list_symbols"})
        if len(self.extra) >= MAX_EXTRA_MODULES:
            return _clip({"error": f"额外模块已达上限 {MAX_EXTRA_MODULES}", "loaded": sorted(self.extra)})
        try:
            rec = resolve_audit_module(
                name,
                work=Path(self.work) / "modules",
                sample_pe=self.artifacts.get("new_pe") or self.artifacts.get("old_pe") or {},
                sample_path=self.new_sys,
            )
        except PatchResolveError as e:
            return _clip({"error": str(e), "filename": name})
        except Exception as e:
            return _clip({"error": str(e), "filename": name})
        self.extra[key] = rec
        self._persist_modules()
        return _clip(
            {
                "filename": rec.get("filename"),
                "source": rec.get("source"),
                "version": rec.get("version"),
                "pdb": bool(rec.get("pdb") and Path(str(rec.get("pdb"))).is_file()),
                "pdb_error": rec.get("pdb_error"),
                "size": (rec.get("pe") or {}).get("size"),
                "imports": rec.get("imports") or {},
                "note": "接下来用 disasm(name, module=该文件名) 或 list_symbols 跟导入函数。",
            }
        )

    def list_imports(self, filename: str = "") -> str:
        key = self._module_key(filename)
        if key and key in self.extra:
            rec = self.extra[key]
            return _clip({"module": rec.get("filename"), "imports": rec.get("imports") or {}})
        try:
            table = pe_import_table(self.new_sys)
        except Exception as e:
            return _clip({"error": str(e)})
        slim = {dll: names[:32] for dll, names in list(table.items())[:32]}
        return _clip({"module": self.new_sys.name, "imports": slim, "loaded": sorted(self.extra)})

    def _ensure_block(self, name: str, module: str = "") -> dict[str, Any] | None:
        cache = self._block_key(name, module)
        if cache in self._by_name:
            return self._by_name[cache]
        if not module and name in self._by_name:
            return self._by_name[name]
        if not module:
            hit = self._sizes_of("", "new").get(name) or self._sizes_of("", "old").get(name)
            if not hit:
                for key in self.extra:
                    if self._sizes_of(key).get(name):
                        return self._ensure_block(name, module=key)
        if self.disasm_used >= self.disasm_budget:
            return None
        self.disasm_used += 1
        old_sys, new_sys, old_pdb, new_pdb = self._module_paths(module)
        try:
            with _binary_lock("disasm", old_sys, new_sys):
                rows = disassemble_functions(
                    old_sys, new_sys, old_pdb, new_pdb, [name], max_lines=None
                )
        except Exception as e:
            return {"name": name, "module": module or self.new_sys.name, "error": str(e)}
        if not rows:
            return None
        block = rows[0]
        block["module"] = self._module_key(module) or self.new_sys.name
        self.blocks.append(block)
        self._by_name[cache] = block
        if not module:
            self._by_name[name] = block
        if self.work and Path(self.work).is_dir():
            try:
                with _binary_lock("write", self.work):
                    write_disasm_files(self.work, [block])
            except Exception:
                pass
        return block

    def pe_info(self, side: str = "both") -> str:
        side = (side or "both").lower()
        if side not in {"old", "new", "both"}:
            side = "both"
        out: dict[str, Any] = {}
        if side in {"old", "both"}:
            out["old"] = _pe_slim(self.artifacts.get("old_pe"))
        if side in {"new", "both"}:
            out["new"] = _pe_slim(self.artifacts.get("new_pe"))
        if side == "both" and self.artifacts.get("mid_pe"):
            out["mid"] = _pe_slim(self.artifacts.get("mid_pe"))
        if side == "both":
            out["import_delta"] = _import_delta(self.artifacts.get("old_pe"), self.artifacts.get("new_pe"))
        return _clip(out)

    def list_symbols(self, query: str, limit: int = 24, module: str = "") -> str:
        q = (query or "").lower().strip()
        if not q or len(q) < 2:
            return _clip({"error": "query 至少 2 个字符"})
        limit = max(1, min(int(limit or 24), 40))
        mod = self._module_key(module)
        matches: list[dict[str, Any]] = []
        if not mod:
            sym = self.artifacts.get("symbol_diff") or {}
            names = [str(n) for n in (sym.get("code_symbols") or []) if q in str(n).lower()]
            resized = {f.get("name") for f in (sym.get("functions_resized") or []) if f.get("name")}
            hot = set(self.artifacts.get("hotspot_names") or [])
            matches.extend(
                {"name": n, "resized": n in resized, "hotspot": n in hot, "module": self.new_sys.name}
                for n in names[:limit]
            )
        search_mods = [mod] if mod else [""] + list(self.extra)
        for m in search_mods:
            if len(matches) >= limit:
                break
            label = (self._module_rec(m) or {}).get("filename") if m else self.new_sys.name
            for n, meta in self._sizes_of(m).items():
                if q not in n.lower():
                    continue
                if any(x.get("name") == n and x.get("module") == label for x in matches):
                    continue
                matches.append(
                    {
                        "name": n,
                        "module": label,
                        "size": meta.get("size"),
                        "rva": hex(meta["rva"]) if meta.get("rva") is not None else None,
                    }
                )
                if len(matches) >= limit:
                    break
        return _clip({"query": query, "module": module or None, "matches": matches[:limit]})

    def function_meta(self, name: str, module: str = "") -> str:
        name = _clean_name(name)
        sym = self.artifacts.get("symbol_diff") or {}
        resized = next(
            (f for f in (sym.get("functions_resized") or []) if f.get("name") == name), None
        )
        old = self._sizes_of(module, "old").get(name) or {}
        new = self._sizes_of(module, "new").get(name) or {}
        if not old and not new and not module:
            for key in self.extra:
                new = self._sizes_of(key).get(name) or {}
                if new:
                    module = key
                    old = new
                    break
        label = (self._module_rec(module) or {}).get("filename") if module else self.new_sys.name
        return _clip(
            {
                "name": name,
                "module": label,
                "hotspot": name in set(self.artifacts.get("hotspot_names") or []),
                "resized": bool(resized),
                "resize_row": resized,
                "old": {"rva": hex(old["rva"]) if old.get("rva") is not None else None, "size": old.get("size")},
                "new": {"rva": hex(new["rva"]) if new.get("rva") is not None else None, "size": new.get("size")},
            }
        )

    def disasm(self, name: str, side: str = "both", module: str = "") -> str:
        name = _clean_name(name)
        side = (side or "both").lower()
        if side not in {"old", "new", "both"}:
            side = "both"
        block = self._ensure_block(name, module=module)
        if not block:
            return _clip(
                {
                    "error": f"无法反汇编 {name}（预算用尽或符号缺失）",
                    "disasm_used": self.disasm_used,
                    "hint": "若目标在其它 DLL/SYS，先 load_module(文件名)",
                }
            )
        if block.get("error"):
            return _clip(block)
        out: dict[str, Any] = {
            "name": name,
            "module": block.get("module") or module or self.new_sys.name,
            "calls_added": (block.get("calls_added") or [])[:32],
            "calls_removed": (block.get("calls_removed") or [])[:32],
        }
        for key in ("old", "new") if side == "both" else (side,):
            d = block.get(key) or {}
            view = _asm_view(d.get("disasm") or [])
            out[key] = {
                "rva": d.get("rva"),
                "size": d.get("size"),
                "calls": (d.get("calls") or [])[:40],
                **view,
            }
        return _clip(out, 12000)

    def cfg_blocks(self, name: str, module: str = "") -> str:
        name = _clean_name(name)
        cached = None
        for fn in (self._cfg_file().get("functions") or []):
            if fn.get("name") == name:
                cached = fn
                break
        if cached and (cached.get("new_blocks") or cached.get("old_blocks")):
            return _clip(_cfg_preview(cached))
        if self.cfg_used >= self.cfg_budget:
            if cached:
                return _clip({"name": name, "summary": cached, "note": "无基本块详情且 CFG 预算已用尽"})
            return _clip({"error": "CFG 预算已用尽", "cfg_used": self.cfg_used})
        self.cfg_used += 1
        old_sys, new_sys, old_pdb, new_pdb = self._module_paths(module)
        try:
            with _binary_lock("disasm", old_sys, new_sys):
                cfg = cfg_diff_functions(old_sys, new_sys, old_pdb, new_pdb, [name])
            fn = (cfg.get("functions") or [None])[0]
            if not fn:
                return _clip({"error": f"无 CFG: {name}"})
            return _clip(_cfg_preview(fn))
        except Exception as e:
            return _clip({"error": str(e)})

    def call_neighbors(self, name: str, module: str = "") -> str:
        name = _clean_name(name)
        self._ensure_block(name, module=module)
        idx = self._merged_call_index()
        return _clip(
            {
                "name": name,
                "module": module or self.new_sys.name,
                "callees": (idx["callees"].get(name) or [])[:32],
                "callers": (idx["callers"].get(name) or [])[:32],
                "note": "已反汇编集合的调用关系。跨模块请 load_module 后再 disasm。",
            }
        )

    def xrefs(self, name: str, module: str = "") -> str:
        name = _clean_name(name)
        block = self._ensure_block(name, module=module)
        idx = self._merged_call_index()
        hunt = self.artifacts.get("hunt_brief") if isinstance(self.artifacts.get("hunt_brief"), dict) else {}
        brief_map = hunt.get("callers_of_hotspots") if isinstance(hunt.get("callers_of_hotspots"), dict) else {}
        callees = list(
            dict.fromkeys(
                list((block or {}).get("calls_added") or [])
                + list(((block or {}).get("new") or {}).get("calls") or [])
                + list(((block or {}).get("old") or {}).get("calls") or [])
                + list(idx["callees"].get(name) or [])
            )
        )[:40]
        callers = list(dict.fromkeys(list(idx["callers"].get(name) or []) + list(brief_map.get(name) or [])))[:40]
        return _clip(
            {
                "name": name,
                "module": (block or {}).get("module") or module or self.new_sys.name,
                "callees": callees,
                "callers": callers,
                "note": "下一跳若是其它模块的导出，用 list_imports + load_module 继续跟。",
            }
        )

    def patched_pattern_tool(self) -> str:
        hot = list(self.artifacts.get("hotspot_names") or [])
        hunt = self.artifacts.get("hunt_brief") or {}
        pattern = hunt.get("patched_pattern") if isinstance(hunt, dict) else None
        if not pattern:
            pattern = patched_pattern(self.artifacts.get("disassembly") or [], hot)
        return _clip(
            {
                "hotspots": hot[:16],
                "pattern": pattern,
                "clone_sites": (hunt.get("clone_sites") or [])[:8] if isinstance(hunt, dict) else [],
                "cfg_gaps": (hunt.get("cfg_gaps") or [])[:6] if isinstance(hunt, dict) else [],
                "skip_windows": (hunt.get("skip_windows") or [])[:6] if isinstance(hunt, dict) else [],
            }
        )

    def feature_info(self) -> str:
        ft = self.artifacts.get("feature_trace") or {}
        feats = []
        for f in (ft.get("features") or [])[:8]:
            feats.append(
                {
                    "feature_id": f.get("feature_id"),
                    "on_disk_dword": f.get("on_disk_dword"),
                    "xrefs": [
                        {"rva": x.get("rva"), "in_function": x.get("in_function")}
                        for x in (f.get("xrefs") or [])[:12]
                    ],
                    "isEnabled_disasm": (f.get("isEnabled_disasm") or [])[:16],
                }
            )
        return _clip({"count": ft.get("count") or len(feats), "features": feats})

    def read_evidence(self, key: str) -> str:
        k = (key or "").strip().lower()
        notes = self.artifacts.get("agent_notes") or {}
        hunt = self.artifacts.get("hunt_brief") or {}
        if k in {"pe"}:
            return _clip(
                {
                    "old": _pe_slim(self.artifacts.get("old_pe")),
                    "new": _pe_slim(self.artifacts.get("new_pe")),
                    "mid": _pe_slim(self.artifacts.get("mid_pe")),
                }
            )
        if k in {"symbols", "symbol"}:
            sym = self.artifacts.get("symbol_diff") or {}
            return _clip(
                {
                    "resized": [f.get("name") for f in (sym.get("functions_resized") or [])[:40]],
                    "added": (sym.get("symbols_added") or [])[:20],
                    "removed": (sym.get("symbols_removed") or [])[:20],
                }
            )
        if k in {"notes"}:
            return _clip({nk: str(nv)[:1500] for nk, nv in notes.items() if nv})
        if k in {"root_cause", "root"}:
            return _clip({"root_cause": (notes.get("root_cause") or "")[:4000]})
        if k in {"hunt_brief", "hunt"}:
            return _clip(
                {
                    "goal": hunt.get("goal"),
                    "high_priority": hunt.get("high_priority"),
                    "alias_sites": (hunt.get("alias_sites") or [])[:12],
                    "clone_sites": (hunt.get("clone_sites") or [])[:12],
                }
            )
        if k in {"hotspots", "hot"}:
            return _clip({"hotspot_names": self.artifacts.get("hotspot_names") or []})
        if k in {"features", "feature"}:
            return self.feature_info()
        if k in {"candidates"}:
            rows = []
            for c in (hunt.get("candidates") or [])[:16]:
                rows.append(
                    {x: c.get(x) for x in ("name", "why", "priority", "missing_lock_vs_patch", "missing_feature_vs_patch")}
                )
            return _clip({"candidates": rows})
        if k in {"surface", "surface_map"}:
            return self.ioctl_table()
        if k in {"handler_scores", "scores"}:
            return _clip({"scores": (self.artifacts.get("handler_scores") or [])[:40]})
        if k in {"findings", "audit", "kernel_audit"}:
            pack = self.artifacts.get("kernel_audit") or {}
            return _clip(
                {
                    "verdict": pack.get("verdict"),
                    "bug_classes": pack.get("bug_classes") or [],
                    "findings": (pack.get("findings") or self.artifacts.get("findings") or [])[:32],
                    "observations": (pack.get("observations") or self.artifacts.get("observations") or [])[:16],
                }
            )
        if k in {"observations"}:
            return _clip({"observations": (self.artifacts.get("observations") or [])[:16]})
        return _clip(
            {
                "error": "key 只能是 pe / symbols / notes / root_cause / hunt_brief / hotspots / features / candidates / surface / handler_scores / findings / observations"
            }
        )

    def ioctl_table(self) -> str:
        surface = self.artifacts.get("surface_map") or {}
        dispatch = surface.get("dispatch") or {}
        ioctl = (dispatch.get("ioctl") or [])[:80]
        imm = ((surface.get("immediate") or {}).get("entries") or [])[:40]
        fast = ((surface.get("fastio") or {}).get("callees") or [])[:20]
        return _clip(
            {
                "status": surface.get("status"),
                "dispatch": dispatch.get("handler"),
                "limit": dispatch.get("limit"),
                "ioctl": ioctl,
                "immediate": imm,
                "fastio": fast,
                "major_functions": surface.get("major_functions") or {},
            }
        )

    def handler_score(self, name: str, module: str = "") -> str:
        name = _clean_name(name)
        for row in self.artifacts.get("handler_scores") or []:
            if row.get("name") == name:
                return _clip(row)
        return _clip({"error": f"无打分: {name}", "hint": "先 read_evidence(surface)"})

    def compare_calls(self, name: str, module: str = "") -> str:
        name = _clean_name(name)
        block = self._ensure_block(name, module=module)
        if not block:
            return _clip({"error": f"无法比较 {name}"})
        old_c = set(((block.get("old") or {}).get("calls") or []))
        new_c = set(((block.get("new") or {}).get("calls") or []))
        return _clip(
            {
                "name": name,
                "module": module or block.get("module") or self.new_sys.name,
                "calls_added": sorted(new_c - old_c)[:24],
                "calls_removed": sorted(old_c - new_c)[:24],
                "shared": sorted(old_c & new_c)[:24],
            }
        )


HuntLabContext = AnalysisToolbox


def _cfg_preview(fn: dict[str, Any]) -> dict[str, Any]:
    def slim(blocks: list[dict[str, Any]] | None, cap: int = 10) -> list[dict[str, Any]]:
        out = []
        for blk in blocks or []:
            out.append(
                {
                    "start": blk.get("start"),
                    "hot": bool(blk.get("hot")),
                    "snip": (blk.get("lines") or [])[:10],
                }
            )
            if len(out) >= cap:
                break
        return out

    return {
        "name": fn.get("name"),
        "old": fn.get("old"),
        "new": fn.get("new"),
        "delta_size": fn.get("delta_size"),
        "old_blocks": slim(fn.get("old_blocks")),
        "new_blocks": slim(fn.get("new_blocks")),
    }


def bind_tools(ctx: AnalysisToolbox) -> list[StructuredTool]:
    return [
        StructuredTool.from_function(
            name="pe_info",
            description="旧/新 PE 摘要：文件名、版本、架构、尺寸、哈希、导入 DLL 计数及增减。",
            func=ctx.pe_info,
            args_schema=SideArgs,
        ),
        StructuredTool.from_function(
            name="list_symbols",
            description="按子串搜索 PDB 代码符号，返回是否尺寸已变/是否热点。",
            func=ctx.list_symbols,
            args_schema=QueryArgs,
        ),
        StructuredTool.from_function(
            name="function_meta",
            description="单个函数的旧/新尺寸、RVA、是否热点、是否被补丁改过。",
            func=ctx.function_meta,
            args_schema=NameArgs,
        ),
        StructuredTool.from_function(
            name="disasm",
            description="反汇编函数。跨模块时传 module=已 load_module 的文件名。返回 CALL 表、兴趣指令、函数头尾。",
            func=ctx.disasm,
            args_schema=DisasmArgs,
        ),
        StructuredTool.from_function(
            name="cfg_blocks",
            description="查看函数基本块 diff（热点块含 lock/Feature/free）。预算有限。",
            func=ctx.cfg_blocks,
            args_schema=NameArgs,
        ),
        StructuredTool.from_function(
            name="call_neighbors",
            description="已反汇编范围内的调用者与被调用者。全库级请用 xrefs。",
            func=ctx.call_neighbors,
            args_schema=NameArgs,
        ),
        StructuredTool.from_function(
            name="xrefs",
            description="函数的 callees / callers。callers 来自已反汇编集合和 HuntPrep，不是全镜像。",
            func=ctx.xrefs,
            args_schema=NameArgs,
        ),
        StructuredTool.from_function(
            name="patched_pattern",
            description="补丁新增检查模式（锁/Feature/Probe）以及 HuntPrep 启发式缺口。无需参数。",
            func=lambda: ctx.patched_pattern_tool(),
        ),
        StructuredTool.from_function(
            name="feature_info",
            description="Feature_* 门控、on-disk 值、xref 函数、IsEnabled 摘要。无需参数。",
            func=lambda: ctx.feature_info(),
        ),
        StructuredTool.from_function(
            name="read_evidence",
            description="读取只读证据切片：pe / symbols / notes / root_cause / hunt_brief / hotspots / features / candidates / surface / handler_scores / findings / observations。",
            func=ctx.read_evidence,
            args_schema=EvidenceArgs,
        ),
        StructuredTool.from_function(
            name="compare_calls",
            description="比较某函数旧版与新版 CALL 集合。",
            func=ctx.compare_calls,
            args_schema=NameArgs,
        ),
        StructuredTool.from_function(
            name="ioctl_table",
            description="用户可达 IOCTL / Immediate / FastIo 处理函数表（研究流程表面图）。无需参数。",
            func=lambda: ctx.ioctl_table(),
        ),
        StructuredTool.from_function(
            name="handler_score",
            description="单个 IOCTL/FastIo 处理函数的 probe/MDL/拷贝静态打分。",
            func=ctx.handler_score,
            args_schema=NameArgs,
        ),
        StructuredTool.from_function(
            name="list_imports",
            description="列出当前样本或已加载模块的导入 DLL 及函数名。跨模块跟调用前先看这里。",
            func=ctx.list_imports,
            args_schema=ModuleQueryArgs,
        ),
        StructuredTool.from_function(
            name="load_module",
            description="加载并分析另一个内核/驱动 PE：优先本机 System32，否则按样本版本从 Winbindex 下载，再拉 PDB。用于跟进导入的 ntoskrnl/netio/fltmgr 等。",
            func=ctx.load_module,
            args_schema=LoadModuleArgs,
        ),
    ]


def _run_tool(tools: list[StructuredTool], name: str, args: dict[str, Any] | None) -> str:
    args = args if isinstance(args, dict) else {}
    for t in tools:
        if t.name == name:
            try:
                return str(t.invoke(args))
            except Exception as e:
                return _clip({"error": str(e), "tool": name})
    return _clip({"error": f"未知工具 {name}，只能用白名单工具"})


def _coerce_tool_args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            val = json.loads(raw)
        except Exception:
            return {}
        return val if isinstance(val, dict) else {}
    return {}


def _one_tool_call(tc: Any, idx: int) -> dict[str, Any] | None:
    if isinstance(tc, dict):
        fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
        name = str(tc.get("name") or fn.get("name") or "")
        cid = str(tc.get("id") or "") or f"call-{name or 'tool'}-{idx}"
        args = tc.get("args")
        if not isinstance(args, dict):
            args = _coerce_tool_args(fn.get("arguments") if fn else tc.get("arguments"))
        item = {"id": cid, "name": name, "args": args}
    else:
        name = str(getattr(tc, "name", "") or "")
        cid = str(getattr(tc, "id", "") or "") or f"call-{name or 'tool'}-{idx}"
        args = getattr(tc, "args", {})
        item = {
            "id": cid,
            "name": name,
            "args": args if isinstance(args, dict) else {},
        }
    return item if item.get("name") else None


def _tool_calls(msg: AIMessage) -> list[dict[str, Any]]:
    raw = list(getattr(msg, "tool_calls", None) or [])
    extra = getattr(msg, "additional_kwargs", None) or {}
    if isinstance(extra, dict) and extra.get("tool_calls") and not raw:
        raw = list(extra.get("tool_calls") or [])
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, tc in enumerate(raw):
        item = _one_tool_call(tc, i)
        if not item or item["id"] in seen:
            continue
        seen.add(item["id"])
        out.append(item)
    return out


def _ensure_tool_call_ids(msg: AIMessage) -> None:
    """Keep LangChain / provider ids aligned so every ToolMessage can match."""
    parsed = _tool_calls(msg)
    if not parsed:
        return
    raw = getattr(msg, "tool_calls", None)
    if isinstance(raw, list):
        for i, tc in enumerate(raw):
            cid = parsed[i]["id"] if i < len(parsed) else f"call-tool-{i}"
            if isinstance(tc, dict) and not tc.get("id"):
                tc["id"] = cid
            elif hasattr(tc, "id") and not getattr(tc, "id", None):
                try:
                    tc.id = cid
                except Exception:
                    pass
    extra = getattr(msg, "additional_kwargs", None) or {}
    kw = extra.get("tool_calls") if isinstance(extra, dict) else None
    if isinstance(kw, list):
        for i, tc in enumerate(kw):
            if isinstance(tc, dict) and not tc.get("id"):
                tc["id"] = parsed[i]["id"] if i < len(parsed) else f"call-tool-{i}"


def _block_text(part: Any) -> str:
    if isinstance(part, str):
        return part
    if isinstance(part, dict):
        kind = str(part.get("type") or "")
        if kind in {"text", "output_text"} or "text" in part:
            return str(part.get("text") or "")
        return ""
    text = getattr(part, "text", None)
    return str(text) if text else ""


def _msg_text(msg: Any) -> str:
    content = getattr(msg, "content", None)
    if isinstance(content, str) and content.strip():
        return content.strip()
    if isinstance(content, list):
        text = "".join(_block_text(x) for x in content).strip()
        if text:
            return text
    extra = getattr(msg, "additional_kwargs", None) or {}
    if isinstance(extra, dict):
        tcs = _tool_calls(msg) if isinstance(msg, AIMessage) else []
        if not tcs:
            for key in ("reasoning_content", "reasoning"):
                val = extra.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
    return ""


def _unanswered_tool_calls(messages: list[Any]) -> list[dict[str, Any]]:
    last_idx = -1
    last_ai: AIMessage | None = None
    for i, m in enumerate(messages):
        if isinstance(m, AIMessage) and _tool_calls(m):
            last_idx = i
            last_ai = m
    if last_ai is None:
        return []
    answered = {
        str(getattr(m, "tool_call_id", "") or "")
        for m in messages[last_idx + 1 :]
        if isinstance(m, ToolMessage)
    }
    return [tc for tc in _tool_calls(last_ai) if tc["id"] not in answered]


def _close_open_tool_calls(
    messages: list[Any],
    content: str = "本轮停止调用工具，请直接写正文。",
) -> None:
    """Every assistant tool_call must have a matching tool message before the next LLM call."""
    for tc in _unanswered_tool_calls(messages):
        messages.append(
            ToolMessage(content=content, tool_call_id=tc["id"], **({"name": tc["name"]} if tc.get("name") else {}))
        )


def tool_trace_suffix(log: list[dict[str, Any]]) -> str:
    bits: list[str] = []
    for item in log:
        name = item.get("tool")
        if not name:
            continue
        args = item.get("args") or {}
        hint = args.get("name") or args.get("query") or args.get("key") or args.get("side") or ""
        bits.append(f"{name}({hint})" if hint else str(name))
    if not bits:
        return ""
    return " · 工具 " + ", ".join(bits[:8])


def artifacts_from_state(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "old_pe": state.get("old_pe"),
        "new_pe": state.get("new_pe"),
        "mid_pe": state.get("mid_pe"),
        "symbol_diff": state.get("symbol_diff"),
        "disassembly": state.get("disassembly"),
        "control_disasm": state.get("control_disasm"),
        "hotspot_names": state.get("hotspot_names") or [],
        "hunt_brief": state.get("hunt_brief") or {},
        "cfg_diff": state.get("cfg_diff"),
        "feature_trace": state.get("feature_trace"),
        "paths": {
            "old_pdb": state.get("old_pdb"),
            "new_pdb": state.get("new_pdb"),
            "work_dir": state.get("work_dir"),
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
    }


def context_from_state(state: dict[str, Any], budget: ToolBudget | None = None) -> AnalysisToolbox | None:
    old = Path(state.get("old_sys") or "")
    new = Path(state.get("new_sys") or "")
    if not old.is_file() or not new.is_file():
        return None
    work = Path(state.get("work_dir") or "")
    budget = budget or DEFAULT_PIPELINE_BUDGET
    return AnalysisToolbox(
        artifacts_from_state(state),
        old_sys=old,
        new_sys=new,
        work=work,
        disasm_budget=budget.disasm_budget,
        cfg_budget=budget.cfg_budget,
    )


def run_tool_loop(
    *,
    system: str,
    user: str,
    tools: list[StructuredTool],
    job_id: str = "",
    state: dict[str, Any] | None = None,
    budget: ToolBudget | None = None,
    require_json: bool = False,
    progress_cb: Callable[[str, int], None] | None = None,
    progress_label: str = "",
    pct_start: int = 0,
    pct_end: int = 0,
    nudge: str = "",
    min_calls: int = 0,
    done_ok: Callable[[dict[str, Any] | None, list[dict[str, Any]]], bool] | None = None,
) -> LoopResult:
    budget = budget or DEFAULT_PIPELINE_BUDGET
    nudge = nudge or (HUNT_LAB_NUDGE if require_json else PIPELINE_NUDGE)
    min_calls = max(0, int(min_calls or 0))
    messages: list[Any] = [
        SystemMessage(content=system),
        HumanMessage(content=user),
    ]
    llm = make_chat(max_tokens=budget.max_tokens, temperature=budget.temperature)
    log: list[dict[str, Any]] = []
    bound_ok = True
    calls = 0
    text = ""
    parsed: dict[str, Any] | None = None
    rnd = 0

    def pct(i: int) -> int:
        span = max(1, pct_end - pct_start)
        return pct_start + min(span, int(span * (i + 1) / max(1, budget.max_rounds)))

    def invoke_llm(*, with_tools: bool):
        _close_open_tool_calls(messages)
        model = llm.bind_tools(tools) if with_tools else llm
        return model.invoke(messages)

    for rnd in range(budget.max_rounds):
        check_cancel(state, job_id=job_id)
        if progress_cb:
            label = progress_label or "工具轮次"
            progress_cb(f"{label} 第 {rnd + 1}/{budget.max_rounds} 轮", pct(rnd) if pct_end else 0)
        msg = None
        try:
            msg = invoke_llm(with_tools=bound_ok)
        except PipelineCancelled:
            raise
        except Exception as e:
            if "tool_call" in str(e).lower():
                _close_open_tool_calls(messages)
                try:
                    msg = invoke_llm(with_tools=bound_ok)
                except PipelineCancelled:
                    raise
                except Exception as e2:
                    e = e2
            if msg is None and bound_ok:
                bound_ok = False
                log.append({"round": rnd, "event": "tools_fallback", "error": str(e)[:240]})
                continue
            if msg is None:
                raise LLMError(str(e)) from e
        if isinstance(msg, AIMessage):
            _ensure_tool_call_ids(msg)
        messages.append(msg)
        native = _tool_calls(msg) if isinstance(msg, AIMessage) else []
        text = _msg_text(msg)
        parsed = _extract_json(text)
        json_tools: list[dict[str, Any]] = []
        if not native and parsed and parsed.get("tool") and not parsed.get("done"):
            json_tools = [{"id": f"json-{rnd}", "name": str(parsed.get("tool")), "args": parsed.get("args") or {}}]
        if native:
            skip_note = "已达本轮工具次数上限，请根据已有结果写正文。"
            for i, tc in enumerate(native):
                check_cancel(state, job_id=job_id)
                cid = str(tc.get("id") or f"call-{tc.get('name') or 'tool'}-{i}")
                if calls < budget.max_tool_calls and i < 4:
                    calls += 1
                    result = _run_tool(tools, tc["name"], tc.get("args"))
                    log.append(
                        {
                            "round": rnd + 1,
                            "tool": tc["name"],
                            "args": tc.get("args") or {},
                            "result_preview": result[:400],
                        }
                    )
                else:
                    result = skip_note
                    log.append({"round": rnd + 1, "tool": tc["name"], "skipped": True})
                messages.append(
                    ToolMessage(content=result, tool_call_id=cid, **({"name": tc["name"]} if tc.get("name") else {}))
                )
            _close_open_tool_calls(messages)
            if text.strip() and not require_json:
                break
            if rnd >= budget.max_rounds - 1:
                break
            continue
        if json_tools and calls < budget.max_tool_calls:
            for tc in json_tools[:4]:
                if calls >= budget.max_tool_calls:
                    break
                check_cancel(state, job_id=job_id)
                calls += 1
                result = _run_tool(tools, tc["name"], tc.get("args"))
                log.append(
                    {
                        "round": rnd + 1,
                        "tool": tc["name"],
                        "args": tc.get("args") or {},
                        "result_preview": result[:400],
                    }
                )
                messages.append(HumanMessage(content=f"工具 {tc['name']} 返回:\n{result}"))
            if rnd >= budget.max_rounds - 1:
                break
            continue
        if require_json:
            ready = bool(parsed) and bool(
                parsed.get("done") or parsed.get("verdict") or parsed.get("findings") is not None
            )
            allow = (done_ok is None or done_ok(parsed, log)) if ready else False
            if ready and allow and calls >= min_calls:
                break
            if text.strip() and rnd >= budget.max_rounds - 1:
                break
            extra = ""
            hops = [str(x).strip() for x in ((parsed or {}).get("unresolved") or []) if str(x).strip()]
            if hops:
                extra = " 请继续跟: " + ", ".join(hops[:12])
            messages.append(HumanMessage(content=nudge + extra))
            continue
        if text.strip() and not json_tools:
            break
        if rnd >= budget.max_rounds - 1:
            break
        messages.append(HumanMessage(content=nudge))

    if not (text or "").strip():
        check_cancel(state, job_id=job_id)
        _close_open_tool_calls(messages)
        messages.append(HumanMessage(content=WRITE_NUDGE))
        try:
            msg = llm.invoke(messages)
            text = _msg_text(msg)
            parsed = _extract_json(text) or parsed
            log.append({"round": rnd + 1, "event": "final_write", "chars": len(text or "")})
        except PipelineCancelled:
            raise
        except Exception as e:
            if "tool_call" in str(e).lower():
                _close_open_tool_calls(messages)
                try:
                    msg = llm.invoke(messages)
                    text = _msg_text(msg)
                    parsed = _extract_json(text) or parsed
                    log.append({"round": rnd + 1, "event": "final_write", "chars": len(text or "")})
                except PipelineCancelled:
                    raise
                except Exception as e2:
                    log.append({"round": rnd + 1, "event": "final_write_failed", "error": str(e2)[:240]})
            else:
                log.append({"round": rnd + 1, "event": "final_write_failed", "error": str(e)[:240]})

    return LoopResult(
        text=(text or "").strip(),
        parsed=parsed,
        tool_log=log,
        calls=calls,
        rounds=min(budget.max_rounds, rnd + 1),
    )


def run_specialist(
    name: str,
    system: str,
    user: str,
    state: dict[str, Any],
    *,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """One specialist: optional whitelist tools, then free-form notes."""
    budget = budget_for(name)
    if max_tokens is not None or temperature is not None:
        budget = replace(budget, max_tokens=max_tokens if max_tokens is not None else budget.max_tokens, temperature=temperature if temperature is not None else budget.temperature)
    ctx = context_from_state(state, budget)
    if ctx is None:
        return run_agent(name, system, user, max_tokens=budget.max_tokens, temperature=budget.temperature), []
    system_text = compose_system(name, system, extra_parts=[TOOL_PREAMBLE])
    result = run_tool_loop(
        system=system_text,
        user=user,
        tools=bind_tools(ctx),
        job_id=Path(state.get("work_dir") or "").name,
        state=state,
        budget=budget,
        require_json=False,
        nudge=PIPELINE_NUDGE,
    )
    text = (result.text or "").strip()
    if not text:
        try:
            text = run_agent(
                name,
                system,
                user + "\n\n不要调用工具，直接写本职中文正文。",
                max_tokens=budget.max_tokens,
                temperature=budget.temperature,
            )
            text = (text or "").strip()
        except LLMError:
            text = ""
    if not text:
        raise LLMError(f"{name} 未返回文本")
    return text, result.tool_log
