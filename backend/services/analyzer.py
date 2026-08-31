"""Windows driver patch analysis pipeline (PE / PDB / symbols / disasm)."""
from __future__ import annotations

import bisect
import hashlib
import json
import os
import re
import shutil
import ssl
import struct
import sys
import threading
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from ..config import ANALYSIS_DIR, PDB_CACHE_DIR, TOOLS_DIR

# Bootstrap legacy analysis dependencies
for p in (str(TOOLS_DIR), str(ANALYSIS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import pefile  # noqa: E402
from capstone import (  # noqa: E402
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_64,
    Cs,
)
from capstone.x86 import X86_OP_IMM, X86_OP_MEM  # noqa: E402
from parse_pdb import Pdb, parse_dbi, parse_pub, iter_symbols, S_PUB32  # noqa: E402

_PDB_CACHE_LOCKS_GUARD = threading.Lock()
_PDB_CACHE_LOCKS: dict[str, threading.Lock] = {}


def _pdb_cache_lock(key: str) -> threading.Lock:
    with _PDB_CACHE_LOCKS_GUARD:
        return _PDB_CACHE_LOCKS.setdefault(key, threading.Lock())

CODE_SECTIONS = {".text", "PAGE", "PAGESAN", "PAGEWTDI", "PAGEWPP", "INIT", "fothk"}
# Windows forbids <>:"/\|?* in filenames; MSVC C++ symbols start with '?'.
_WIN_BAD_NAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_ASM_STEM_KEEP = re.compile(r"[^\w.\-+]+")


def asm_file_stem(name: str) -> str:
    """Safe stem for disasm/{old,new}_{stem}.asm. Keeps plain C names unchanged."""
    raw = (name or "unknown").strip() or "unknown"
    pretty = raw.lstrip("?").replace("::", "_").replace("@@", "_").replace("@", "_")
    pretty = _WIN_BAD_NAME.sub("_", pretty)
    pretty = _ASM_STEM_KEEP.sub("_", pretty)
    pretty = re.sub(r"_+", "_", pretty).strip("._") or "unknown"
    if pretty.upper() in {"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"}:
        pretty = f"_{pretty}"
    if pretty == raw and len(pretty) <= 80 and not _WIN_BAD_NAME.search(raw):
        return pretty
    digest = hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:10]
    if len(pretty) > 72:
        pretty = pretty[:72].rstrip("._") or "sym"
    return f"{pretty}_{digest}"


def disasm_relpath(side: str, name: str) -> str:
    return f"disasm/{side}_{asm_file_stem(name)}.asm"

# Soft hints only — included when the symbol exists in either build's code PDB.
# Prefer .pdata size changes + Feature xrefs + byte-diff tops as the real hotspot source.
SOFT_HOTSPOT_HINTS = [
    "AfdBind",
    "AfdUnBindSocket",
    "AfdRestartBindGetAddress",
    "AfdRestartGetAddress",
    "AfdStartNextTPacketsIrp",
]

SOFT_CONTROL_HINTS = [
    "AfdNotifyPostEvents",
    "AfdNotifySock",
    "AfdCleanupNotify",
    "AfdNotifyDestroyContext",
    "AfdNotifySockIndicateEventsUnlock",
    "AfdNotifySockEventsChangedUnderLock",
    "AfdCleanupCore",
    "AfdCloseCore",
    "AfdCleanup",
    "AfdClose",
    "AfdDereferenceEndpoint",
    "AfdReferenceEndpoint",
    "AfdAllocateEndpoint",
    "AfdFreeEndpoint",
    "AfdSanConnectHandler",
    "AfdSanAcceptCore",
    "AfdSanCleanupHelper",
    "AfdRioDeregisterBuffer",
    "AfdRioCleanupBufferCache",
    "AfdRioCleanupRioState",
    "AfdLockEndpointContext",
    "AfdUnlockEndpointContext",
    "AfdAcquireWriteLock",
    "AfdReleaseWriteLock",
    "AfdTdiValidateDeviceNameUnderLock",
    "AfdTdiValidateTransportFileObject",
    "AfdDerefTLBaseEndpoint",
    "AfdDereferenceTransport",
    "AfdDeleteConnectedReference",
    "AfdInsertNewEndpointInList",
    "AfdRemoveEndpointFromList",
]

# Back-compat aliases for older imports / scripts
BIND_HOTSPOT_NAMES = SOFT_HOTSPOT_HINTS
CONTROL_FUNCTION_NAMES = SOFT_CONTROL_HINTS


def select_hotspot_names(
    symbol_diff: dict[str, Any],
    *,
    byte_diff: dict[str, Any] | None = None,
    feature_trace: dict[str, Any] | None = None,
    extra_hints: list[str] | None = None,
    max_hotspots: int = 16,
) -> list[str]:
    """Pick functions to disassemble / CFG. Feature xrefs are forced in; rest by |Δsize|."""
    from .pipeline import plan_hotspots

    hints = list(extra_hints or [])
    known = set(symbol_diff.get("code_symbols") or [])
    for hint in SOFT_HOTSPOT_HINTS:
        if hint not in hints and (not known or hint in known):
            hints.append(hint)
    plan = plan_hotspots(
        symbol_diff,
        byte_diff=byte_diff,
        feature_trace=feature_trace,
        extra_names=hints,
        max_hotspots=max_hotspots,
    )
    return list(plan.get("selected") or [])


def select_control_names(
    symbol_diff: dict[str, Any],
    hotspot_names: list[str] | None = None,
    *,
    max_controls: int = 24,
) -> list[str]:
    """Unchanged peers for exclusion analysis — soft hints if present, else same-prefix unchanged."""
    known = set(symbol_diff.get("code_symbols") or [])
    resized = {f["name"] for f in (symbol_diff.get("functions_resized") or []) if f.get("name")}
    hot = set(hotspot_names or [])
    controls: list[str] = []

    for hint in SOFT_CONTROL_HINTS:
        if hint in known and hint not in resized:
            controls.append(hint)

    if len(controls) < 8 and known:
        prefixes: list[str] = []
        for n in list(resized)[:5] or list(hot)[:5]:
            m = re.match(r"^([A-Z][a-z]+|[A-Z]{2,})", n or "")
            if m:
                prefixes.append(m.group(1))
        prefixes = list(dict.fromkeys(prefixes))
        keywords = ("Notify", "Cleanup", "Lock", "Close", "Free", "Release", "Destroy", "Deref")
        candidates = []
        for n in known:
            if n in resized or n in hot or n in controls:
                continue
            if prefixes and not any(n.startswith(p) for p in prefixes):
                continue
            score = 0 if any(k in n for k in keywords) else 1
            candidates.append((score, len(n), n))
        candidates.sort()
        for _, _, n in candidates:
            controls.append(n)
            if len(controls) >= max_controls:
                break

    return controls[:max_controls]


def extract_pe(path: str | Path) -> dict[str, Any]:
    """Extract PE metadata (adapted from analysis/extract_pe.py)."""
    path = str(path)
    pe = pefile.PE(path, fast_load=False)
    from datetime import datetime, timezone

    ts = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc).isoformat()
    info: dict[str, Any] = {
        "path": path,
        "size": os.path.getsize(path),
        "machine": {0x8664: "AMD64", 0x14C: "I386"}.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
        "timestamp_utc": ts,
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
        "sections": [],
        "debug": [],
        "imports": {},
        "exports": [],
        "original_filename": Path(path).name,
        "file_version": "",
        "machine_id": pe.FILE_HEADER.Machine,
        "pe_timestamp": pe.FILE_HEADER.TimeDateStamp,
    }
    try:
        raw = Path(path).read_bytes()
        info["md5"] = hashlib.md5(raw).hexdigest()
        info["sha1"] = hashlib.sha1(raw).hexdigest()
        info["sha256"] = hashlib.sha256(raw).hexdigest()
    except OSError:
        pass
    try:
        if hasattr(pe, "FileInfo") and pe.FileInfo:
            for fileinfo in pe.FileInfo:
                for st in fileinfo:
                    if not hasattr(st, "StringTable"):
                        continue
                    for row in st.StringTable:
                        entries = {
                            (k.decode() if isinstance(k, bytes) else str(k)): (
                                v.decode() if isinstance(v, bytes) else str(v)
                            )
                            for k, v in row.entries.items()
                        }
                        if entries.get("OriginalFilename"):
                            info["original_filename"] = entries["OriginalFilename"].strip()
                        if entries.get("FileVersion"):
                            info["file_version"] = entries["FileVersion"].split()[0]
    except Exception:
        pass
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        info["sections"].append(
            {
                "name": name,
                "virtual_address": hex(s.VirtualAddress),
                "virtual_size": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData,
            }
        )
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            entry = dbg.struct
            d: dict[str, Any] = {"type": entry.Type, "timestamp": entry.TimeDateStamp}
            raw = None
            if entry.PointerToRawData and entry.SizeOfData:
                raw = pe.__data__[entry.PointerToRawData : entry.PointerToRawData + entry.SizeOfData]
            if raw and entry.Type == 2 and len(raw) >= 24 and raw[:4] == b"RSDS":
                guid_bytes = raw[4:20]
                age = int.from_bytes(raw[20:24], "little")
                pdb_path = raw[24:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                d1 = int.from_bytes(guid_bytes[0:4], "little")
                d2 = int.from_bytes(guid_bytes[4:6], "little")
                d3 = int.from_bytes(guid_bytes[6:8], "little")
                d4 = guid_bytes[8:16]
                guid_compact = f"{d1:08X}{d2:04X}{d3:04X}{d4.hex().upper()}"
                pdb_name = os.path.basename(pdb_path.replace("\\", "/"))
                d.update(
                    {
                        "pdb_filename": pdb_name,
                        "guid_compact": guid_compact,
                        "age": age,
                        "symbol_url": f"https://msdl.microsoft.com/download/symbols/{pdb_name}/{guid_compact}{age}/{pdb_name}",
                    }
                )
            info["debug"].append(d)
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace")
            info["imports"][dll] = len(entry.imports)
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.name:
                continue
            name = exp.name.decode() if isinstance(exp.name, bytes) else str(exp.name)
            info["exports"].append({"name": name, "rva": hex(int(exp.address or 0))})
    pe.close()
    return info


def pe_import_table(sys_path: Path, *, per_dll: int = 48) -> dict[str, list[str]]:
    """Import DLL → function names. Used to follow a call into another module."""
    pe = pefile.PE(str(sys_path))
    out: dict[str, list[str]] = {}
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return out
        cap = max(4, min(int(per_dll or 48), 80))
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace") if entry.dll else ""
            if not dll:
                continue
            names: list[str] = []
            for imp in entry.imports or []:
                if imp.name:
                    names.append(imp.name.decode() if isinstance(imp.name, bytes) else str(imp.name))
                elif imp.ordinal is not None:
                    names.append(f"ord{imp.ordinal}")
                if len(names) >= cap:
                    break
            out[dll] = names
    finally:
        pe.close()
    return out


def download_pdb(symbol_url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = Request(symbol_url, headers={"User-Agent": "Microsoft-Symbol-Server/10.0"})
    with urlopen(req, context=ssl.create_default_context(), timeout=120) as resp:
        data = resp.read()
    dest.write_bytes(data)
    return dest


def _section_map(pe) -> dict[int, dict]:
    m = {}
    for i, s in enumerate(pe.sections, start=1):
        name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        m[i] = {
            "name": name,
            "va": s.VirtualAddress,
            "is_code": bool(s.Characteristics & 0x20) or name in CODE_SECTIONS,
        }
    return m


def _read_pdata(pe) -> list[dict]:
    funcs = []
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") != b".pdata":
            continue
        data = s.get_data()[: s.Misc_VirtualSize]
        for off in range(0, len(data) - 11, 12):
            begin, end, unwind = struct.unpack_from("<III", data, off)
            if begin and end > begin:
                funcs.append({"begin": begin, "end": end, "size": end - begin, "unwind": unwind})
        break
    funcs.sort(key=lambda x: x["begin"])
    return funcs


def _publics_from_pdb(pdb_path: str) -> tuple[list, list, dict]:
    pdb = Pdb(pdb_path)
    info, procs, publics, _ = parse_dbi(pdb)
    names: dict[str, dict] = {}
    for p in publics:
        names[p["name"]] = p
    for st in pdb.streams:
        if not st:
            continue
        try:
            for kind, payload in iter_symbols(st, 0):
                if kind == S_PUB32:
                    pub = parse_pub(payload)
                    if pub and pub["name"]:
                        names[pub["name"]] = pub
        except Exception:
            continue
    return list(names.values()), procs, info


def _attach_rva(symbols, segmap):
    out = []
    for s in symbols:
        info = segmap.get(s.get("segment"))
        if not info:
            continue
        item = dict(s)
        item["rva"] = info["va"] + s["offset"]
        item["section"] = info["name"]
        item["is_code"] = info["is_code"]
        out.append(item)
    return out


def _map_to_pdata(code_syms, pdata):
    by_rva: dict[int, list] = {}
    for s in code_syms:
        by_rva.setdefault(s["rva"], []).append(s)
    named = []
    for fn in pdata:
        cands = by_rva.get(fn["begin"], [])
        name = None
        if cands:
            pref = [c for c in cands if not c["name"].startswith("$")]
            name = (pref or cands)[0]["name"]
        named.append({**fn, "name": name})
    return named


def compare_symbols(old_sys: Path, new_sys: Path, old_pdb: Path | str | None, new_pdb: Path | str | None) -> dict[str, Any]:
    fn_old, pd_old, info_old, q_old = _named_from_sys(old_sys, old_pdb)
    fn_new, pd_new, info_new, q_new = _named_from_sys(new_sys, new_pdb)

    names_old = {f["name"] for f in fn_old if f.get("name")}
    names_new = {f["name"] for f in fn_new if f.get("name")}
    size_old = {f["name"]: f["size"] for f in fn_old if f.get("name")}
    size_new = {f["name"]: f["size"] for f in fn_new if f.get("name")}
    rva_old = {f["name"]: f["begin"] for f in fn_old if f.get("name")}
    rva_new = {f["name"]: f["begin"] for f in fn_new if f.get("name")}

    resized = []
    for n in sorted(set(size_old) & set(size_new)):
        if size_old[n] != size_new[n]:
            resized.append(
                {
                    "name": n,
                    "old": size_old[n],
                    "new": size_new[n],
                    "delta": size_new[n] - size_old[n],
                    "old_rva": hex(rva_old.get(n, 0)),
                    "new_rva": hex(rva_new.get(n, 0)),
                }
            )

    only_old = names_old - names_new
    only_new = names_new - names_old
    used_new: set[str] = set()
    renames: list[dict[str, Any]] = []
    for on in sorted(only_old):
        best = None
        best_score = 1e18
        so = size_old.get(on) or 0
        if so <= 0:
            continue
        for nn in only_new:
            if nn in used_new:
                continue
            sn = size_new.get(nn) or 0
            rel = abs(so - sn) / so
            rva_d = abs((rva_old.get(on) or 0) - (rva_new.get(nn) or 0))
            score = rel * 10000 + rva_d / 32
            if rel <= 0.3 and score < best_score:
                best, best_score = nn, score
        if not best:
            continue
        used_new.add(best)
        delta = size_new[best] - so
        renames.append({"old": on, "new": best, "old_size": so, "new_size": size_new[best], "delta": delta})
        if delta:
            resized.append(
                {
                    "name": best,
                    "old": so,
                    "new": size_new[best],
                    "delta": delta,
                    "old_rva": hex(rva_old.get(on, 0)),
                    "new_rva": hex(rva_new.get(best, 0)),
                    "renamed_from": on,
                }
            )
    resized.sort(key=lambda x: abs(x["delta"]), reverse=True)
    quality = "pdb" if q_old == "pdb" and q_new == "pdb" else "heuristic"

    return {
        "old": {"publics": len(names_old), "pdata_funcs": len(pd_old), "pdb_info": info_old},
        "new": {"publics": len(names_new), "pdata_funcs": len(pd_new), "pdb_info": info_new},
        "symbols_added": sorted(names_new - names_old - used_new),
        "symbols_removed": sorted(only_old - {r["old"] for r in renames}),
        "functions_resized": resized,
        "feature_symbols_added": [n for n in sorted(names_new - names_old) if n.startswith("Feature_")],
        "code_symbols": sorted(set(size_old) | set(size_new)),
        "quality": quality,
        "pdb_quality": {"old": q_old, "new": q_new},
        "renames": renames,
    }


def _iat_map(pe):
    m = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return m
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.address:
                rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                m[rva] = imp.name.decode() if imp.name else f"ord{imp.ordinal}"
    return m


def _intern_by_rva(pubs, sm):
    m = {}
    for name, p in ((x["name"], x) for x in pubs if "name" in x):
        seg = p.get("segment") if isinstance(p, dict) else p["segment"]
        off = p.get("offset") if isinstance(p, dict) else p["offset"]
        va = sm.get(seg)
        if va is not None:
            m[va + off] = name
    return m


def pdb_ok(path: str | Path | None) -> bool:
    try:
        p = Path(path) if path else None
        return bool(p and p.exists() and p.stat().st_size > 1024)
    except OSError:
        return False


def pdb_cache_file(pe_info: dict[str, Any]) -> Path | None:
    for d in pe_info.get("debug") or []:
        guid = d.get("guid_compact")
        age = d.get("age")
        name = d.get("pdb_filename")
        if guid and name:
            return PDB_CACHE_DIR / f"{guid}{age}" / name
    return None


def _exports_by_rva(pe) -> dict[int, str]:
    out: dict[int, str] = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT") or not pe.DIRECTORY_ENTRY_EXPORT:
        return out
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name and exp.address:
            name = exp.name.decode() if isinstance(exp.name, bytes) else str(exp.name)
            out[int(exp.address)] = name
    return out


def _heuristic_named(pe) -> list[dict]:
    named = []
    exports = _exports_by_rva(pe)
    for f in _read_pdata(pe):
        name = exports.get(f["begin"]) or f"sub_{f['begin']:08X}"
        named.append({**f, "name": name})
    return named


def _named_from_sys(sys_path: Path, pdb_path: Path | str | None) -> tuple[list[dict], list[dict], dict, str]:
    pe = pefile.PE(str(sys_path))
    pdata = _read_pdata(pe)
    info: dict[str, Any] = {}
    try:
        if pdb_ok(pdb_path):
            pubs, _, info = _publics_from_pdb(str(pdb_path))
            attached = _attach_rva(pubs, _section_map(pe))
            named = [f for f in _map_to_pdata([p for p in attached if p.get("is_code")], pdata) if f.get("name")]
            if named:
                pe.close()
                return named, pdata, info, "pdb"
        named = _heuristic_named(pe)
        pe.close()
        return named, pdata, info, "heuristic"
    except Exception:
        named = _heuristic_named(pe)
        pe.close()
        return named, pdata, info, "heuristic"


def pdb_url_and_name(pe_info: dict[str, Any]) -> tuple[str, str]:
    url = next((d["symbol_url"] for d in pe_info.get("debug", []) if "symbol_url" in d), None)
    name = next((d["pdb_filename"] for d in pe_info.get("debug", []) if "pdb_filename" in d), None)
    if not url or not name:
        raise ValueError("PE 缺少 PDB CodeView 信息")
    return url, name


def fetch_pdb(pe_info: dict[str, Any], dest: Path, retries: int = 2) -> Path:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    cache = pdb_cache_file(pe_info)
    lock_key = str(cache or dest)
    with _pdb_cache_lock(lock_key):
        if cache and cache.exists() and cache.stat().st_size > 1024:
            if not dest.exists() or dest.stat().st_size < 1024:
                shutil.copy2(cache, dest)
            return dest
        if dest.exists() and dest.stat().st_size > 1024:
            if cache:
                cache.parent.mkdir(parents=True, exist_ok=True)
                if not cache.exists():
                    shutil.copy2(dest, cache)
            return dest
        url, _ = pdb_url_and_name(pe_info)
        last: Exception | None = None
        for _ in range(max(1, retries + 1)):
            try:
                download_pdb(url, dest)
                if dest.stat().st_size > 1024:
                    if cache:
                        cache.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(dest, cache)
                    return dest
            except Exception as e:
                last = e
        if last:
            raise last
        raise ValueError("PDB 下载失败")


def named_function_sizes(sys_path: Path, pdb_path: Path | str | None) -> dict[str, dict[str, Any]]:
    """.pdata sizes + RVA; falls back to export / sub_RVA names when PDB is missing."""
    named, _, _, _ = _named_from_sys(sys_path, pdb_path)
    return {f["name"]: {"size": f["size"], "rva": f["begin"]} for f in named if f.get("name")}


def size_timeline(
    samples: list[tuple[str, Path, Path]],
    names: list[str],
) -> dict[str, Any]:
    """Compare named function sizes across 2–3 builds (8875 / 8972 / 9168 style)."""
    all_sizes: dict[str, dict[str, int]] = {}
    rvas: dict[str, dict[str, str]] = {}
    for label, sys_path, pdb_path in samples:
        m = named_function_sizes(sys_path, pdb_path)
        all_sizes[label] = {n: m[n]["size"] for n in m}
        rvas[label] = {n: hex(m[n]["rva"]) for n in m}
    rows = []
    for n in names:
        row = {"name": n}
        vals = []
        for label, _, _ in samples:
            sz = all_sizes.get(label, {}).get(n)
            row[label] = sz if sz is not None else None
            row[f"{label}_rva"] = rvas.get(label, {}).get(n)
            if sz is not None:
                vals.append(sz)
        row["unchanged_across_samples"] = len(set(vals)) <= 1 if vals else True
        rows.append(row)
    return {
        "labels": [s[0] for s in samples],
        "rows": rows,
    }


def _intern_names(pe, pdb_path: Path | str | None) -> dict[int, str]:
    intern: dict[int, str] = {}
    if pdb_ok(pdb_path):
        try:
            for p in _attach_rva(_publics_from_pdb(str(pdb_path))[0], _section_map(pe)):
                if p.get("rva") is not None and p.get("name"):
                    intern[p["rva"]] = p["name"]
            if intern:
                return intern
        except Exception:
            intern = {}
    for f in _heuristic_named(pe):
        intern[f["begin"]] = f["name"]
    return intern


def _pdata_func_at(pdata: list[dict[str, Any]]):
    """O(log n) containing-function lookup with last-hit cache (ntoskrnl .pdata is huge)."""
    lookup = _pdata_lookup(pdata)
    size_at = {int(f["begin"]): int(f["size"]) for f in pdata if f.get("begin") is not None and f.get("size") is not None}
    end_at = {int(f["begin"]): int(f["end"]) for f in pdata if f.get("begin") is not None and f.get("end") is not None}
    last = [None, None, None]  # begin, end, size

    def at(rva: int):
        if last[0] is not None and last[0] <= rva < last[1]:
            return last[0], last[2]
        begin = lookup(rva)
        if begin is None:
            last[0] = last[1] = last[2] = None
            return None, None
        size = size_at.get(begin)
        last[0] = begin
        last[1] = end_at.get(begin, begin + (size or 0))
        last[2] = size
        return begin, size

    return at


def byte_diff_code(old_sys: Path, new_sys: Path, old_pdb: Path | str | None, new_pdb: Path | str | None) -> dict[str, Any]:
    """Code-section byte diff (analysis/byte_diff.py), summarized; relocation-noisy."""
    pe_old = pefile.PE(str(old_sys))
    pe_new = pefile.PE(str(new_sys))
    names_old = _intern_names(pe_old, old_pdb)
    at_old = _pdata_func_at(_read_pdata(pe_old))
    at_new = _pdata_func_at(_read_pdata(pe_new))
    chunk = 8192

    changed_funcs: dict = {}
    total = 0
    for s_old, s_new in zip(pe_old.sections, pe_new.sections):
        n_old = s_old.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        n_new = s_new.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        if n_old != n_new or not (s_old.Characteristics & 0x20):
            continue
        va = s_old.VirtualAddress
        d_old = s_old.get_data()[: s_old.Misc_VirtualSize]
        d_new = s_new.get_data()[: s_new.Misc_VirtualSize]
        lim = min(len(d_old), len(d_new))
        vo, vn = memoryview(d_old), memoryview(d_new)
        i = 0
        while i < lim:
            end = min(i + chunk, lim)
            if vo[i:end] == vn[i:end]:
                i = end
                continue
            while i < end and vo[i] == vn[i]:
                i += 1
            start = i
            while i < lim and vo[i] != vn[i]:
                i += 1
            rva = va + start
            length = i - start
            total += length
            b_old, sz_old = at_old(rva)
            b_new, sz_new = at_new(rva)
            key = b_old if b_old else (b_new or rva)
            rec = changed_funcs.setdefault(
                key,
                {
                    "label": names_old.get(b_old) or names_old.get(b_new) or f"rva_{rva:X}",
                    "rva_old": hex(b_old) if b_old else None,
                    "size_old": sz_old,
                    "rva_new": hex(b_new) if b_new else None,
                    "size_new": sz_new,
                    "patch_bytes": 0,
                },
            )
            rec["patch_bytes"] += length
    pe_old.close()
    pe_new.close()
    items = sorted(changed_funcs.values(), key=lambda x: x["patch_bytes"], reverse=True)
    return {
        "total_bytes": total,
        "functions_with_byte_changes": len(items),
        "note": "含 RIP 相对重定位噪声；补丁归因以 .pdata 尺寸变化为准。",
        "top": items[:40],
    }


def write_disasm_files(work_dir: Path, blocks: list[dict[str, Any]], prefix_map: tuple[str, str] = ("old", "new")) -> None:
    dump = work_dir / "disasm"
    dump.mkdir(parents=True, exist_ok=True)
    for block in blocks:
        name = block.get("name") or "unknown"
        stem = asm_file_stem(name)
        for side, key in (("old", prefix_map[0]), ("new", prefix_map[1])):
            d = block.get(side)
            if not d or not d.get("disasm"):
                continue
            (dump / f"{key}_{stem}.asm").write_text("\n".join(d["disasm"]), encoding="utf-8")


def _pdata_lookup(pdata: list[dict[str, Any]]):
    ranges = sorted((int(f["begin"]), int(f["end"])) for f in pdata if f.get("end") is not None)
    begins = [r[0] for r in ranges]

    def lookup(rva: int) -> int | None:
        i = bisect.bisect_right(begins, rva) - 1
        if i >= 0 and ranges[i][0] <= rva < ranges[i][1]:
            return ranges[i][0]
        return None

    return lookup


def _call_target_names(insn, iat: dict[int, str], intern: dict[int, str], pdata_at) -> list[str]:
    """Resolve CALL targets: rel32, RIP-relative IAT, and containing .pdata function."""
    if insn.mnemonic != "call":
        return []
    names: list[str] = []

    def resolve(target: int) -> str | None:
        n = iat.get(target) or intern.get(target)
        if n:
            return n
        begin = pdata_at(target) if pdata_at else None
        if begin is not None:
            return intern.get(begin)
        return None

    for op in getattr(insn, "operands", None) or []:
        target = None
        if op.type == X86_OP_IMM:
            target = int(op.imm)
        elif op.type == X86_OP_MEM:
            try:
                base = insn.reg_name(op.mem.base) if op.mem.base else ""
            except Exception:
                base = ""
            if base == "rip":
                target = int(insn.address) + int(insn.size) + int(op.mem.disp)
        if target is None:
            continue
        n = resolve(target)
        if n:
            names.append(n)
    if not names and insn.disp and "rip" in (insn.op_str or ""):
        n = resolve(int(insn.address) + int(insn.size) + int(insn.disp))
        if n:
            names.append(n)
    return names


def disassemble_functions(
    old_sys: Path,
    new_sys: Path,
    old_pdb: Path,
    new_pdb: Path,
    function_names: list[str],
    max_lines: int | None = None,
) -> list[dict[str, Any]]:
    results = []

    def disasm_one(sys_path: Path, pdb_path: Path | str | None, name: str, label: str) -> dict | None:
        pe = pefile.PE(str(sys_path))
        pdata = _read_pdata(pe)
        intern = _intern_names(pe, pdb_path)
        rva = next((addr for addr, n in intern.items() if n == name), None)
        if rva is None and pdb_ok(pdb_path):
            try:
                sm = {i + 1: s.VirtualAddress for i, s in enumerate(pe.sections)}
                pubs, _, _ = _publics_from_pdb(str(pdb_path))
                pub = next((p for p in pubs if p["name"] == name), None)
                if pub and pub.get("segment") in sm:
                    rva = sm[pub["segment"]] + pub["offset"]
            except Exception:
                rva = None
        if rva is None:
            pe.close()
            return None
        size = next((f["size"] for f in pdata if f["begin"] == rva), 0x400)
        if size <= 0 or size > 0x8000:
            size = min(max(size, 0x40), 0x2000)
        iat = _iat_map(pe)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        pdata_at = _pdata_lookup(pdata)
        lines = []
        calls = []
        for insn in md.disasm(pe.get_data(rva, size), rva):
            lines.append(f"{insn.address:08x}  {insn.mnemonic:8} {insn.op_str}")
            calls.extend(_call_target_names(insn, iat, intern, pdata_at))
        pe.close()
        return {
            "label": label,
            "name": name,
            "rva": hex(rva),
            "size": size,
            "calls": list(dict.fromkeys(calls)),
            "disasm": lines if max_lines is None else lines[:max_lines],
            "truncated": False if max_lines is None else len(lines) > max_lines,
        }

    for name in function_names:
        old_d = disasm_one(old_sys, old_pdb, name, "old")
        new_d = disasm_one(new_sys, new_pdb, name, "new")
        added_calls = sorted(set(new_d["calls"] if new_d else []) - set(old_d["calls"] if old_d else []))
        removed_calls = sorted(set(old_d["calls"] if old_d else []) - set(new_d["calls"] if new_d else []))
        results.append(
            {
                "name": name,
                "old": old_d,
                "new": new_d,
                "calls_added": added_calls,
                "calls_removed": removed_calls,
            }
        )
    return results


_CFG_INTEREST = (
    "spinlock",
    "lock",
    "free",
    "feature",
    "tdicopy",
    "acquire",
    "release",
    "cmpxchg",
    "xchg",
    "0xf0",
    "0xec",
    "0x38",
)


def _basic_blocks(image: bytes, rva: int, size: int) -> list[dict[str, Any]]:
    from capstone.x86 import X86_OP_IMM

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(image[rva : rva + size], rva))
    if not insns:
        return []
    leaders = {insns[0].address}
    for ins in insns:
        if ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL) or ins.group(CS_GRP_RET):
            if ins.group(CS_GRP_JUMP) and ins.operands and ins.operands[0].type == X86_OP_IMM:
                tgt = ins.operands[0].imm
                if rva <= tgt < rva + size:
                    leaders.add(tgt)
            nxt = ins.address + ins.size
            if nxt < rva + size:
                leaders.add(nxt)
    leaders = sorted(leaders)
    blocks = []
    for i, start in enumerate(leaders):
        end = leaders[i + 1] if i + 1 < len(leaders) else rva + size
        lines, hot = [], False
        for ins in insns:
            if start <= ins.address < end:
                line = f"{ins.address:08x}  {ins.mnemonic:8} {ins.op_str}"
                if any(k in line.lower() for k in _CFG_INTEREST):
                    hot = True
                lines.append(line)
        if lines:
            blocks.append({"start": hex(start), "lines": lines, "hot": hot})
    return blocks


def cfg_diff_functions(
    old_sys: Path,
    new_sys: Path,
    old_pdb: Path,
    new_pdb: Path,
    function_names: list[str],
) -> dict[str, Any]:
    """Capstone basic-block side-by-side diff (BinDiff-style view without IDA)."""
    pe_old = pefile.PE(str(old_sys))
    pe_new = pefile.PE(str(new_sys))
    img_old = pe_old.get_memory_mapped_image()
    img_new = pe_new.get_memory_mapped_image()
    sizes_old = named_function_sizes(old_sys, old_pdb)
    sizes_new = named_function_sizes(new_sys, new_pdb)
    funcs = []
    for name in function_names:
        o, n = sizes_old.get(name), sizes_new.get(name)
        if not o and not n:
            funcs.append({"name": name, "error": "missing symbol"})
            continue
        old_blocks = _basic_blocks(img_old, o["rva"], o["size"]) if o else []
        new_blocks = _basic_blocks(img_new, n["rva"], n["size"]) if n else []
        funcs.append(
            {
                "name": name,
                "old": {
                    "rva": hex(o["rva"]) if o else None,
                    "size": o["size"] if o else None,
                    "blocks": len(old_blocks),
                    "hot_blocks": sum(1 for b in old_blocks if b["hot"]),
                },
                "new": {
                    "rva": hex(n["rva"]) if n else None,
                    "size": n["size"] if n else None,
                    "blocks": len(new_blocks),
                    "hot_blocks": sum(1 for b in new_blocks if b["hot"]),
                },
                "delta_size": ((n["size"] if n else 0) - (o["size"] if o else 0)),
                "old_blocks": old_blocks,
                "new_blocks": new_blocks,
            }
        )
    pe_old.close()
    pe_new.close()
    return {
        "note": "Capstone 基本块划分；橙色热点含 lock/Feature/pool/TdiCopy。完整 BinDiff 需 IDA。",
        "functions": funcs,
    }


def _rip_xrefs(text: bytes, base: int, targets: set[int]) -> list[dict[str, Any]]:
    hits = []
    for off in range(len(text) - 6):
        for op_len in (6, 7):
            if op_len == 7:
                if text[off] != 0x48 or text[off + 1] not in (0x8B, 0x89, 0x8D):
                    continue
                mod = text[off + 2]
                disp_off = 3
            else:
                if text[off] not in (0x8B, 0x89, 0x3B, 0x8D):
                    continue
                mod = text[off + 1]
                disp_off = 2
            if mod not in (0x05, 0x0D, 0x15, 0x1D, 0x35, 0x3D):
                continue
            disp = struct.unpack_from("<i", text, off + disp_off)[0]
            insn_rva = base + off
            tgt = insn_rva + op_len + disp
            if tgt in targets:
                hits.append({"rva": hex(insn_rva), "target": hex(tgt), "bytes": text[off : off + op_len].hex()})
    return hits


def _disasm_slice(image: bytes, rva: int, size: int = 0x70) -> list[str]:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    return [f"{i.address:08x}  {i.mnemonic:8} {i.op_str}" for i in md.disasm(image[rva : rva + size], rva)]


def trace_feature_symbols(new_sys: Path, new_pdb: Path, symbol_diff: dict[str, Any]) -> dict[str, Any]:
    """Trace Feature_*__private_featureState on the patched binary (WIL enable bits)."""
    added = [n for n in (symbol_diff.get("feature_symbols_added") or []) if n.startswith("Feature_")]
    groups: dict[str, list[str]] = {}
    for n in added:
        m = re.match(r"Feature_(\d+)", n)
        fid = m.group(1) if m else n
        groups.setdefault(fid, []).append(n)

    pe = pefile.PE(str(new_sys))
    image = pe.get_memory_mapped_image()
    sm = _section_map(pe)
    attached = {p["name"]: p for p in _attach_rva(_publics_from_pdb(str(new_pdb))[0], sm)}
    text_sec = next((s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"), None)
    text = text_sec.get_data() if text_sec else b""
    text_base = text_sec.VirtualAddress if text_sec else 0
    sizes = named_function_sizes(new_sys, new_pdb)

    def owner(rva_hex: str) -> str:
        rva = int(rva_hex, 16)
        best = ""
        best_begin = -1
        for name, meta in sizes.items():
            begin, end = meta["rva"], meta["rva"] + meta["size"]
            if begin <= rva < end and begin > best_begin:
                best, best_begin = name, begin
        return best

    features = []
    for fid, names in sorted(groups.items()):
        state_name = f"Feature_{fid}__private_featureState"
        desc_name = f"Feature_{fid}__private_descriptor"
        en_name = f"Feature_{fid}__private_IsEnabledDeviceUsageNoInline"
        state = attached.get(state_name)
        desc = attached.get(desc_name)
        en = attached.get(en_name)
        targets = set()
        if state:
            targets.add(state["rva"])
        if desc:
            targets.add(desc["rva"])
        xrefs = _rip_xrefs(text, text_base, targets) if targets else []
        for x in xrefs:
            x["in_function"] = owner(x["rva"])
        on_disk = None
        if state:
            on_disk = struct.unpack_from("<I", image, state["rva"])[0]
        en_disasm = _disasm_slice(image, en["rva"]) if en else []
        cached_bit = any("0x10" in ln and "test" in ln for ln in en_disasm)
        enable_and = any("eax, 1" in ln or "eax,1" in ln for ln in en_disasm)
        features.append(
            {
                "feature_id": fid,
                "symbols": names,
                "featureState_rva": hex(state["rva"]) if state else None,
                "descriptor_rva": hex(desc["rva"]) if desc else None,
                "isEnabled_rva": hex(en["rva"]) if en else None,
                "on_disk_dword": on_disk,
                "xrefs": xrefs,
                "isEnabled_disasm": en_disasm,
                "enable_semantics": {
                    "cached_valid_bit": "0x10" if cached_bit else "unknown",
                    "enabled_bit": "0x1" if enable_and else "unknown",
                    "fast_path": "test al, 0x10 / and eax, 1" if cached_bit else None,
                },
                "default_note": (
                    "映像内 featureState 通常为 0；首次检查走 RtlQueryFeatureConfiguration。"
                    "安全补丁 Feature 生产环境预期 Enabled；动态确认 WinDbg: "
                    f"dd poi(<mod>!{state_name}) L1 — 常见 0x11 (cached+enabled)。"
                ),
            }
        )
    pe.close()
    return {
        "count": len(features),
        "features": features,
        "windbg_hint": "lm m <driver>; x <driver>!Feature_*__private_featureState",
    }


def write_cfg_html(work_dir: Path, cfg: dict[str, Any], old_label: str, new_label: str) -> Path:
    import html as html_mod

    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>CFG Diff</title>",
        "<style>body{font-family:Consolas,monospace;background:#1e1e1e;color:#ddd;margin:1rem}",
        "h1,h2{color:#4fc3f7}.row{display:flex;gap:8px;margin-bottom:8px}",
        ".block{flex:1;background:#2d2d2d;border:1px solid #444;border-radius:4px;overflow:auto;max-height:280px}",
        ".block.hot{border-color:#ff9800}.hdr{background:#333;padding:4px 8px;font-size:12px}",
        "pre{margin:0;padding:8px;font-size:11px;white-space:pre-wrap}.hot pre{background:#3a2a1a}",
        "nav a{color:#81c784;margin-right:1rem}</style></head><body>",
        "<h1>函数基本块 Diff</h1><p>",
        html_mod.escape(cfg.get("note") or ""),
        "</p><nav>",
    ]
    for fn in cfg.get("functions") or []:
        if fn.get("name"):
            parts.append(f"<a href='#{html_mod.escape(fn['name'])}'>{html_mod.escape(fn['name'])}</a>")
    parts.append("</nav>")
    for fn in cfg.get("functions") or []:
        name = fn.get("name") or "?"
        parts.append(f"<section id='{html_mod.escape(name)}'><h2>{html_mod.escape(name)}</h2>")
        o, n = fn.get("old") or {}, fn.get("new") or {}
        parts.append(
            f"<p>{html_mod.escape(old_label)} {o.get('rva')} size={o.get('size')} "
            f"({o.get('blocks')} blocks) → {html_mod.escape(new_label)} {n.get('rva')} "
            f"size={n.get('size')} ({n.get('blocks')} blocks) Δ{fn.get('delta_size')}</p>"
        )
        ob, nb = fn.get("old_blocks") or [], fn.get("new_blocks") or []
        for i in range(max(len(ob), len(nb))):
            def cell(b, side):
                if not b:
                    return "<div class='block'><div class='hdr'>—</div></div>"
                cls = "block hot" if b.get("hot") else "block"
                body = html_mod.escape("\n".join(b.get("lines") or []))
                return f"<div class='{cls}'><div class='hdr'>{side} @ {b.get('start')}</div><pre>{body}</pre></div>"
            left = cell(ob[i] if i < len(ob) else None, old_label)
            right = cell(nb[i] if i < len(nb) else None, new_label)
            parts.append(f"<div class='row'>{left}{right}</div>")
        parts.append("</section>")
    parts.append("</body></html>")
    path = work_dir / "cfg_diff.html"
    path.write_text("".join(parts), encoding="utf-8")
    return path


def _verify_driver_name(pe: dict[str, Any] | None, fallback: str = "driver.sys") -> str:
    raw = ""
    if isinstance(pe, dict):
        raw = str(pe.get("original_filename") or "")
        if not raw and pe.get("path"):
            raw = Path(str(pe["path"])).name
    name = Path(raw).name.strip() or fallback
    if "." not in name:
        name += ".sys"
    if not re.match(r"^[\w.\-]+\.sys$", name, re.I):
        return fallback
    return name


def write_verify_pack(
    work_dir: Path,
    title: str,
    driver_hint: str = "",
    *,
    old_pe: dict[str, Any] | None = None,
    new_pe: dict[str, Any] | None = None,
    feature_trace: dict[str, Any] | None = None,
    disassembly: list | None = None,
    hotspot_names: list | None = None,
) -> dict[str, Any]:
    """Write isolated-VM Driver Verifier + WinDbg checklists. Never executed by the server."""
    verify = work_dir / "verify"
    verify.mkdir(parents=True, exist_ok=True)
    old_pe = old_pe or {}
    new_pe = new_pe or {}
    driver = _verify_driver_name(old_pe or new_pe, driver_hint or "driver.sys")
    module = re.sub(r"\.sys$", "", driver, flags=re.I).lower() or "driver"
    old_ver = str((old_pe or {}).get("file_version") or "")
    new_ver = str((new_pe or {}).get("file_version") or "")
    names = [n for n in (hotspot_names or []) if n][:8]
    if not names:
        names = [b.get("name") for b in (disassembly or []) if b.get("name")][:8]
    by_name = {b.get("name"): b for b in (disassembly or []) if b.get("name")}
    hotspots = []
    for name in names:
        b = by_name.get(name) or {}
        o, n = b.get("old") or {}, b.get("new") or {}
        hotspots.append({
            "name": name,
            "old_rva": o.get("rva"),
            "new_rva": n.get("rva"),
            "old_size": o.get("size"),
            "new_size": n.get("size"),
        })
    features = []
    for f in (feature_trace or {}).get("features") or []:
        fid = str(f.get("feature_id") or "")
        if not fid:
            continue
        features.append({
            "feature_id": fid,
            "featureState_rva": f.get("featureState_rva"),
            "on_disk_dword": f.get("on_disk_dword"),
            "symbol": f"Feature_{fid}__private_featureState",
        })
        if len(features) >= 8:
            break

    bp_lines = [f"bp {module}!{h['name']}" for h in hotspots if re.match(r"^[A-Za-z_][\w]*$", h["name"] or "")]
    feat_lines = [f"dd {module}!{f['symbol']} L1" for f in features]
    windbg = "\n".join([
        "$$ Patchalyzer 补丁核对 — 仅隔离 VM",
        f"lm m {module}",
        "!verifier 1",
        *bp_lines[:8],
        *feat_lines[:8],
        "",
    ])
    setup = (
        "@echo off\n"
        "REM Isolated VM + snapshot only. Administrator required. Reboot after setup.\n"
        f"REM Job: {title}\n"
        f"echo Enabling Driver Verifier on {driver}\n"
        f"verifier /standard /driver {driver}\n"
        f"verifier /flags 0x1 /driver {driver}\n"
        "verifier /query\n"
        "echo Reboot, then attach WinDbg and run windbg_hotspots.wds\n"
        "pause\n"
    )
    hotspot_md = "\n".join(
        f"- `{h['name']}`"
        + (f" old `{h['old_rva']}`" if h.get("old_rva") else "")
        + (f" → new `{h['new_rva']}`" if h.get("new_rva") else "")
        for h in hotspots
    ) or "- （尚无热点函数）"
    feat_md = "\n".join(
        f"- `Feature_{f['feature_id']}__private_featureState`"
        + (f" RVA `{f['featureState_rva']}`" if f.get("featureState_rva") else "")
        + (f" on-disk `{f['on_disk_dword']}`" if f.get("on_disk_dword") is not None else "")
        for f in features
    ) or "- （无新增 Feature 符号）"
    readme = f"""# 补丁验证材料（不在分析服务器执行）

任务: {title}
驱动: `{driver}`（WinDbg 模块 `{module}`）
版本: {old_ver or "漏洞版"} → {new_ver or "修复版"}

本包用于在**隔离虚拟机**里核对补丁是否生效：配置 Driver Verifier，并用 WinDbg 在热点函数 / Feature 状态上下断。
**不含触发程序。** Web 服务不会启用 Verifier，也不会在主机执行这些脚本。

## 步骤

1. 给虚拟机打快照。
2. 管理员运行 `setup_verifier_vm.cmd`，按提示重启。
3. 分别在漏洞版 / 修复版构建上附加 WinDbg，执行 `windbg_hotspots.wds`。
4. 对照 Feature dword（映像内常见为 0；运行时 `RtlQueryFeatureConfiguration` 后可能变为 cached+enabled）以及热点是否走到新增路径。
5. 核对完毕后 `verifier /reset` 并还原快照。

## 热点函数

{hotspot_md}

## Feature

{feat_md}

## 文件

- `setup_verifier_vm.cmd` — Driver Verifier + Special Pool
- `windbg_hotspots.wds` — 模块、Verifier、断点、Feature dword
- `job_context.json` — 机器可读上下文
"""
    context = {
        "title": title,
        "driver": driver,
        "module": module,
        "old_version": old_ver,
        "new_version": new_ver,
        "hotspots": hotspots,
        "features": features,
        "executed_on_server": False,
    }
    for stale in ("poc_bind_race.c", "windbg_feature.wds"):
        p = verify / stale
        if p.exists():
            p.unlink()
    (verify / "setup_verifier_vm.cmd").write_text(setup, encoding="utf-8")
    (verify / "README.md").write_text(readme, encoding="utf-8")
    (verify / "windbg_hotspots.wds").write_text(windbg, encoding="utf-8")
    (verify / "job_context.json").write_text(
        json.dumps(context, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {
        "dir": "verify",
        "driver": driver,
        "module": module,
        "old_version": old_ver,
        "new_version": new_ver,
        "hotspots": hotspots,
        "features": features,
        "files": [
            {"name": "README.md", "role": "验证步骤"},
            {"name": "setup_verifier_vm.cmd", "role": "Driver Verifier 配置"},
            {"name": "windbg_hotspots.wds", "role": "WinDbg 断点 / Feature"},
            {"name": "job_context.json", "role": "任务上下文"},
        ],
        "windbg": windbg,
        "verifier_cmd": f"verifier /standard /driver {driver}",
        "executed_on_server": False,
        "warning": "仅在隔离虚拟机中使用。分析服务器不会启用 Driver Verifier，本包也不含触发程序。",
    }


def run_pipeline(
    old_sys: Path,
    new_sys: Path,
    work_dir: Path,
    *,
    disasm_top_n: int = 8,
    progress_cb=None,
) -> dict[str, Any]:
    """Full analysis: PE extract → PDB download → symbol diff → disasm top changes."""

    def step(msg: str, pct: int):
        if progress_cb:
            progress_cb(msg, pct)

    work_dir.mkdir(parents=True, exist_ok=True)
    step("Extracting PE metadata (old)", 5)
    old_pe = extract_pe(old_sys)
    step("Extracting PE metadata (new)", 10)
    new_pe = extract_pe(new_sys)

    pdb_dir = work_dir / "pdb"
    old_url = next((d["symbol_url"] for d in old_pe["debug"] if "symbol_url" in d), None)
    new_url = next((d["symbol_url"] for d in new_pe["debug"] if "symbol_url" in d), None)
    if not old_url or not new_url:
        raise ValueError("PDB debug directory missing in one or both PE files")

    old_pdb_name = next(d["pdb_filename"] for d in old_pe["debug"] if "pdb_filename" in d)
    new_pdb_name = next(d["pdb_filename"] for d in new_pe["debug"] if "pdb_filename" in d)
    old_pdb = pdb_dir / f"old_{old_pdb_name}"
    new_pdb = pdb_dir / f"new_{new_pdb_name}"

    step("Downloading PDB (old)", 20)
    if not old_pdb.exists() or old_pdb.stat().st_size < 1024:
        download_pdb(old_url, old_pdb)
    step("Downloading PDB (new)", 35)
    if not new_pdb.exists() or new_pdb.stat().st_size < 1024:
        download_pdb(new_url, new_pdb)

    step("Comparing symbols", 50)
    sym_diff = compare_symbols(old_sys, new_sys, old_pdb, new_pdb)

    top_names = [f["name"] for f in sym_diff["functions_resized"][:disasm_top_n]]
    step(f"Disassembling top {len(top_names)} changed functions", 70)
    disasm = disassemble_functions(old_sys, new_sys, old_pdb, new_pdb, top_names) if top_names else []

    step("Writing artifacts", 90)
    artifacts = {
        "old_pe": old_pe,
        "new_pe": new_pe,
        "symbol_diff": sym_diff,
        "disassembly": disasm,
        "paths": {
            "old_pdb": str(old_pdb),
            "new_pdb": str(new_pdb),
        },
    }
    (work_dir / "result.json").write_text(json.dumps(artifacts, indent=2, ensure_ascii=False), encoding="utf-8")
    step("Done", 100)
    return artifacts
