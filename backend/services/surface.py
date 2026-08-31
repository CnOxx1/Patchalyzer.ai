"""User-reachable IOCTL / FastIo surface map + handler scoring.

Deterministic. No exploit / PoC. Used by the research-lab flow.
"""
from __future__ import annotations

import re
import struct
from collections import Counter
from pathlib import Path
from typing import Any

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

from .analyzer import _iat_map, _intern_names, _read_pdata, named_function_sizes, pdb_ok
from .lpe_patterns import RE_ALLOC, RE_COPY, RE_FREE, RE_LOCK, RE_MDL, RE_PRIV, RE_PROBE, RE_REF

METHODS = {0: "buffered", 1: "in_direct", 2: "out_direct", 3: "neither"}

_DISPATCH = re.compile(r"DispatchDeviceControl$", re.I)
_FASTIO = re.compile(r"FastIoDeviceControl$", re.I)
_IMMEDIATE = re.compile(r"ImmediateCallDispatch$", re.I)
_MJ = (
    ("create", re.compile(r"(DispatchCreate|IrpMjCreate)$", re.I)),
    ("close", re.compile(r"(DispatchClose|IrpMjClose)$", re.I)),
    ("cleanup", re.compile(r"(DispatchCleanup|IrpMjCleanup)$", re.I)),
    ("internal_device_control", re.compile(r"(DispatchInternalDeviceControl|InternalDeviceControl)$", re.I)),
    ("file_system_control", re.compile(r"(DispatchFileSystemControl|FileSystemControl)$", re.I)),
    ("read", re.compile(r"DispatchRead$", re.I)),
    ("write", re.compile(r"DispatchWrite$", re.I)),
)


def _md() -> Cs:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def _rev(intern: dict[int, str]) -> dict[str, int]:
    return {v: k for k, v in intern.items()}


def _pick_name(sizes: dict[str, dict], pattern: re.Pattern[str]) -> str | None:
    hits = [n for n in sizes if pattern.search(n)]
    if not hits:
        return None
    hits.sort(key=lambda n: (-(sizes[n].get("size") or 0), n))
    return hits[0]


def _rip_target(insn) -> int | None:
    if not insn.disp:
        return None
    if "rip" in insn.op_str or insn.mnemonic in ("call", "jmp", "lea"):
        return insn.address + insn.size + insn.disp
    return None


def function_events(pe, intern: dict[int, str], iat: dict[int, str], rva: int, size: int) -> Counter:
    ev: Counter = Counter()
    if size <= 0 or size > 0x20000:
        return ev
    try:
        blob = pe.get_data(rva, size)
    except Exception:
        return ev
    md = _md()
    for insn in md.disasm(blob, rva):
        tgt = None
        if insn.mnemonic == "call":
            if insn.op_str.startswith("0x"):
                try:
                    tgt = int(insn.op_str, 16)
                except ValueError:
                    tgt = None
            elif insn.disp:
                tgt = insn.address + insn.size + insn.disp
        elif insn.disp and "rip" in insn.op_str:
            tgt = insn.address + insn.size + insn.disp
        if tgt is None:
            continue
        nm = iat.get(tgt) or intern.get(tgt)
        if nm:
            ev[nm] += 1
    return ev


def _parse_dispatch_tables(pe, intern: dict[int, str], iat: dict[int, str], name: str, meta: dict[str, Any]) -> dict[str, Any]:
    rva, size = meta["rva"], meta["size"]
    md = _md()
    try:
        blob = pe.get_data(rva, min(size, 0x800))
    except Exception:
        return {"handler": name, "rva": hex(rva), "size": size, "ioctl": [], "limit": None}
    limit = None
    code_rva = None
    ptr_rva = None
    image_base_reg = False
    for insn in md.disasm(blob, rva):
        if insn.mnemonic == "cmp":
            for op in insn.operands:
                if op.type == X86_OP_IMM and 8 <= op.imm <= 512:
                    limit = int(op.imm)
        if insn.mnemonic == "lea" and "rip" in insn.op_str:
            tgt = _rip_target(insn)
            if tgt == 0:
                image_base_reg = True
        scaled = re.search(r"\*([48])\s*\+\s*(0x[0-9a-fA-F]+)", insn.op_str)
        if scaled:
            scale, off = int(scaled.group(1)), int(scaled.group(2), 16)
            if scale == 4:
                code_rva = off
            elif scale == 8:
                ptr_rva = off
        rip_tbl = re.search(r"\[rip ([+-]) (0x[0-9a-fA-F]+)\]", insn.op_str)
        if rip_tbl and insn.mnemonic in ("lea", "mov"):
            sign = 1 if rip_tbl.group(1) == "+" else -1
            tgt = insn.address + insn.size + sign * int(rip_tbl.group(2), 16)
            if insn.mnemonic == "lea" and tgt == 0:
                image_base_reg = True
    rows = []
    if limit and ptr_rva is not None:
        ib = pe.OPTIONAL_HEADER.ImageBase
        try:
            codes = pe.get_data(code_rva, limit * 4) if code_rva is not None else b""
            ptrs = pe.get_data(ptr_rva, limit * 8)
        except Exception:
            codes, ptrs = b"", b""
        for i in range(limit):
            code = struct.unpack_from("<I", codes, i * 4)[0] if codes and len(codes) >= (i + 1) * 4 else 0
            raw = struct.unpack_from("<Q", ptrs, i * 8)[0] if len(ptrs) >= (i + 1) * 8 else 0
            hrva = raw - ib if raw >= ib else raw
            hname = intern.get(hrva, f"sub_{hrva:x}" if hrva else "(null)")
            method = METHODS.get(code & 3, "unknown") if code else None
            rows.append(
                {
                    "index": i,
                    "code": hex(code) if code else None,
                    "method": method,
                    "handler": hname,
                    "handler_rva": hex(hrva) if hrva else None,
                }
            )
    return {
        "handler": name,
        "rva": hex(rva),
        "size": size,
        "limit": limit,
        "code_table_rva": hex(code_rva) if code_rva is not None else None,
        "ptr_table_rva": hex(ptr_rva) if ptr_rva is not None else None,
        "image_base_lea": image_base_reg,
        "ioctl": rows,
    }


def _immediate_table(pe, intern: dict[str, Any] | dict[int, str], sizes: dict[str, dict], name: str) -> dict[str, Any]:
    rev = _rev(intern)  # type: ignore[arg-type]
    rva = rev.get(name)
    if rva is None:
        return {"symbol": name, "entries": []}
    later = sorted(a for a in intern if a > rva)
    span = (later[0] - rva) if later else 74 * 8
    nent = min(max(span // 8, 1), 1024)
    ib = pe.OPTIONAL_HEADER.ImageBase
    try:
        data = pe.get_data(rva, nent * 8)
    except Exception:
        return {"symbol": name, "rva": hex(rva), "entries": []}
    entries = []
    for i in range(nent):
        raw = struct.unpack_from("<Q", data, i * 8)[0]
        if not raw:
            continue
        hrva = raw - ib if raw >= ib else raw
        hname = intern.get(hrva, f"sub_{hrva:x}")
        meta = sizes.get(hname) or {}
        entries.append(
            {
                "index": i,
                "handler": hname,
                "handler_rva": hex(hrva),
                "size": meta.get("size"),
            }
        )
    return {"symbol": name, "rva": hex(rva), "span": hex(span), "filled": len(entries), "entries": entries}


def _fastio_callees(pe, intern: dict[int, str], iat: dict[int, str], name: str, meta: dict[str, Any]) -> list[dict[str, Any]]:
    rva, size = meta["rva"], meta["size"]
    md = _md()
    out = []
    seen = set()
    try:
        blob = pe.get_data(rva, min(size, 0x4000))
    except Exception:
        return out
    for insn in md.disasm(blob, rva):
        if insn.mnemonic != "call":
            continue
        tgt = None
        if insn.op_str.startswith("0x"):
            try:
                tgt = int(insn.op_str, 16)
            except ValueError:
                continue
        elif insn.disp:
            tgt = insn.address + insn.size + insn.disp
        nm = (iat.get(tgt) or intern.get(tgt)) if tgt else None
        if not nm or nm in seen:
            continue
        if nm.startswith("__") or nm in iat.values():
            continue
        seen.add(nm)
        out.append({"from": name, "to": nm, "at": hex(insn.address), "kind": "direct_call"})
    return out[:40]


def _flags(ev: Counter) -> dict[str, list[str]]:
    keys = list(ev)
    def anyk(pat: re.Pattern[str]) -> list[str]:
        return [k for k in keys if pat.search(k)]
    return {
        "probe": anyk(RE_PROBE),
        "mdl": anyk(RE_MDL),
        "copy": anyk(RE_COPY),
        "lock": anyk(RE_LOCK),
        "alloc": anyk(RE_ALLOC),
        "priv": anyk(RE_PRIV),
        "free": anyk(RE_FREE),
        "ref": anyk(RE_REF),
    }


def score_handler(
    name: str,
    size: int | None,
    ev: Counter,
    method: str | None,
) -> dict[str, Any]:
    fl = _flags(ev)
    size = size or 0
    why: list[str] = []
    risk = "low"
    if size and size < 80:
        risk = "wrapper"
        why.append("tiny stub")
    elif fl["copy"] and not fl["probe"] and not fl["mdl"] and method != "buffered":
        risk = "high"
        why.append("copy without probe/MDL")
    elif method == "neither" and not fl["probe"] and not fl["mdl"]:
        risk = "high"
        why.append("METHOD_NEITHER without probe/MDL")
    elif method == "buffered":
        risk = "buffered"
        why.append("METHOD_BUFFERED")
    elif fl["probe"] or fl["mdl"]:
        risk = "hardened"
        why.append("has probe or MDL")
    elif size > 1500 and not fl["probe"] and not fl["mdl"]:
        risk = "medium"
        why.append("large handler, no intern probe/MDL")
    else:
        why.append("no copy/probe pattern in intern events")
    if risk != "wrapper" and fl["free"] and not fl["lock"]:
        why.append("free/deref without lock")
        if risk in {"low", "hardened", "buffered"}:
            risk = "medium"
        elif risk == "medium":
            pass
    return {
        "name": name,
        "size": size,
        "method": method,
        "risk": risk,
        "why": why,
        "probe": fl["probe"][:8],
        "mdl": fl["mdl"][:6],
        "copy": fl["copy"][:6],
        "lock": fl["lock"][:6],
        "priv": fl["priv"][:6],
        "free": fl["free"][:6],
        "ref": fl["ref"][:6],
        "top_calls": [k for k, _ in ev.most_common(10)],
    }


def _major_functions(sizes: dict[str, dict]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for key, pat in _MJ:
        name = _pick_name(sizes, pat)
        if not name:
            continue
        meta = sizes.get(name) or {}
        out[key] = {
            "handler": name,
            "size": meta.get("size"),
            "rva": hex(meta["rva"]) if meta.get("rva") is not None else None,
        }
    return out


def build_surface_map(sys_path: Path, pdb_path: Path | str | None) -> dict[str, Any]:
    """Parse user-reachable handlers from the patched (or only) image."""
    pe = pefile.PE(str(sys_path))
    intern = _intern_names(pe, pdb_path)
    iat = _iat_map(pe)
    sizes = named_function_sizes(sys_path, pdb_path)
    dispatch_name = _pick_name(sizes, _DISPATCH)
    fastio_name = _pick_name(sizes, _FASTIO)
    imm_name = next((n for n in intern.values() if _IMMEDIATE.search(n)), None)
    dispatch = None
    if dispatch_name and sizes.get(dispatch_name):
        dispatch = _parse_dispatch_tables(pe, intern, iat, dispatch_name, sizes[dispatch_name])
    immediate = _immediate_table(pe, intern, sizes, imm_name) if imm_name else {"symbol": None, "entries": []}
    fastio = []
    if fastio_name and sizes.get(fastio_name):
        fastio = _fastio_callees(pe, intern, iat, fastio_name, sizes[fastio_name])
        # outlined fragments: call imm from unnamed pdata that land on intern FastIo extras
        rio = next((n for n in sizes if re.search(r"RioFastIo$", n, re.I)), None)
        if rio and sizes.get(rio) and not any(x.get("to") == rio for x in fastio):
            rio_rva = sizes[rio]["rva"]
            md = _md()
            for rec in _read_pdata(pe):
                if rec["size"] > 4000 or rec["size"] < 16:
                    continue
                try:
                    blob = pe.get_data(rec["begin"], rec["size"])
                except Exception:
                    continue
                for insn in md.disasm(blob, rec["begin"]):
                    if insn.mnemonic != "call" or not insn.op_str.startswith("0x"):
                        continue
                    try:
                        tgt = int(insn.op_str, 16)
                    except ValueError:
                        continue
                    if tgt == rio_rva:
                        fastio.append(
                            {
                                "from": intern.get(rec["begin"], hex(rec["begin"])),
                                "to": rio,
                                "at": hex(insn.address),
                                "kind": "outlined_call",
                            }
                        )
                        break
                if any(x.get("to") == rio for x in fastio):
                    break

    major = _major_functions(sizes)
    names: dict[str, str | None] = {}
    for row in (dispatch or {}).get("ioctl") or []:
        h = row.get("handler")
        if h and h != "(null)" and not str(h).startswith("sub_"):
            names[h] = row.get("method")
    for row in immediate.get("entries") or []:
        h = row.get("handler")
        if h and not str(h).startswith("sub_"):
            names.setdefault(h, None)
    for edge in fastio:
        to = edge.get("to") or ""
        if re.search(r"(FastIo|RioFastIo|DeviceControl)$", to, re.I):
            names.setdefault(to, None)
    for rec in major.values():
        h = rec.get("handler")
        if h:
            names.setdefault(str(h), None)

    scores = []
    for n, method in sorted(names.items()):
        meta = sizes.get(n) or {}
        ev = function_events(pe, intern, iat, meta["rva"], meta["size"]) if meta.get("rva") is not None else Counter()
        row = score_handler(n, meta.get("size"), ev, method)
        row["rva"] = hex(meta["rva"]) if meta.get("rva") is not None else None
        scores.append(row)
    order = {"high": 0, "medium": 1, "low": 2, "buffered": 3, "hardened": 4, "wrapper": 5}
    scores.sort(key=lambda r: (order.get(r["risk"], 9), -(r.get("size") or 0)))

    pe.close()
    has_ioctl = bool(dispatch and dispatch.get("ioctl"))
    has_imm = bool(immediate.get("entries"))
    status = "ok" if has_ioctl or has_imm or major else "partial"
    return {
        "status": status,
        "pdb": bool(pdb_ok(pdb_path)),
        "dispatch": dispatch,
        "immediate": immediate,
        "fastio": {"handler": fastio_name, "size": (sizes.get(fastio_name) or {}).get("size"), "callees": fastio},
        "major_functions": major,
        "handler_count": len(scores),
        "scores": scores,
        "notes": "IOCTL 表来自 DeviceControl 反汇编；Immediate 为二级指针表；FastIo 为直接 call；"
        "MajorFunction 来自符号名。禁止据此写 exploit。",
    }


def observations_from_scores(scores: list[dict[str, Any]], *, cap: int = 12) -> list[dict[str, Any]]:
    """WinDbg observation conditions only — not trigger steps."""
    out = []
    for row in scores:
        if row.get("risk") not in {"high", "medium"}:
            continue
        out.append(
            {
                "function": row.get("name"),
                "rva": row.get("rva"),
                "watch": "probe/MDL 配对与用户长度",
                "why": "; ".join(row.get("why") or []),
                "bp": f"bp {row.get('name')}" if re.match(r"^[A-Za-z_][\w]*$", str(row.get("name") or "")) else None,
            }
        )
        if len(out) >= cap:
            break
    return out
