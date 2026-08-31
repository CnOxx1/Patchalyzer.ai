"""Shrink job JSON for the case UI. Full artifacts stay on disk / ?full=1."""
from __future__ import annotations

from typing import Any

_PE_DROP = ("exports", "sections")
_DISASM_SIDES = ("old", "new")


def _slim_pe(pe: Any) -> Any:
    if not isinstance(pe, dict):
        return pe
    out = dict(pe)
    for key in _PE_DROP:
        out.pop(key, None)
    return out


def _slim_disasm_block(block: Any) -> Any:
    if not isinstance(block, dict):
        return block
    out = dict(block)
    for side in _DISASM_SIDES:
        body = out.get(side)
        if isinstance(body, dict):
            slim = dict(body)
            slim.pop("disasm", None)
            out[side] = slim
    return out


def _slim_cfg(cfg: Any) -> Any:
    if not isinstance(cfg, dict):
        return cfg
    out = dict(cfg)
    fns = []
    for fn in out.get("functions") or []:
        if not isinstance(fn, dict):
            continue
        row = {k: v for k, v in fn.items() if k not in ("old_blocks", "new_blocks")}
        for side in _DISASM_SIDES:
            body = row.get(side)
            if isinstance(body, dict):
                row[side] = {k: body[k] for k in ("rva", "size", "blocks") if k in body}
        fns.append(row)
    out["functions"] = fns
    return out


def _artifacts_of(result: Any) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        return None
    art = result.get("artifacts")
    if isinstance(art, dict):
        return art
    if "old_pe" in result or "symbol_diff" in result or "llm_report" in result:
        return result
    return None


def slim_job(job: dict[str, Any]) -> dict[str, Any]:
    job = dict(job)
    result = job.get("result")
    art = _artifacts_of(result)
    if not isinstance(result, dict) or art is None:
        job["ui_slim"] = True
        return job
    wrapped = art is not result
    art = dict(art)
    for key in ("old_pe", "new_pe", "mid_pe"):
        if key in art:
            art[key] = _slim_pe(art[key])
    sd = art.get("symbol_diff")
    if isinstance(sd, dict):
        sd = dict(sd)
        symbols = sd.pop("code_symbols", None)
        sd["code_symbol_count"] = len(symbols) if isinstance(symbols, list) else 0
        art["symbol_diff"] = sd
    if isinstance(art.get("disassembly"), list):
        art["disassembly"] = [_slim_disasm_block(b) for b in art["disassembly"]]
    if isinstance(art.get("control_disasm"), list):
        art["control_disasm"] = [_slim_disasm_block(b) for b in art["control_disasm"]]
    if isinstance(art.get("cfg_diff"), dict):
        art["cfg_diff"] = _slim_cfg(art["cfg_diff"])
    if wrapped:
        job["result"] = {**result, "artifacts": art}
    else:
        job["result"] = {"artifacts": art}
    job["ui_slim"] = True
    return job
