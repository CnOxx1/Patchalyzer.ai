"""Resolve an extra kernel/user PE so an audit can follow a call off-module.

Prefers a local Windows copy; otherwise Winbindex + MSDL for a version close to
the sample. No arbitrary URLs. No exploit artifacts.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from .analyzer import extract_pe, fetch_pdb, pdb_ok, pe_import_table
from .patch_resolver import (
    PatchResolveError,
    fetch_versioned_binary,
    parse_version,
    sanitize_filename,
)

MAX_EXTRA_MODULES = 8


def local_module_candidates(name: str, sample_path: Path | None = None) -> list[Path]:
    n = sanitize_filename(name)
    out: list[Path] = []
    if sample_path:
        sp = Path(sample_path)
        if sp.is_file() and sp.name.lower() == n.lower():
            out.append(sp)
        out.append(sp.parent / n)
    root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    out.extend(
        [
            root / "System32" / "drivers" / n,
            root / "System32" / n,
            root / "Sysnative" / "drivers" / n,
            root / "Sysnative" / n,
        ]
    )
    seen: set[str] = set()
    uniq: list[Path] = []
    for p in out:
        key = str(p).lower()
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)
    return uniq


def find_local_module(name: str, sample_path: Path | None = None) -> Path | None:
    for p in local_module_candidates(name, sample_path):
        try:
            if p.is_file() and p.stat().st_size > 256 and p.read_bytes()[:2] == b"MZ":
                return p
        except OSError:
            continue
    return None


def resolve_audit_module(
    filename: str,
    *,
    work: Path,
    sample_pe: dict[str, Any] | None = None,
    sample_path: Path | None = None,
) -> dict[str, Any]:
    """Copy or download filename into work/, fetch PDB. Raises PatchResolveError."""
    name = sanitize_filename(filename)
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    dest = work / name
    source = "local"
    local = find_local_module(name, sample_path)
    if local:
        if dest.resolve() != local.resolve():
            shutil.copy2(local, dest)
        elif not dest.exists():
            shutil.copy2(local, dest)
    else:
        pe = sample_pe or {}
        want_ver = parse_version(str(pe.get("file_version") or ""))
        machine = str(pe.get("machine") or "AMD64")
        want_arch = "amd64" if machine == "AMD64" else "x86" if machine == "I386" else "amd64"
        fetch_versioned_binary(name, dest, want_ver=want_ver, want_arch=want_arch)
        source = "winbindex+msdl"
    if dest.read_bytes()[:2] != b"MZ":
        dest.unlink(missing_ok=True)
        raise PatchResolveError(f"{name} 不是有效 PE")
    info = extract_pe(dest)
    pdb_path = work / f"{Path(name).stem}.pdb"
    pdb_error = None
    try:
        fetch_pdb(info, pdb_path)
    except Exception as e:
        pdb_error = str(e)
        pdb_path = Path()
    imports = pe_import_table(dest)
    return {
        "filename": name,
        "path": dest,
        "pdb": pdb_path if pdb_ok(pdb_path) else Path(),
        "pe": info,
        "imports": {k: v[:24] for k, v in list(imports.items())[:24]},
        "source": source,
        "pdb_error": pdb_error,
        "version": info.get("file_version") or "",
    }
