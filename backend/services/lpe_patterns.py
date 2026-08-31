"""Absolute (patch-independent) LPE pattern scanners.

Findings are suspects and observation conditions only.
Does not produce exploits, PoCs, or trigger steps.
"""
from __future__ import annotations

import re
from typing import Any

BUG_CLASSES = (
    "missing_probe",
    "missing_lock",
    "lifetime_uaf",
    "check_use_window",
)

RE_PROBE = re.compile(
    r"ProbeFor|MmProbe|MmUserProbeAddress|ExRaiseAccessViolation|ExRaiseDatatypeMisalignment",
    re.I,
)
RE_MDL = re.compile(r"IoAllocateMdl|MmProbeAndLockPages|MmUnlockPages|IoFreeMdl|LockPages", re.I)
RE_COPY = re.compile(r"memcpy|memmove|RtlCopy|TdiCopy|CopyMemory", re.I)
RE_LOCK = re.compile(
    r"SpinLock|KeAcquire|KeRelease|ExAcquire|ExRelease|ExEnterCritical|"
    r"cmpxchg|QueuedSpin|CancelSpinLock|FastMutex|ResourceExclusive",
    re.I,
)
RE_ALLOC = re.compile(r"ExAllocatePool", re.I)
RE_PRIV = re.compile(
    r"SeAccessCheck|SePrivilegeCheck|SeSinglePrivilegeCheck|IoIs32bitProcess|"
    r"SeQueryInformationToken|SeTokenIsAdmin",
    re.I,
)
RE_FREE = re.compile(r"ExFreePool|ExFreeToPaged|IoFreeMdl|ObfDereference|ObDereferenceObject", re.I)
RE_REF = re.compile(r"ObReferenceObjectByHandle|ObOpenObjectByPointer|ObReferenceObject", re.I)
RE_FEATURE = re.compile(r"Feature_\w+|WilFeature|Feature_IsEnabled|RtlQueryFeature", re.I)
RE_JZ = re.compile(r"\b(jz|jnz|je|jne|ja|jbe|jb|jae|js|jns|jg|jl)\b", re.I)
RE_NAME_OK = re.compile(r"^[A-Za-z_][\w]*$")

_RISK_ORDER = {"high": 0, "medium": 1, "low": 2}


def _finding(
    *,
    function: str,
    bug_class: str,
    severity: str,
    status: str,
    evidence: str,
    rva: str | None = None,
    watch: str = "",
) -> dict[str, Any]:
    return {
        "function": function,
        "pattern": bug_class,
        "severity": severity,
        "status": status,
        "evidence": evidence,
        "rva": rva,
        "watch": watch,
    }


def findings_from_score(row: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Map a deterministic handler score into absolute bug-class suspects."""
    row = row or {}
    name = str(row.get("name") or "")
    if not name:
        return []
    why = [str(x) for x in (row.get("why") or []) if x]
    blob = " ".join(why).lower()
    method = str(row.get("method") or "")
    risk = str(row.get("risk") or "low")
    rva = row.get("rva")
    out: list[dict[str, Any]] = []

    if risk == "wrapper":
        return []
    if risk in {"buffered", "hardened"} and "free/deref without lock" not in blob:
        return [
            _finding(
                function=name,
                bug_class="missing_probe",
                severity="low",
                status="cleared",
                evidence="; ".join(why) or risk,
                rva=rva,
                watch="保持对照，不必优先观察",
            )
        ]

    if "copy without probe" in blob or "method_neither without probe" in blob or (
        method == "neither" and risk == "high"
    ):
        out.append(
            _finding(
                function=name,
                bug_class="missing_probe",
                severity="high" if risk == "high" else "medium",
                status="suspect",
                evidence="; ".join(why) or "用户指针路径未见 Probe/MDL",
                rva=rva,
                watch="ProbeFor / MDL 配对与用户长度",
            )
        )
    elif "no intern probe" in blob or "large handler" in blob:
        out.append(
            _finding(
                function=name,
                bug_class="missing_probe",
                severity="medium",
                status="similar",
                evidence="; ".join(why) or "大处理函数未见 Probe/MDL",
                rva=rva,
                watch="是否走用户指针以及 Probe 是否在子函数",
            )
        )

    if "free/deref without lock" in blob:
        out.append(
            _finding(
                function=name,
                bug_class="missing_lock",
                severity="medium" if risk != "high" else "high",
                status="suspect",
                evidence="; ".join(why) or "释放/解引用路径未见锁",
                rva=rva,
                watch="释放与引用计数是否被自旋锁/资源锁罩住",
            )
        )
    return out


def findings_from_disasm(
    name: str,
    lines: list[str] | None,
    *,
    calls: list[str] | None = None,
    rva: str | None = None,
) -> list[dict[str, Any]]:
    """Heuristic scan of one function's disassembly. Not a confirmed vuln."""
    rows = list(lines or [])
    if not name or not rows:
        return []
    blob = "\n".join(rows)
    call_blob = "\n".join(calls or [])
    text = blob + "\n" + call_blob
    out: list[dict[str, Any]] = []

    has_lock = bool(RE_LOCK.search(text))
    has_free = bool(RE_FREE.search(text))
    has_probe = bool(RE_PROBE.search(text) or RE_MDL.search(text))
    has_copy = bool(RE_COPY.search(text))

    free_i = next((i for i, ln in enumerate(rows) if RE_FREE.search(ln)), None)
    use_after = None
    if free_i is not None:
        for i, ln in enumerate(rows[free_i + 1 :], free_i + 1):
            if RE_COPY.search(ln) or RE_PROBE.search(ln) or RE_MDL.search(ln):
                use_after = i
                break
    if free_i is not None and use_after is not None:
        out.append(
            _finding(
                function=name,
                bug_class="lifetime_uaf",
                severity="high",
                status="suspect",
                evidence=f"free/deref 后 {use_after - free_i} 条指令内仍有 copy/probe",
                rva=rva,
                watch="释放后是否仍有指针使用；对照完成例程与关闭路径",
            )
        )
    elif has_free and not has_lock:
        out.append(
            _finding(
                function=name,
                bug_class="missing_lock",
                severity="medium",
                status="suspect",
                evidence="汇编中有释放/解引用，未见锁原语",
                rva=rva,
                watch="释放与对象指针读取是否同一把锁",
            )
        )

    check_i = next(
        (i for i, ln in enumerate(rows) if RE_PROBE.search(ln) or RE_LOCK.search(ln) or RE_FEATURE.search(ln)),
        None,
    )
    if check_i is not None:
        has_jz = any(RE_JZ.search(ln) for ln in rows[check_i : check_i + 12])
        use_i = None
        for i, ln in enumerate(rows[check_i + 1 :], check_i + 1):
            if RE_FREE.search(ln) or RE_COPY.search(ln):
                use_i = i
                break
        if has_jz and use_i is not None and 1 < (use_i - check_i) <= 48:
            out.append(
                _finding(
                    function=name,
                    bug_class="check_use_window",
                    severity="medium",
                    status="suspect",
                    evidence=f"检查后有条件跳转，{use_i - check_i} 条指令后才 free/copy",
                    rva=rva,
                    watch="检查与使用之间的失败返回/窗口",
                )
            )

    if has_copy and not has_probe:
        out.append(
            _finding(
                function=name,
                bug_class="missing_probe",
                severity="high",
                status="suspect",
                evidence="汇编可见 copy，未见 Probe/MDL",
                rva=rva,
                watch="用户缓冲 copy 前是否 Probe",
            )
        )
    return out


def _dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = (str(row.get("function") or ""), str(row.get("pattern") or ""), str(row.get("status") or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    out.sort(
        key=lambda r: (
            _RISK_ORDER.get(str(r.get("severity") or ""), 9),
            0 if r.get("status") == "suspect" else 1,
            str(r.get("function") or ""),
        )
    )
    return out


def verdict_of(findings: list[dict[str, Any]] | None) -> str:
    rows = list(findings or [])
    suspects = [r for r in rows if r.get("status") == "suspect"]
    if any(r.get("severity") == "high" for r in suspects):
        return "likely"
    if suspects:
        return "suspects"
    if rows:
        return "none"
    return "none"


def classify_audit(
    scores: list[dict[str, Any]] | None,
    disassembly: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for row in scores or []:
        findings.extend(findings_from_score(row))
    for block in disassembly or []:
        name = str(block.get("name") or "")
        side = (block.get("new") or block.get("old") or {}) if isinstance(block, dict) else {}
        lines = list(side.get("disasm") or [])
        calls = list(side.get("calls") or [])
        rva = side.get("rva") or block.get("rva")
        findings.extend(findings_from_disasm(name, lines, calls=calls, rva=rva))
    findings = _dedupe(findings)
    return {
        "verdict": verdict_of(findings),
        "findings": findings[:48],
        "bug_classes": sorted({str(f.get("pattern")) for f in findings if f.get("status") == "suspect"}),
    }


def observations_from_audit(
    findings: list[dict[str, Any]] | None,
    scores: list[dict[str, Any]] | None = None,
    *,
    cap: int = 16,
) -> list[dict[str, Any]]:
    """WinDbg observation conditions only — not trigger steps."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in findings or []:
        if row.get("status") not in {"suspect", "similar"}:
            continue
        name = str(row.get("function") or "")
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(
            {
                "function": name,
                "rva": row.get("rva"),
                "watch": row.get("watch") or "核对检查与对象生命周期",
                "why": f"{row.get('pattern')}: {row.get('evidence')}",
                "bp": f"bp {name}" if RE_NAME_OK.match(name) else None,
            }
        )
        if len(out) >= cap:
            return out
    for row in scores or []:
        if row.get("risk") not in {"high", "medium"}:
            continue
        name = str(row.get("name") or "")
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(
            {
                "function": name,
                "rva": row.get("rva"),
                "watch": "probe/MDL 配对与用户长度",
                "why": "; ".join(row.get("why") or []),
                "bp": f"bp {name}" if RE_NAME_OK.match(name) else None,
            }
        )
        if len(out) >= cap:
            break
    return out
