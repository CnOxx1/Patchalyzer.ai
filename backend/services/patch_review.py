"""Patch completeness (bypass surface) and residual-vuln review packs."""
from __future__ import annotations

import json
import re
from typing import Any

from .mdutil import demote_h2

_NOTE_JUNK_HEAD = re.compile(r"^(?:#+\s*)?(?:中文\s*)?(?:Markdown\s*)?(?:技术)?解读\s*$", re.M | re.I)
_JSON_INTRO = re.compile(
    r"(?is)^(?:以下为[^\n]{0,80}|先(?:给|输出)[^\n]{0,80}|[^\n]{0,100}结构化\s*JSON[^\n]{0,40})$"
)


def _drop_json_preamble(prefix: str) -> str:
    """Keep only real prose before a JSON pack; drop fence lines and '先输出 JSON' intros."""
    p = (prefix or "").strip()
    p = re.sub(r"```(?:json)?\s*$", "", p, flags=re.I).strip()
    p = re.sub(r"^```(?:json)?\s*", "", p, flags=re.I).strip()
    if not p:
        return ""
    if _JSON_INTRO.match(p) or (re.search(r"(?i)\bjson\b", p) and len(p) < 160):
        return ""
    return p


def _strip_json_fences(text: str) -> str:
    cleaned = (text or "").strip()
    cleaned = re.sub(r"```(?:json)?\s*[\s\S]*?```", "", cleaned, flags=re.I)
    # Unclosed ```json leftover would swallow the following markdown as a code block.
    cleaned = re.sub(r"```(?:json)?[ \t]*\n(?!\s*\{)", "\n", cleaned, flags=re.I)
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned.strip(), flags=re.I)
    return cleaned.strip()


def _slice_json_object(text: str) -> tuple[str | None, str]:
    """Return (json_blob, remainder) using brace matching; remainder is prose."""
    s = text or ""
    lead = s.lstrip()
    fence = re.match(r"```(?:json)?\s*", lead, re.I)
    hay = lead[fence.end() :] if fence else lead
    start_in_hay = 0 if hay.startswith("{") else -1
    if start_in_hay < 0:
        m = re.search(r"```(?:json)?\s*\{", s, re.I | re.S)
        if not m:
            return None, s.strip()
        start = s.find("{", m.start())
    else:
        start = s.find("{")
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(s[start:], start):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                blob = s[start : i + 1]
                rest = s[i + 1 :]
                rest = re.sub(r"^\s*```[ \t]*", "", rest).strip()
                prefix = _drop_json_preamble(s[:start])
                if prefix:
                    rest = f"{prefix}\n\n{rest}".strip()
                return blob, rest
    return None, s.strip()


def extract_json_object(text: str) -> dict[str, Any] | None:
    blob, _rest = _slice_json_object(text or "")
    if not blob:
        return None
    try:
        obj = json.loads(blob)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def notes_without_json(text: str) -> str:
    blob, rest = _slice_json_object(text or "")
    cleaned = _strip_json_fences(_NOTE_JUNK_HEAD.sub("", rest or ""))
    if "\n" in cleaned:
        first, more = cleaned.split("\n", 1)
        dropped = _drop_json_preamble(first)
        cleaned = (dropped + "\n" + more).strip() if dropped else more.strip()
    else:
        cleaned = _drop_json_preamble(cleaned)

    def _looks_like_pack(s: str) -> bool:
        t = (s or "").strip()
        if not t.startswith("{"):
            return False
        head = t[:800]
        if re.search(
            r'"(?:verdict|findings|confidence|summary|surfaces|suspects)"\s*:',
            head,
        ):
            return True
        try:
            obj = json.loads(t)
            return isinstance(obj, dict)
        except Exception:
            return len(re.findall(r'"[^"]+"\s*:', t)) >= 2 and "}" in t

    # Entire note was the JSON pack (common when LLM only emits JSON)
    if blob and not cleaned:
        return ""
    if _looks_like_pack(cleaned):
        return ""
    if cleaned.startswith("{"):
        # Truncated / invalid JSON pack — do not show braces to users
        if re.search(r'"(?:verdict|findings|confidence)"\s*:', cleaned[:500]):
            return ""
    return cleaned


BYPASS_VERDICTS = {
    "closed": ("ok", "补丁已闭合"),
    "partial": ("mid", "部分闭合"),
    "bypassable": ("hot", "存在绕过面"),
    "unknown": ("muted", "证据不足"),
}

RESIDUAL_VERDICTS = {
    "none": ("ok", "未发现同类缺陷"),
    "suspects": ("mid", "有待核实嫌疑"),
    "likely": ("hot", "可能仍有漏洞"),
    "unknown": ("muted", "证据不足"),
}


def _norm_status(val: str, allowed: tuple[str, ...], default: str) -> str:
    s = str(val or "").strip().lower()
    aliases = {
        "open": "residual",
        "yes": "bypassable",
        "no": "closed",
        "ok": "closed",
        "cleared": "none",
        "clean": "none",
        "found": "suspects",
        "possible": "suspects",
        "confirmed": "likely",
    }
    mapped = aliases.get(s, s)
    if mapped in allowed:
        return mapped
    if s in allowed:
        return s
    return default


_GROUND_EV = re.compile(
    r"0x[0-9a-fA-F]+|\b(call|jz|jnz|je|jne|cmpxchg)\b|"
    r"IoAcquire|KeAcquire|KeRelease|ExAcquire|ExRelease|ProbeFor|MmProbe|"
    r"IoAllocate|IofCall|RtlQueryFeature|Feature_IsEnabled|IsEnabledDevice|"
    r"ExFree|CancelSpinLock|QueuedSpin|calls_added|calls_removed|调用差",
    re.I,
)
_NAME_GUESS = re.compile(
    r"作为最终|可能都调用|若被非|若存在未|基于命名|命名已表明|名字像|"
    r"推测其职责|按名字|无反汇编|缺少反汇编|无法确认.*路径|可能全部调用|"
    r"核心实现|的 APC|配对，属于|与已修补的",
    re.I,
)
_SIBLING_STORY = re.compile(
    r"APC|rundown|核心实现|配对|与已修补|的内核例程|间接保护",
    re.I,
)
_UNCHANGED_CLAIM = re.compile(r"未修改|尺寸未变|自身未变|未引入|调用亦无变化", re.I)
_SPECULATIVE_FEATURE = re.compile(
    r"攻击者若能|修改 Feature|注册表|内存破坏|关闭修复|可关闭开关",
    re.I,
)


def evidence_grounded(text: str) -> bool:
    return bool(_GROUND_EV.search(text or ""))


def looks_like_name_guess(text: str) -> bool:
    t = text or ""
    if _NAME_GUESS.search(t) and not evidence_grounded(t):
        return True
    if not (t.strip()):
        return True
    return False


def _demote_bypass_finding(f: dict[str, Any]) -> dict[str, Any]:
    ev = str(f.get("evidence") or "")
    st = f.get("status") or "unknown"
    speculative_feat = bool(_SPECULATIVE_FEATURE.search(ev)) and not re.search(
        r"IsEnabled|jz |jnz |featureState", ev, re.I
    )
    if st == "residual" and (
        looks_like_name_guess(ev) or not evidence_grounded(ev) or speculative_feat
    ):
        f = {**f, "status": "unknown", "demoted": "name_guess"}
        if ev and "未按汇编/调用差核实" not in ev:
            f["evidence"] = ev.rstrip("。") + "。系统已降级：无汇编或调用差，不能按函数名定为残留。"
    elif st == "closed" and looks_like_name_guess(ev) and not evidence_grounded(ev):
        f = {**f, "status": "unknown", "demoted": "name_guess"}
    return f


def _demote_residual_finding(f: dict[str, Any]) -> dict[str, Any]:
    ev = str(f.get("evidence") or "")
    st = f.get("status") or "unknown"
    sibling_only = bool(_SIBLING_STORY.search(ev) and _UNCHANGED_CLAIM.search(ev))
    if st in {"suspect", "likely"} and (
        looks_like_name_guess(ev) or not evidence_grounded(ev) or sibling_only
    ):
        f = {**f, "status": "similar", "demoted": "name_guess"}
        if ev and "仅名字" not in ev:
            f["evidence"] = ev.rstrip("。") + "。系统已降级为 similar：缺少该函数自己的汇编/调用表。"
    return f


def _recompute_bypass_verdict(verdict: str, findings: list[dict[str, Any]]) -> str:
    if verdict == "unknown":
        return verdict
    statuses = {f.get("status") for f in findings}
    if "residual" in statuses:
        return "partial" if "closed" in statuses or verdict in {"partial", "closed"} else "bypassable"
    if verdict == "bypassable" and "residual" not in statuses:
        return "unknown" if "unknown" in statuses else "closed"
    if verdict == "partial" and "residual" not in statuses:
        return "closed" if "closed" in statuses and "unknown" not in statuses else ("unknown" if "unknown" in statuses else verdict)
    return verdict


def _recompute_residual_verdict(verdict: str, findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "none" if verdict in {"suspects", "likely", "none"} else verdict
    if any(f.get("status") in {"suspect", "likely"} for f in findings):
        return "likely" if any(f.get("severity") == "high" and f.get("status") in {"suspect", "likely"} for f in findings) else "suspects"
    if all(f.get("status") == "cleared" for f in findings):
        return "none"
    if any(f.get("status") == "similar" for f in findings):
        return "unknown"
    return verdict


def _finding_list(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw[:16]:
        if isinstance(item, dict):
            out.append(item)
        elif isinstance(item, str) and item.strip():
            out.append({"summary": item.strip()})
    return out


def _synthesize_notes(summary: str, findings: list[dict[str, Any]], kind: str) -> str:
    """When LLM only returns JSON, build Chinese prose for the UI."""
    parts: list[str] = []
    if summary:
        parts.append(summary.strip())
    for f in findings:
        if kind == "bypass":
            title = str(f.get("method") or "发现项").strip()
            bits = []
            if f.get("target"):
                bits.append(f"对象：{f['target']}")
            if f.get("evidence"):
                bits.append(f"证据：{f['evidence']}")
            if f.get("hardening"):
                bits.append(f"加固：{f['hardening']}")
        else:
            title = str(f.get("function") or "发现项").strip()
            bits = []
            if f.get("pattern"):
                bits.append(f"模式：{f['pattern']}")
            if f.get("evidence"):
                bits.append(f"证据：{f['evidence']}")
        if bits:
            parts.append(f"### {title}\n\n" + "\n\n".join(bits))
    return "\n\n".join(parts).strip()


def build_bypass_pack(notes: str) -> dict[str, Any]:
    text = (notes or "").strip()
    skipped = text.startswith("（跳过") or text.startswith("（失败") or not text
    data = {} if skipped else (extract_json_object(text) or {})
    verdict = _norm_status(data.get("verdict") or data.get("status") or "", tuple(BYPASS_VERDICTS), "unknown")
    findings = []
    for f in _finding_list(data.get("findings") or data.get("surfaces") or []):
        findings.append(
            {
                "method": str(f.get("method") or f.get("dimension") or f.get("name") or "未命名维度").strip(),
                "target": str(f.get("target") or f.get("function") or "").strip(),
                "status": _norm_status(f.get("status") or "", ("closed", "residual", "unknown"), "unknown"),
                "likelihood": _norm_status(f.get("likelihood") or f.get("risk") or "", ("high", "medium", "low"), "medium"),
                "evidence": str(f.get("evidence") or f.get("why") or f.get("summary") or "").strip(),
                "hardening": str(f.get("hardening") or f.get("fix") or f.get("note") or "").strip(),
            }
        )
    findings = [_demote_bypass_finding(x) for x in findings]
    if skipped:
        verdict = "unknown"
    else:
        verdict = _recompute_bypass_verdict(verdict, findings)
    body = "" if skipped else notes_without_json(text)
    summary = str(data.get("summary") or "").strip()
    if not summary and body:
        summary = re.split(r"\n\s*\n", body)[0].replace("#", "").strip()[:180]
    if not body and not skipped and (summary or findings):
        body = _synthesize_notes(summary, findings, "bypass")
    return {
        "verdict": verdict,
        "confidence": _norm_status(data.get("confidence") or "", ("high", "medium", "low"), "medium"),
        "summary": summary,
        "findings": findings,
        "notes": body,
        "has_analyst": (not skipped) and bool(body or findings or summary),
        "kind": "bypass",
    }


def build_residual_pack(notes: str) -> dict[str, Any]:
    text = (notes or "").strip()
    skipped = text.startswith("（跳过") or text.startswith("（失败") or not text
    data = {} if skipped else (extract_json_object(text) or {})
    verdict = _norm_status(data.get("verdict") or data.get("status") or "", tuple(RESIDUAL_VERDICTS), "unknown")
    findings = []
    for f in _finding_list(data.get("findings") or data.get("suspects") or []):
        findings.append(
            {
                "function": str(f.get("function") or f.get("target") or f.get("name") or "未命名函数").strip(),
                "pattern": str(f.get("pattern") or f.get("method") or f.get("kind") or "同类模式").strip(),
                "severity": _norm_status(f.get("severity") or f.get("risk") or "", ("high", "medium", "low"), "medium"),
                "status": _norm_status(f.get("status") or "", ("suspect", "similar", "cleared", "unknown"), "unknown"),
                "evidence": str(f.get("evidence") or f.get("why") or f.get("summary") or "").strip(),
            }
        )
    findings = [_demote_residual_finding(x) for x in findings]
    if skipped:
        verdict = "unknown"
    elif findings:
        verdict = _recompute_residual_verdict(verdict, findings)
    elif not findings and verdict == "unknown" and not skipped and text:
        verdict = "none"
    body = "" if skipped else notes_without_json(text)
    summary = str(data.get("summary") or "").strip()
    if not summary and body:
        summary = re.split(r"\n\s*\n", body)[0].replace("#", "").strip()[:180]
    if not body and not skipped and (summary or findings):
        body = _synthesize_notes(summary, findings, "residual")
    return {
        "verdict": verdict,
        "confidence": _norm_status(data.get("confidence") or "", ("high", "medium", "low"), "medium"),
        "summary": summary,
        "findings": findings,
        "notes": body,
        "has_analyst": (not skipped) and bool(body or findings or summary),
        "kind": "residual",
    }


def sanitize_bypass_pack(pack: dict[str, Any] | None) -> dict[str, Any]:
    """Re-grade stored packs so old name-guess residuals are not shown as residual."""
    pack = dict(pack or {})
    findings = [_demote_bypass_finding(dict(f)) for f in (pack.get("findings") or [])]
    pack["findings"] = findings
    if pack.get("verdict"):
        pack["verdict"] = _recompute_bypass_verdict(str(pack.get("verdict") or "unknown"), findings)
    notes = pack.get("notes") or ""
    guessed = any(f.get("demoted") or looks_like_name_guess(str(f.get("evidence") or "")) for f in findings)
    if (guessed or looks_like_name_guess(notes) or _NAME_GUESS.search(notes)) and "系统注：" not in notes:
        pack["notes"] = (
            "系统注：按函数名猜测的路径（如「Free 即释放点」「若被未改路径调用」）"
            "且未引用汇编或调用差的，不能当作残留绕过；清单里此类项已降为未知。\n\n"
            + notes
        )
    return pack


def sanitize_residual_pack(pack: dict[str, Any] | None) -> dict[str, Any]:
    pack = dict(pack or {})
    findings = [_demote_residual_finding(dict(f)) for f in (pack.get("findings") or [])]
    pack["findings"] = findings
    if pack.get("verdict"):
        pack["verdict"] = _recompute_residual_verdict(str(pack.get("verdict") or "unknown"), findings)
    notes = pack.get("notes") or ""
    if any(f.get("demoted") for f in findings) and "系统注：" not in notes:
        pack["notes"] = (
            "系统注：仅因名字像热点（APC/Core/兄弟）且自身未改、又没有该函数汇编的，"
            "已降为 similar，不能当作已确认残留。\n\n" + notes
        )
    return pack


def bypass_section_markdown(pack: dict[str, Any] | None) -> str:
    pack = pack or {}
    _, title = BYPASS_VERDICTS.get(pack.get("verdict") or "", ("muted", "尚未评估"))
    rows = []
    for f in pack.get("findings") or []:
        rows.append(
            f"| {f.get('method') or '—'} | {f.get('target') or '—'} | {f.get('status') or '—'} "
            f"| {f.get('likelihood') or '—'} | {(f.get('evidence') or '—').replace('|', '/')} |"
        )
    table = (
        "\n".join(
            [
                "| 维度 | 涉及函数 | 状态 | 可能性 | 证据 |",
                "|---|---|---|---|---|",
                *rows,
            ]
        )
        if rows
        else "本样本未列出可核对的绕过面。"
    )
    notes = demote_h2((pack.get("notes") or "").strip()) or "尚无 BypassAnalyst 解读。"
    return "\n".join(
        [
            "## 18. 补丁完整性 / 绕过面",
            "",
            f"**结论**：{title}。{pack.get('summary') or ''}".strip(),
            "",
            "### 18.1 分析师解读",
            "",
            notes,
            "",
            "### 18.2 绕过面清单",
            "",
            table,
            "",
        ]
    )


def residual_section_markdown(pack: dict[str, Any] | None) -> str:
    pack = pack or {}
    _, title = RESIDUAL_VERDICTS.get(pack.get("verdict") or "", ("muted", "尚未评估"))
    rows = []
    for f in pack.get("findings") or []:
        rows.append(
            f"| {f.get('function') or '—'} | {f.get('pattern') or '—'} | {f.get('severity') or '—'} "
            f"| {f.get('status') or '—'} | {(f.get('evidence') or '—').replace('|', '/')} |"
        )
    table = (
        "\n".join(
            [
                "| 函数 | 模式 | 严重度 | 状态 | 证据 |",
                "|---|---|---|---|---|",
                *rows,
            ]
        )
        if rows
        else "未发现与本次根因同类的未修复函数。"
    )
    notes = demote_h2((pack.get("notes") or "").strip()) or "尚无 ResidualVulnAnalyst 解读。"
    return "\n".join(
        [
            "## 19. 残留漏洞 / 同类缺陷",
            "",
            f"**结论**：{title}。{pack.get('summary') or ''}".strip(),
            "",
            "### 19.1 分析师解读",
            "",
            notes,
            "",
            "### 19.2 嫌疑函数",
            "",
            table,
            "",
        ]
    )


def _replace_section(report: str, number: int, section: str) -> str:
    text = report or ""
    pattern = rf"(?ms)^##\s*{number}\.\s*.*?(?=^##\s*\d+\.|\Z)"
    if re.search(rf"(?m)^##\s*{number}\.\s*", text):
        return re.sub(pattern, lambda _m: section.rstrip() + "\n\n", text)
    return text.rstrip() + "\n\n" + section


def merge_review_pack(base: dict[str, Any] | None, extra: dict[str, Any] | None, *, kind: str, source: str) -> dict[str, Any]:
    """Fold a specialist pack into §18 (bypass) or §19 (residual) without dropping either."""
    base = dict(base or {})
    extra = extra if isinstance(extra, dict) else {}
    extra_findings = extra.get("findings") or []
    if not extra_findings and not extra.get("summary"):
        return base
    tagged = []
    for f in extra_findings:
        if not isinstance(f, dict):
            continue
        row = dict(f)
        row["source"] = source
        tagged.append(row)
    merged = list(base.get("findings") or []) + tagged
    base["findings"] = merged
    if extra.get("summary"):
        extra_sum = str(extra.get("summary") or "").strip()
        if extra_sum and extra_sum not in str(base.get("summary") or ""):
            base["summary"] = (str(base.get("summary") or "").strip() + ("；" if base.get("summary") else "") + f"{source}：{extra_sum}").strip("；")
    if kind == "bypass":
        rank = {"bypassable": 3, "partial": 2, "unknown": 1, "closed": 0}
    else:
        rank = {"likely": 3, "suspects": 2, "unknown": 1, "none": 0}
    bv = str(base.get("verdict") or "unknown")
    ev = str(extra.get("verdict") or "unknown")
    if rank.get(ev, 0) > rank.get(bv, 0):
        base["verdict"] = ev
    if kind == "bypass":
        return sanitize_bypass_pack(base)
    return sanitize_residual_pack(base)


def ensure_bypass_section(report: str, pack: dict[str, Any] | None) -> str:
    return _replace_section(report, 18, bypass_section_markdown(pack))


def ensure_residual_section(report: str, pack: dict[str, Any] | None) -> str:
    return _replace_section(report, 19, residual_section_markdown(pack))
