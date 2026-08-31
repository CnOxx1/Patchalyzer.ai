"""Fill missing ## 1.–## 15. when ReportWriter only emitted §16–§19."""
from __future__ import annotations

import re
from typing import Any

from .ioc import ioc_section_markdown
from .patch_review import bypass_section_markdown, residual_section_markdown
from .pipeline import unwrap_markdown_fence
from .threat_intel import threat_section_markdown

SECTION_TITLES = {
    1: "执行摘要",
    2: "分析方法论",
    3: "CVE/MSRC 描述对照",
    4: "漏洞根因",
    5: "竞态/同步时序",
    6: "漏洞链",
    7: "汇编证据",
    8: "伪代码对比",
    9: "状态机/标志位",
    10: "Feature 开关",
    11: "用户态触发面",
    12: "利用难度与影响",
    13: "对照路径排除",
    14: "修复有效性与残余风险",
    15: "附录",
    16: "IOC / 检测方法",
    17: "在野利用 / 威胁情报",
    18: "补丁完整性 / 绕过面",
    19: "残留漏洞 / 同类缺陷",
}

_H2 = re.compile(r"(?m)^(##\s*(\d+)\.\s[^\n]*)")


def report_section_numbers(md: str) -> set[int]:
    return {int(n) for n in re.findall(r"(?m)^##\s*(\d+)\.\s", md or "") if n.isdigit() and 1 <= int(n) <= 19}


def _demote(text: str) -> str:
    s = unwrap_markdown_fence(text or "").strip()
    if not s:
        return ""
    return re.sub(r"(?m)^#{1,2} ", "### ", s).strip()


def _notes(art: dict[str, Any], key: str) -> str:
    notes = art.get("agent_notes") if isinstance(art.get("agent_notes"), dict) else {}
    return _demote(str(notes.get(key) or ""))


def _pe(art: dict[str, Any], side: str) -> dict[str, Any]:
    pe = art.get(side)
    return pe if isinstance(pe, dict) else {}


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return ""
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join("" if c is None else str(c) for c in row) + " |")
    return "\n".join(lines)


def split_numbered_report(md: str) -> tuple[str, dict[int, str]]:
    text = unwrap_markdown_fence(md or "").replace("\r\n", "\n")
    hits = list(_H2.finditer(text))
    preamble = text[: hits[0].start()].strip() if hits else text.strip()
    sections: dict[int, str] = {}
    for i, m in enumerate(hits):
        n = int(m.group(2))
        if n < 1 or n > 19 or n in sections:
            continue
        end = hits[i + 1].start() if i + 1 < len(hits) else len(text)
        sections[n] = text[m.start() : end].rstrip() + "\n"
    return preamble, sections


def _fill_1(art: dict[str, Any]) -> str:
    conc = art.get("conclusions") if isinstance(art.get("conclusions"), dict) else {}
    pr = art.get("patch_resolve") if isinstance(art.get("patch_resolve"), dict) else {}
    old, new = _pe(art, "old_pe"), _pe(art, "new_pe")
    sd = art.get("symbol_diff") if isinstance(art.get("symbol_diff"), dict) else {}
    resized = sd.get("functions_resized") or []
    intel = art.get("threat_intel") if isinstance(art.get("threat_intel"), dict) else {}
    cve = intel.get("cve") or pr.get("cve") or art.get("title") or ""
    one = conc.get("root_one_liner") or ""
    cut = conc.get("patch_cut") or ""
    table = _md_table(
        ["项", "值"],
        [
            ["CVE", cve or "—"],
            ["组件", pr.get("old_file") or old.get("original_filename") or "—"],
            ["漏洞版", old.get("file_version") or art.get("old_label") or "—"],
            ["修复版", new.get("file_version") or art.get("new_label") or "—"],
            ["架构", old.get("machine") or new.get("machine") or "—"],
            ["尺寸变化函数", str(len(resized))],
            ["根因一句话", one or "见 §4"],
            ["补丁切断点", cut or "见 §6.4"],
            ["在野", "CISA KEV" if intel.get("in_kev") else "未列入 KEV / 待查"],
        ],
    )
    return f"## 1. 执行摘要\n\n{table}\n\n**漏洞链一句话**：{one or '见 §6。'}\n"


def _fill_2(art: dict[str, Any]) -> str:
    conc = art.get("conclusions") if isinstance(art.get("conclusions"), dict) else {}
    cut = conc.get("patch_cut") or "补丁落点见尺寸时间线 §15。"
    return (
        "## 2. 分析方法论\n\n"
        "| 步骤 | 做法 |\n| --- | --- |\n"
        "| 样本 | Winbindex/MSDL 或上传的漏洞版与修复版 PE |\n"
        "| 符号 | PDB / 导出符号；缺失时按 .pdata 尺寸差挑热点 |\n"
        "| 证据 | 反汇编、CFG、Feature xref、对照路径 |\n"
        "| 热点 | 尺寸变化优先，其次 Feature / 字节差 |\n\n"
        f"{cut}\n"
    )


def _fill_3(art: dict[str, Any]) -> str:
    intel = art.get("threat_intel") if isinstance(art.get("threat_intel"), dict) else {}
    nvd = intel.get("nvd") if isinstance(intel.get("nvd"), dict) else {}
    cve = intel.get("cve") or ""
    blob = nvd.get("description") or intel.get("summary") or ""
    extra = _notes(art, "pe")
    body = blob.strip() or "公开公告未给出可核对的补丁说明，下列对照以 diff 证据为准【推断】。"
    return (
        f"## 3. CVE/MSRC 描述对照\n\n"
        f"- CVE：`{cve or '（未解析）'}`\n"
        f"- NVD：{nvd.get('cvss') or '—'} {nvd.get('severity') or ''}\n\n"
        f"{body}\n"
        + (f"\n{extra}\n" if extra else "")
    )


def _fill_4(art: dict[str, Any]) -> str:
    body = _notes(art, "root_cause") or _notes(art, "symbol") or "尚无根因专家笔记。"
    return f"## 4. 漏洞根因\n\n{body}\n"


def _fill_5(art: dict[str, Any]) -> str:
    body = _notes(art, "disasm")
    if not body:
        body = "未能从当前样本证实独立竞态窗口。缺陷按同步/校验缺失理解，详见 §4 与 §6。"
    return f"## 5. 竞态/同步时序\n\n{body}\n"


def _fill_6(art: dict[str, Any]) -> str:
    chain = art.get("vuln_chain") if isinstance(art.get("vuln_chain"), dict) else {}
    conc = art.get("conclusions") if isinstance(art.get("conclusions"), dict) else {}
    steps = chain.get("steps") or []
    rows = []
    for i, st in enumerate(steps, 1):
        if not isinstance(st, dict):
            continue
        apis = st.get("apis") or []
        rows.append(
            [
                str(st.get("n") or i),
                st.get("location") or "—",
                st.get("title") or st.get("action") or "—",
                ", ".join(apis) if isinstance(apis, list) else (apis or "—"),
                "—",
                (st.get("detail") or st.get("action") or "")[:80],
                "【已证实】" if chain.get("present") else "【推断】",
            ]
        )
    table = _md_table(
        ["步骤", "位置", "动作", "函数/API", "对象/偏移", "结果", "证据"],
        rows,
    ) or "漏洞链步骤见根因笔记。"
    md = (chain.get("markdown") or "").strip()
    return (
        "## 6. 漏洞链\n\n"
        "### 6.1 链路总览\n\n"
        f"{table}\n\n"
        "### 6.2 函数逻辑链\n\n"
        "系统将在打开「漏洞链」页时用调用差覆盖本节图。\n\n"
        "### 6.3 原语与影响\n\n"
        f"{md or '见 §4。'}\n\n"
        "### 6.4 补丁如何切断链路\n\n"
        f"{conc.get('patch_cut') or '切断点见尺寸变化最大的函数，详见 §7 / §14。'}\n"
    )


def _fill_7(art: dict[str, Any]) -> str:
    body = _notes(art, "disasm")
    blocks = art.get("disassembly") if isinstance(art.get("disassembly"), list) else []
    lines = ["## 7. 汇编证据\n"]
    if body:
        lines += [body, ""]
    for b in blocks[:5]:
        if not isinstance(b, dict):
            continue
        old, new = b.get("old") or {}, b.get("new") or {}
        if not isinstance(old, dict):
            old = {}
        if not isinstance(new, dict):
            new = {}
        added = ", ".join((b.get("calls_added") or [])[:8]) or "—"
        removed = ", ".join((b.get("calls_removed") or [])[:8]) or "—"
        d = (new.get("size") or 0) - (old.get("size") or 0)
        lines.append(
            f"### `{b.get('name') or '—'}`\n\n"
            f"- 旧 RVA `{old.get('rva') or '—'}` · {old.get('size') or '—'} B\n"
            f"- 新 RVA `{new.get('rva') or '—'}` · {new.get('size') or '—'} B · Δ {d:+d}\n"
            f"- 新增调用：{added}\n"
            f"- 删除调用：{removed}\n"
        )
    if len(lines) == 1:
        lines.append("无热点反汇编。见工作目录 `disasm/`。\n")
    return "\n".join(lines)


def _fill_8(art: dict[str, Any]) -> str:
    body = _notes(art, "symbol") or "以调用差与尺寸变化为准，伪代码见反汇编页。"
    return f"## 8. 伪代码对比\n\n{body}\n"


def _fill_9(_art: dict[str, Any]) -> str:
    return "## 9. 状态机/标志位\n\n本样本未单独抽出可核对的状态机字段变更。Feature 门控见 §10。\n"


def _fill_10(art: dict[str, Any]) -> str:
    body = _notes(art, "feature")
    ft = art.get("feature_trace") if isinstance(art.get("feature_trace"), dict) else {}
    feats = ft.get("features") or []
    rows = []
    for f in feats[:16]:
        if not isinstance(f, dict):
            continue
        rows.append(
            [
                f.get("feature_id") or f.get("name") or "—",
                f.get("featureState_rva") or "—",
                f.get("on_disk_dword") if f.get("on_disk_dword") is not None else "—",
                ", ".join(f.get("gated_functions") or [])[:80] or "—",
            ]
        )
    table = _md_table(["Feature", "featureState RVA", "on-disk", "门控函数"], rows)
    if not table and not body:
        return "## 10. Feature 开关\n\n无新增 Feature_* 符号，修复可能是纯校验/锁路径。\n"
    return f"## 10. Feature 开关\n\n{table}\n\n{body}\n".strip() + "\n"


def _fill_11(art: dict[str, Any]) -> str:
    pack = art.get("ioc_pack") if isinstance(art.get("ioc_pack"), dict) else {}
    apis = (pack.get("apis") or {}).get("user_mode") or []
    if apis:
        items = "\n".join(f"- `{a}`" for a in apis[:24])
        return f"## 11. 用户态触发面\n\n{items}\n\n与 §6 步骤的对应关系见漏洞链页。\n"
    return "## 11. 用户态触发面\n\n未抽出用户态 API。触发面在内核路径上，见 §6。\n"


def _fill_12(art: dict[str, Any]) -> str:
    intel = art.get("threat_intel") if isinstance(art.get("threat_intel"), dict) else {}
    nvd = intel.get("nvd") if isinstance(intel.get("nvd"), dict) else {}
    return (
        "## 12. 利用难度与影响\n\n"
        f"- 目录评分：{nvd.get('cvss') or '—'} {nvd.get('severity') or ''}\n"
        f"- 在野：{'CISA KEV' if intel.get('in_kev') else '未列入 KEV'}\n"
        "- 概念影响与原语见 §6.3。禁止在此复述逐步利用。\n"
    )


def _fill_13(art: dict[str, Any]) -> str:
    body = _notes(art, "control") or "对照路径见「对照」页。尺寸未变且仅重定位的函数可排除。"
    return f"## 13. 对照路径排除\n\n{body}\n"


def _fill_14(art: dict[str, Any]) -> str:
    bypass = art.get("bypass_pack") if isinstance(art.get("bypass_pack"), dict) else {}
    residual = art.get("residual_pack") if isinstance(art.get("residual_pack"), dict) else {}
    conc = art.get("conclusions") if isinstance(art.get("conclusions"), dict) else {}
    return (
        "## 14. 修复有效性与残余风险\n\n"
        f"- 绕过面结论：`{bypass.get('verdict') or 'unknown'}`，细节见 §18。\n"
        f"- 残留结论：`{residual.get('verdict') or 'unknown'}`，细节见 §19。\n"
        f"- {conc.get('patch_cut') or '切断点见 §6.4。'}\n"
    )


def _fill_15(art: dict[str, Any]) -> str:
    sd = art.get("symbol_diff") if isinstance(art.get("symbol_diff"), dict) else {}
    resized = [f for f in (sd.get("functions_resized") or []) if isinstance(f, dict)]
    resized.sort(key=lambda f: abs(int(f.get("delta") or 0)), reverse=True)
    rows = [
        [
            f"`{f.get('name') or '—'}`",
            f.get("old") or f.get("old_size") or "—",
            f.get("new") or f.get("new_size") or "—",
            f.get("delta") if f.get("delta") is not None else "—",
        ]
        for f in resized[:24]
    ]
    table = _md_table(["函数", "Old", "New", "Δ"], rows) or "无尺寸变化表。"
    return (
        "## 15. 附录\n\n"
        f"{table}\n\n"
        "产物：`cfg_diff.html`、`feature_trace.json`、`disasm/`、`verify/`、`ioc.json`。\n"
    )


_FILLERS = {
    1: _fill_1,
    2: _fill_2,
    3: _fill_3,
    4: _fill_4,
    5: _fill_5,
    6: _fill_6,
    7: _fill_7,
    8: _fill_8,
    9: _fill_9,
    10: _fill_10,
    11: _fill_11,
    12: _fill_12,
    13: _fill_13,
    14: _fill_14,
    15: _fill_15,
}


def needs_report_complete(md: str) -> bool:
    nums = report_section_numbers(md)
    return 1 not in nums or 6 not in nums


def heal_artifacts_report(artifacts: dict[str, Any] | None) -> bool:
    """Fill missing §1–§15 in place. Return True if llm_report changed."""
    art = artifacts if isinstance(artifacts, dict) else None
    if not art:
        return False
    raw = str(art.get("llm_report") or "")
    if not raw.strip() or not needs_report_complete(raw):
        return False
    filled = complete_llm_report(raw, art)
    if filled == raw:
        return False
    art["llm_report"] = filled
    return True


def complete_llm_report(report: str, artifacts: dict[str, Any] | None) -> str:
    """Ensure the 19 numbered sections exist. Keep LLM prose when present."""
    art = artifacts if isinstance(artifacts, dict) else {}
    _, found = split_numbered_report(report)
    parts: list[str] = []
    for n in range(1, 20):
        body = (found.get(n) or "").strip()
        if n <= 15 and (not body or not re.search(rf"(?m)^##\s*{n}\.", body)):
            parts.append(_FILLERS[n](art).rstrip())
            continue
        if n >= 16 and not body:
            if n == 16:
                parts.append(ioc_section_markdown(art.get("ioc_pack") or {}).rstrip())
            elif n == 17:
                parts.append(threat_section_markdown(art.get("threat_intel") or {}).rstrip())
            elif n == 18:
                parts.append(bypass_section_markdown(art.get("bypass_pack") or {}).rstrip())
            else:
                parts.append(residual_section_markdown(art.get("residual_pack") or {}).rstrip())
            continue
        parts.append(body)
    return "\n\n".join(p for p in parts if p).rstrip() + "\n"
