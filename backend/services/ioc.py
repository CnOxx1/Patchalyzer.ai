"""Deterministic IOC pack for SOC: hashes, versions, APIs, hunt tables."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .mdutil import demote_h2

USER_API_RE = re.compile(
    r"^(socket|bind|listen|accept|connect|closesocket|getsockopt|setsockopt|"
    r"recvfrom|sendto|WSA|DeviceIoControl|CreateFile)",
    re.I,
)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)


def file_hashes(path: str | Path | None) -> dict[str, str]:
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    data = p.read_bytes()
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _ensure_hashes(pe: dict[str, Any] | None) -> dict[str, Any]:
    pe = dict(pe or {})
    if pe.get("sha256"):
        return pe
    pe.update(file_hashes(pe.get("path")))
    return pe


def _debug_guid(pe: dict[str, Any] | None) -> str:
    for d in (pe or {}).get("debug") or []:
        guid = d.get("guid_compact") or d.get("guid")
        if guid:
            age = d.get("age")
            return f"{guid}{age}" if age is not None else str(guid)
    return ""


def _cve_from(*blobs: Any) -> str:
    for blob in blobs:
        if not blob:
            continue
        if isinstance(blob, dict):
            for key in ("cve", "CVE", "title"):
                m = CVE_RE.search(str(blob.get(key) or ""))
                if m:
                    return m.group(0).upper()
            m = CVE_RE.search(str(blob))
        else:
            m = CVE_RE.search(str(blob))
        if m:
            return m.group(0).upper()
    return ""


def _identity(role: str, label: str, pe: dict[str, Any] | None, version_hint: str = "") -> dict[str, Any]:
    pe = _ensure_hashes(pe)
    return {
        "role": role,
        "label": label,
        "filename": pe.get("original_filename") or (Path(pe.get("path")).name if pe.get("path") else ""),
        "file_version": version_hint or pe.get("file_version") or "",
        "machine": pe.get("machine") or "",
        "size": pe.get("size"),
        "timestamp_utc": pe.get("timestamp_utc") or "",
        "md5": pe.get("md5") or "",
        "sha1": pe.get("sha1") or "",
        "sha256": pe.get("sha256") or "",
        "pdb_guid": _debug_guid(pe),
        "path": pe.get("path") or "",
    }


def _split_apis(names: list[str]) -> tuple[list[str], list[str]]:
    user, kernel, seen_u, seen_k = [], [], set(), set()
    for raw in names:
        name = (raw or "").strip().strip("`")
        if not name:
            continue
        key = name.lower()
        if USER_API_RE.search(name):
            if key not in seen_u:
                seen_u.add(key)
                user.append(name if name.endswith("()") or "(" in name else f"{name}()")
        else:
            if key not in seen_k:
                seen_k.add(key)
                kernel.append(name)
    return user, kernel


def build_ioc_pack(
    *,
    title: str = "",
    old_pe: dict[str, Any] | None = None,
    new_pe: dict[str, Any] | None = None,
    mid_pe: dict[str, Any] | None = None,
    symbol_diff: dict[str, Any] | None = None,
    feature_trace: dict[str, Any] | None = None,
    disassembly: list | None = None,
    vuln_chain: dict[str, Any] | None = None,
    patch_resolve: dict[str, Any] | None = None,
    detection_notes: str = "",
    labels: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Structured IOCs + hunt inputs. Hashes come from files on disk when missing."""
    old_pe = _ensure_hashes(old_pe)
    new_pe = _ensure_hashes(new_pe)
    mid_pe = _ensure_hashes(mid_pe) if mid_pe else {}
    labels = labels or {}
    pr = patch_resolve or {}
    chain = vuln_chain or {}
    resized = list((symbol_diff or {}).get("functions_resized") or [])
    resized.sort(key=lambda f: abs(f.get("delta") or 0), reverse=True)
    call_by_name = {b.get("name"): b for b in (disassembly or []) if b.get("name")}

    functions = []
    for f in resized[:16]:
        block = call_by_name.get(f.get("name")) or {}
        functions.append(
            {
                "name": f.get("name"),
                "old_rva": f.get("old_rva") or (block.get("old") or {}).get("rva"),
                "new_rva": f.get("new_rva") or (block.get("new") or {}).get("rva"),
                "old_size": f.get("old"),
                "new_size": f.get("new"),
                "delta": f.get("delta"),
                "calls_added": (block.get("calls_added") or [])[:12],
                "calls_removed": (block.get("calls_removed") or [])[:12],
            }
        )

    features = []
    for feat in (feature_trace or {}).get("features") or []:
        xrefs = feat.get("xrefs") or []
        features.append(
            {
                "feature_id": feat.get("feature_id"),
                "featureState_rva": feat.get("featureState_rva"),
                "on_disk_dword": feat.get("on_disk_dword"),
                "gated_functions": list(dict.fromkeys(x.get("in_function") for x in xrefs if x.get("in_function")))[:12],
                "xref_rvas": [x.get("rva") for x in xrefs if x.get("rva")][:12],
            }
        )

    api_names: list[str] = []
    hunts: list[dict[str, Any]] = []
    for st in chain.get("steps") or []:
        apis = list(st.get("apis") or [])
        api_names.extend(apis)
        loc = st.get("location") or ""
        action = st.get("action") or st.get("detail") or st.get("title") or ""
        if apis or action:
            hunts.append(
                {
                    "n": st.get("n"),
                    "location": loc,
                    "apis": apis,
                    "action": action,
                    "evidence": st.get("evidence") or "",
                }
            )
    user_apis, kernel_apis = _split_apis(api_names)

    notes = (detection_notes or "").strip()
    if notes.startswith("（跳过") or notes.startswith("（失败"):
        notes = ""

    return {
        "product": "Patchalyzer.ai",
        "title": title,
        "cve": _cve_from(pr, title, pr.get("msrc_title")),
        "component": pr.get("old_file") or old_pe.get("original_filename") or "",
        "kbs": pr.get("matched_kbs") or pr.get("kbs") or [],
        "identity": [
            _identity("vulnerable", labels.get("old") or "漏洞版", old_pe, pr.get("old_version") or ""),
            _identity("patched", labels.get("new") or "修复版", new_pe, pr.get("new_version") or ""),
            *(
                [_identity("earlier", labels.get("mid") or "更早版本", mid_pe)]
                if mid_pe.get("path") or mid_pe.get("sha256")
                else []
            ),
        ],
        "functions": functions,
        "features": features,
        "apis": {"user_mode": user_apis, "kernel": kernel_apis},
        "hunts": hunts[:12],
        "detection_notes": notes,
        "has_detection": bool(notes),
    }


def build_ioc_pack_from_artifacts(art: dict[str, Any], title: str = "") -> dict[str, Any]:
    notes = (art.get("agent_notes") or {}).get("detection") or ""
    return build_ioc_pack(
        title=title or art.get("title") or "",
        old_pe=art.get("old_pe"),
        new_pe=art.get("new_pe"),
        mid_pe=art.get("mid_pe"),
        symbol_diff=art.get("symbol_diff"),
        feature_trace=art.get("feature_trace"),
        disassembly=art.get("disassembly"),
        vuln_chain=art.get("vuln_chain"),
        patch_resolve=art.get("patch_resolve"),
        detection_notes=notes,
        labels=art.get("labels"),
    )


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_无_\n"
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        cells = [str(c if c not in (None, "") else "—") for c in row]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def ioc_section_markdown(pack: dict[str, Any]) -> str:
    """Canonical §16 for reports — hashes are copied from the pack, never invented."""
    ident_rows = []
    for item in pack.get("identity") or []:
        ident_rows.append(
            [
                item.get("role") or "",
                item.get("filename") or "",
                item.get("file_version") or "",
                item.get("machine") or "",
                f"`{item['sha256']}`" if item.get("sha256") else "—",
                f"`{item['md5']}`" if item.get("md5") else "—",
            ]
        )
    api_u = pack.get("apis", {}).get("user_mode") or []
    api_k = pack.get("apis", {}).get("kernel") or []
    feat_rows = [
        [
            f.get("feature_id") or "",
            f.get("featureState_rva") or "",
            f.get("on_disk_dword") if f.get("on_disk_dword") is not None else "",
            ", ".join(f.get("gated_functions") or []) or "—",
        ]
        for f in pack.get("features") or []
    ]
    fn_rows = [
        [
            f"`{f.get('name')}`",
            f.get("old_rva") or "",
            f.get("new_rva") or "",
            f.get("old_size") if f.get("old_size") is not None else "",
            f.get("new_size") if f.get("new_size") is not None else "",
            f.get("delta") if f.get("delta") is not None else "",
        ]
        for f in pack.get("functions") or []
    ]
    hunt_rows = [
        [
            h.get("n") or "",
            h.get("location") or "",
            ", ".join(h.get("apis") or []) or "—",
            (h.get("action") or "")[:80],
        ]
        for h in pack.get("hunts") or []
    ]
    vuln = next((i for i in pack.get("identity") or [] if i.get("role") == "vulnerable"), {})
    patched = next((i for i in pack.get("identity") or [] if i.get("role") == "patched"), {})
    cve = pack.get("cve") or ""
    component = pack.get("component") or vuln.get("filename") or ""
    sigma = []
    if vuln.get("sha256"):
        sigma.append(
            "```yaml\n"
            f"title: Patchalyzer.ai vulnerable driver {cve or component or ''}\n"
            "logsource:\n  product: windows\n  category: image_load\n"
            "detection:\n  selection:\n"
            f"    Hashes|contains: '{vuln['sha256']}'\n"
            + (f"    OriginalFileName: '{component}'\n" if component else "")
            + (f"    FileVersion: '{vuln.get('file_version')}'\n" if vuln.get("file_version") else "")
            + "  condition: selection\n"
            "falsepositives:\n  - 已打补丁但仍缓存旧映像的安装介质\n"
            "level: high\n```"
        )
    notes = demote_h2((pack.get("detection_notes") or "").strip())
    if not notes:
        notes = (
            "可依据上表做资产清点：匹配漏洞版 SHA256 / FileVersion，"
            "并关注用户态 API 时序与热点内核函数。"
        )
    kbs = pack.get("kbs") or []
    head = [
        "## 16. IOC / 检测方法",
        "",
        "文件哈希与版本号来自样本实算，可用于资产清点与威胁狩猎。",
        "",
        f"- CVE：`{cve or '（标题未解析到 CVE）'}`",
        f"- 组件：`{component or '—'}`",
        f"- 建议补丁版本：`{patched.get('file_version') or '见修复版样本'}`"
        + (f"（KB{', KB'.join(str(k) for k in kbs)}）" if kbs else ""),
        "",
        "### 16.1 样本身份（IOC）",
        "",
        _md_table(["角色", "文件名", "FileVersion", "架构", "SHA256", "MD5"], ident_rows),
        "### 16.2 行为检测线索",
        "",
        f"- 用户态 API：{', '.join(f'`{x}`' for x in api_u) or '（漏洞链未抽出用户态 API）'}",
        f"- 内核函数：{', '.join(f'`{x}`' for x in api_k) or '（见热点函数表）'}",
        "",
        _md_table(["步骤", "位置", "API/函数", "动作"], hunt_rows) if hunt_rows else "",
        "### 16.3 Feature / 热点函数",
        "",
        _md_table(["Feature", "featureState RVA", "on-disk", "门控函数"], feat_rows) if feat_rows else "无新增 Feature。\n",
        _md_table(["函数", "Old RVA", "New RVA", "Old size", "New size", "Δ"], fn_rows),
        "### 16.4 示例 Sigma（映像加载）",
        "",
        "\n".join(sigma) if sigma else "缺少漏洞版 SHA256，无法生成映像加载规则。",
        "",
        "### 16.5 运营检测方法",
        "",
        notes,
        "",
    ]
    return "\n".join(head).rstrip() + "\n"


def ensure_ioc_section(report: str, pack: dict[str, Any]) -> str:
    section = ioc_section_markdown(pack)
    text = report or ""
    if re.search(r"(?m)^##\s*16\.\s*", text):
        return re.sub(
            r"(?ms)^##\s*16\.\s*.*?(?=^##\s*\d+\.|\Z)",
            lambda _m: section.rstrip() + "\n\n",
            text,
        )
    return text.rstrip() + "\n\n" + section
