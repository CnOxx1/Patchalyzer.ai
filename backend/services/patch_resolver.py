"""Resolve a patched Windows PE via MSRC CVE + Winbindex + Microsoft symbol server."""
from __future__ import annotations

import gzip
import json
import re
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.request import Request, urlopen

from ..config import DATA_DIR
from .analyzer import download_pdb, extract_pe

_PE_CACHE_LOCKS_GUARD = threading.Lock()
_PE_CACHE_LOCKS: dict[str, threading.Lock] = {}


def _pe_cache_lock(key: str) -> threading.Lock:
    with _PE_CACHE_LOCKS_GUARD:
        return _PE_CACHE_LOCKS.setdefault(key, threading.Lock())

WINBINDEX_URLS = [
    "https://raw.githubusercontent.com/m417z/winbindex/gh-pages/data/by_filename_compressed/{name}.json.gz",
    "https://winbindex.m417z.com/data/by_filename_compressed/{name}.json.gz",
]
MSRC_UPDATES = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
MSRC_CVRF = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{doc_id}"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
VER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)\.(\d+)")
MONTH_RE = re.compile(r"^\d{4}-[A-Z][a-z]{2}$")
_MONTH_ZH = {
    "Jan": "1 月",
    "Feb": "2 月",
    "Mar": "3 月",
    "Apr": "4 月",
    "May": "5 月",
    "Jun": "6 月",
    "Jul": "7 月",
    "Aug": "8 月",
    "Sep": "9 月",
    "Oct": "10 月",
    "Nov": "11 月",
    "Dec": "12 月",
}
FILE_IN_TEXT = re.compile(r"\b([A-Za-z][\w-]+\.(?:sys|dll|exe))\b", re.I)
HTML_TAG = re.compile(r"<[^>]+>")
SKIP_BULLETIN_TITLE = re.compile(
    r"Edge|Chrome|Office|Excel|Word|SharePoint|Azure|Visual Studio|\.NET|SQL Server|"
    r"Power BI|Dynamics|Exchange|Teams|Outlook|Microsoft 365|GitHub|Copilot|Azure DevOps|"
    r"PowerPoint|OneNote|Access\b|Publisher\b",
    re.I,
)
UA_JSON = {"User-Agent": "Patchalyzer.ai/1.0", "Accept": "application/json"}
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][\w.\-]{1,80}\.(sys|dll|exe)$", re.I)

# More specific phrases first. Used when MSRC title does not name the file.
COMPONENT_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("lua file virtualization", "luafv"), "luafv.sys"),
    (("ancillary function", "winsock"), "afd.sys"),
    (("kernel streaming",), "ks.sys"),
    (("win32k", "win32k.sys"), "win32k.sys"),
    (("common log file", " clfs"), "clfs.sys"),
    (("cloud files mini", "cldflt"), "cldflt.sys"),
    (("bind filter", "bindflt"), "bindflt.sys"),
    (("resilient file system", " refs"), "refs.sys"),
    ((" ntfs", "windows ntfs"), "ntfs.sys"),
    (("smb client", "mini-redirector", "mrxsmb"), "mrxsmb.sys"),
    (("smb server", "windows smb"), "srv2.sys"),
    (("tcp/ip", "tcpip"), "tcpip.sys"),
    (("http.sys", "windows http"), "http.sys"),
    (("ndis",), "ndis.sys"),
    (("network address translation", "windows nat"), "ipnat.sys"),
    (("kernel-mode driver framework", "wdf01000"), "wdf01000.sys"),
    (("directx graphics kernel", "dxgkrnl"), "dxgkrnl.sys"),
    (("usb hub", "usbhub"), "usbhub3.sys"),
    (("bluetooth", "bthport"), "bthport.sys"),
    (("storport",), "storport.sys"),
    (("spaceport",), "spaceport.sys"),
    (("virtual hard disk", "vhdmp"), "vhdmp.sys"),
    (("encrypting file system",), "ksecdd.sys"),
    (("code integrity",), "ci.dll"),
    (("windows kernel", "ntoskrnl"), "ntoskrnl.exe"),
]


class PatchResolveError(Exception):
    """User-facing: could not automatically obtain the patched binary."""


def _http_get(url: str, headers: dict[str, str] | None = None, timeout: int = 90) -> bytes:
    req = Request(url, headers=headers or UA_JSON)
    with urlopen(req, context=ssl.create_default_context(), timeout=timeout) as resp:
        return resp.read()


def parse_version(text: str) -> tuple[int, int, int, int] | None:
    m = VER_RE.search(text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


def normalize_cve(text: str) -> str:
    m = re.search(r"CVE-\d{4}-\d{4,}", text or "", re.I)
    if not m:
        raise PatchResolveError("请填写有效的 CVE 编号，例如 CVE-2026-68820")
    return m.group(0).upper()


def _kb_num(text: str) -> str:
    m = re.search(r"(\d{6,7})", text or "")
    return m.group(1) if m else ""


def lookup_cve_msrc(cve: str) -> dict[str, Any]:
    cve = normalize_cve(cve)
    cache = DATA_DIR / "cache" / "msrc" / f"{cve}.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if cache.exists():
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    catalog = json.loads(_http_get(MSRC_UPDATES))
    months = [
        x
        for x in catalog.get("value") or []
        if MONTH_RE.match(str(x.get("ID") or ""))
    ]
    months.sort(key=lambda x: x.get("CurrentReleaseDate") or x.get("InitialReleaseDate") or "", reverse=True)
    for item in months[:14]:
        doc_id = item["ID"]
        cvrf = json.loads(_http_get(MSRC_CVRF.format(doc_id=doc_id)))
        for vuln in cvrf.get("Vulnerability") or []:
            if (vuln.get("CVE") or "").upper() != cve:
                continue
            title = (vuln.get("Title") or {}).get("Value") or cve
            kbs = []
            seen = set()
            for rem in vuln.get("Remediations") or []:
                desc = rem.get("Description")
                val = desc.get("Value") if isinstance(desc, dict) else ""
                kb = _kb_num(val) or _kb_num(rem.get("URL") or "")
                if kb and kb not in seen:
                    seen.add(kb)
                    kbs.append(kb)
            result = {
                "cve": cve,
                "title": title,
                "bulletin": doc_id,
                "kbs": kbs,
                "cwe": [c.get("ID") for c in (vuln.get("CWE") or []) if c.get("ID")],
            }
            cache.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
            return result
    raise PatchResolveError(f"MSRC 近一年月度公告中未找到 {cve}，请核对编号或手动上传修复版")


def _load_winbindex(filename: str) -> dict[str, Any]:
    cache = DATA_DIR / "cache" / "winbindex" / f"{filename}.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if cache.exists() and cache.stat().st_size > 100:
        return json.loads(cache.read_text(encoding="utf-8"))
    last_err = None
    for attempt in range(3):
        for tmpl in WINBINDEX_URLS:
            url = tmpl.format(name=filename)
            try:
                raw = _http_get(url, timeout=120)
                data = json.loads(gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw)
                cache.write_text(json.dumps(data), encoding="utf-8")
                return data
            except Exception as e:
                last_err = e
        if attempt < 2:
            time.sleep(0.6 * (attempt + 1))
    raise PatchResolveError(f"无法获取 Winbindex 索引（{filename}）：{last_err}")


def _entry_kbs(entry: dict) -> set[str]:
    out = set()
    for _winver, updates in (entry.get("windowsVersions") or {}).items():
        if not isinstance(updates, dict):
            continue
        for key in updates:
            n = _kb_num(str(key))
            if n:
                out.add(n)
    return out


def _entry_arch(entry: dict) -> str:
    for updates in (entry.get("windowsVersions") or {}).values():
        if not isinstance(updates, dict):
            continue
        for meta in updates.values():
            if not isinstance(meta, dict):
                continue
            for asm in (meta.get("assemblies") or {}).values():
                ident = (asm or {}).get("assemblyIdentity") or {}
                arch = (ident.get("processorArchitecture") or "").lower()
                if arch:
                    return arch
    return ""


def _binary_url(filename: str, timestamp: int, virtual_size: int) -> str:
    return f"https://msdl.microsoft.com/download/symbols/{filename}/{timestamp:08X}{virtual_size:x}/{filename}"


def resolve_patched_binary(
    old_sys: Path,
    cve: str,
    dest: Path,
    progress_cb: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    """Download the patched sibling of old_sys for this CVE. Raises PatchResolveError."""

    def step(msg: str, pct: int):
        if progress_cb:
            progress_cb(msg, pct)

    step("读取漏洞样本 PE 版本", 4)
    pe = extract_pe(old_sys)
    filename = (pe.get("original_filename") or old_sys.name).split("\\")[-1].split("/")[-1]
    if not filename.lower().endswith((".sys", ".dll", ".exe")):
        filename = old_sys.name
    old_ver = parse_version(pe.get("file_version") or "")
    if not old_ver:
        raise PatchResolveError("无法从样本读取 FileVersion，请改用手动上传修复版")
    machine = pe.get("machine") or "AMD64"
    want_arch = "amd64" if machine == "AMD64" else "x86" if machine == "I386" else ""

    step(f"查询 MSRC {normalize_cve(cve)}", 8)
    msrc = lookup_cve_msrc(cve)
    kb_set = set(msrc["kbs"])
    if not kb_set:
        raise PatchResolveError(f"{msrc['cve']} 在 MSRC 中没有 KB 修复项，请手动上传修复版")

    step(f"检索 Winbindex {filename}", 12)
    index = _load_winbindex(filename)
    kb_hits = []
    same_branch = []
    already_patched = []
    for sha, entry in index.items():
        fi = entry.get("fileInfo") or {}
        ver = parse_version(fi.get("version") or "")
        ts, vs = fi.get("timestamp"), fi.get("virtualSize")
        if not ver or not ts or not vs:
            continue
        if ver[:3] != old_ver[:3]:
            continue
        arch = _entry_arch(entry)
        if want_arch and arch and arch != want_arch:
            continue
        entry_kbs = _entry_kbs(entry)
        matched = sorted(kb_set & entry_kbs)
        if ver == old_ver and matched:
            already_patched.append(
                {
                    "version": fi.get("version"),
                    "matched_kbs": matched,
                }
            )
        if ver <= old_ver:
            continue
        rec = {
            "sha256": sha,
            "version": fi.get("version"),
            "ver": ver,
            "timestamp": ts,
            "virtual_size": vs,
            "kbs": sorted(entry_kbs),
            "url": _binary_url(filename, int(ts), int(vs)),
        }
        same_branch.append(rec)
        if matched:
            rec["matched_kbs"] = matched
            kb_hits.append(rec)

    pool = kb_hits or []
    if not pool:
        if already_patched:
            hit = already_patched[0]
            raise PatchResolveError(
                f"当前上传的是 {filename} {pe.get('file_version')}，"
                f"它本身已是 {msrc['cve']} 的修复构建（KB{', KB'.join(hit['matched_kbs'])}），"
                f"不能再当「漏洞版」去自动找补丁。"
                f"请改传漏洞样本（例如同分支更早的 10.0.26100.8972），"
                f"或在高级选项里手动上传另一份修复版做对比。"
            )
        newer = ", ".join(sorted({str(r["version"]).split()[0] for r in same_branch})[:8])
        raise PatchResolveError(
            f"已定位 {msrc['cve']}（{msrc['title']}），修复 KB：{', '.join('KB'+k for k in msrc['kbs'][:8])}。"
            f"但 Winbindex 上没有可下载的 {filename} {old_ver[0]}.{old_ver[1]}.{old_ver[2]}.* 补丁构建"
            + (f"（索引中较新版本：{newer}）。" if newer else "。")
            + "请手动上传修复版驱动。"
        )
    pool.sort(key=lambda r: r["ver"])
    chosen = pool[0]
    short_ver = str(chosen["version"]).split()[0]
    cache_pe = DATA_DIR / "cache" / "binaries" / f"{filename}_{short_ver}"
    cache_pe.parent.mkdir(parents=True, exist_ok=True)
    step(f"下载修复版 {filename} {short_ver}", 16)
    with _pe_cache_lock(str(cache_pe)):
        if not cache_pe.exists() or cache_pe.stat().st_size < 1024:
            download_pdb(chosen["url"], cache_pe)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(cache_pe.read_bytes())
    if dest.read_bytes()[:2] != b"MZ":
        dest.unlink(missing_ok=True)
        raise PatchResolveError("下载的修复版不是有效 PE，请手动上传")
    return {
        "cve": msrc["cve"],
        "msrc_title": msrc["title"],
        "bulletin": msrc["bulletin"],
        "kbs": msrc["kbs"],
        "old_file": filename,
        "old_version": pe.get("file_version"),
        "new_version": short_ver,
        "new_url": chosen["url"],
        "matched_kbs": chosen.get("matched_kbs") or [],
        "source": "winbindex+msdl",
    }


def sanitize_filename(name: str) -> str:
    raw = (name or "").strip()
    if "://" in raw or ".." in raw.replace("\\", "/"):
        raise PatchResolveError("组件文件名须为 afd.sys / ntoskrnl.exe 这类 PE 名")
    n = raw.split("\\")[-1].split("/")[-1]
    if not SAFE_FILENAME.match(n):
        raise PatchResolveError("组件文件名须为 afd.sys / ntoskrnl.exe 这类 PE 名")
    return n.lower()


def kernelish_filename(name: str) -> bool:
    n = (name or "").lower()
    return n.endswith(".sys") or n in {"ntoskrnl.exe", "win32k.sys", "win32kfull.sys", "win32kbase.sys"}


DIFF_HINT = re.compile(
    r"race condition|use[\s-]?after[\s-]?free|\buaf\b|toctou|double[\s-]?free|"
    r"pool overflow|heap[\s-]?based|integer overflow|buffer overflow|"
    r"竞态|释放后使用|整数溢出|缓冲区溢出",
    re.I,
)


def analysis_fit(row: dict[str, Any]) -> dict[str, Any]:
    """Score how well this CVE fits automated PE patch-diff analysis."""
    filename = str(row.get("filename_guess") or "")
    title = str(row.get("title") or "")
    desc = str(row.get("description") or "")
    faq = " ".join(row.get("faq") or [])
    blob = f"{title} {desc} {faq}"
    reasons: list[str] = []
    blockers: list[str] = []
    score = 0

    pe_ok = bool(filename) and bool(SAFE_FILENAME.match(filename))
    kernel = kernelish_filename(filename)
    weapon = bool(row.get("weaponizable"))
    impact = str(row.get("impact") or "")
    likely = str(row.get("exploit_likely") or "")

    if pe_ok:
        score += 3
        reasons.append(f"已识别 {filename}")
    else:
        blockers.append("组件未识别，无法自动成对下载")

    if kernel:
        score += 3
        reasons.append("内核 / 驱动")

    if weapon:
        score += 2
        reasons.append(row.get("impact_label") or "可利用向")
    elif impact in {"dos", "info"}:
        score -= 2
        blockers.append("DoS / 信息泄露，对照收益低")

    if likely == "detected":
        score += 4
        reasons.append("已发现在野利用")
    elif likely == "more":
        score += 2
        reasons.append("较可能被利用")

    if DIFF_HINT.search(blob):
        score += 2
        reasons.append("竞态 / UAF / 溢出，适合补丁对照")

    if not (row.get("kbs") or []):
        blockers.append("没有 Windows KB")
        score -= 4

    auto_ok = pe_ok and kernel and weapon and impact not in {"dos", "info"}
    if auto_ok:
        reasons.append("可自动排队对照")
    elif pe_ok and not kernel:
        blockers.append("用户态 PE，自动对照把握较低")

    if likely == "detected" and auto_ok:
        rank = "priority"
    elif auto_ok and score >= 8:
        rank = "priority"
    elif auto_ok:
        rank = "ready"
    elif pe_ok and weapon and score >= 5:
        rank = "ready"
    else:
        rank = "weak"

    return {
        "score": score,
        "rank": rank,
        "auto_ok": auto_ok,
        "reasons": reasons[:6],
        "blockers": blockers[:4],
    }


def attach_analysis_fit(row: dict[str, Any]) -> dict[str, Any]:
    row["analysis"] = analysis_fit(row)
    return row


IMPACT_LABEL = {
    "eop": "提权",
    "rce": "远程代码执行",
    "dos": "拒绝服务",
    "info": "信息泄露",
    "sfb": "安全功能绕过",
    "spoof": "欺骗",
    "tamper": "篡改",
}
WEAPONIZABLE_IMPACTS = frozenset({"eop", "rce", "sfb"})
_IMPACT_HINTS = (
    ("elevation of privilege", "eop"),
    ("特权提升", "eop"),
    ("remote code execution", "rce"),
    ("远程代码", "rce"),
    ("denial of service", "dos"),
    ("拒绝服务", "dos"),
    ("information disclosure", "info"),
    ("信息泄露", "info"),
    ("security feature bypass", "sfb"),
    ("安全功能绕过", "sfb"),
    ("spoofing", "spoof"),
    ("欺骗", "spoof"),
    ("tampering", "tamper"),
    ("篡改", "tamper"),
)


def _impact_from_text(text: str) -> str:
    blob = (text or "").lower()
    for needle, code in _IMPACT_HINTS:
        if needle in blob:
            return code
    return ""


def _threat_value(threat: dict[str, Any]) -> str:
    desc = threat.get("Description")
    if isinstance(desc, dict):
        return str(desc.get("Value") or "")
    return str(desc or "")


def _vuln_impact(vuln: dict[str, Any], title: str = "") -> dict[str, Any]:
    impact = ""
    likely = ""
    for threat in vuln.get("Threats") or []:
        typ = threat.get("Type")
        val = _threat_value(threat)
        if not val:
            continue
        if typ == 0 and not impact:
            impact = _impact_from_text(val)
        if typ == 1 and not likely:
            low = val.lower()
            if "exploited:yes" in low.replace(" ", "") or "exploitation detected" in low:
                likely = "detected"
            elif "more likely" in low:
                likely = "more"
            elif "unlikely" in low:
                likely = "unlikely"
            elif "less likely" in low:
                likely = "less"
    if not impact:
        impact = _impact_from_text(title)
    return {
        "impact": impact or "other",
        "impact_label": IMPACT_LABEL.get(impact, "其他"),
        "exploit_likely": likely,
        "weaponizable": (impact or "other") in WEAPONIZABLE_IMPACTS,
    }


def _plain(text: str) -> str:
    return HTML_TAG.sub(" ", text or "").replace("&nbsp;", " ")


def _collapse_ws(text: str) -> str:
    return " ".join((_plain(text) or "").split())


def _vuln_msrc_notes(vuln: dict[str, Any]) -> dict[str, Any]:
    desc = ""
    faqs: list[str] = []
    for note in vuln.get("Notes") or []:
        if not isinstance(note, dict):
            continue
        title = str(note.get("Title") or "")
        typ = note.get("Type")
        val = _collapse_ws(str(note.get("Value") or ""))
        if not val:
            continue
        if typ == 2 or title == "Description":
            if not desc:
                desc = val[:1600]
        elif typ == 4 or title == "FAQ":
            faqs.append(val[:900])
    return {"description": desc, "faq": faqs[:5]}


def _vuln_title(vuln: dict[str, Any]) -> str:
    t = vuln.get("Title")
    if isinstance(t, dict):
        return str(t.get("Value") or "")
    return str(t or "")


def _vuln_blob(vuln: dict[str, Any]) -> str:
    parts = [_vuln_title(vuln)]
    for note in vuln.get("Notes") or []:
        if isinstance(note, dict):
            parts.append(_plain(str(note.get("Value") or "")))
    return " ".join(parts)


def _vuln_kbs(vuln: dict[str, Any]) -> list[str]:
    seen: list[str] = []
    for rem in vuln.get("Remediations") or []:
        desc = rem.get("Description")
        val = desc.get("Value") if isinstance(desc, dict) else desc
        blob = " ".join(
            str(x)
            for x in (val, rem.get("URL") or "")
            if x
        )
        kb = _kb_num(blob)
        if kb and kb not in seen:
            seen.append(kb)
    return seen


def guess_filenames(title: str, extra: str = "") -> list[str]:
    blob = f"{title} {extra}".lower()
    out: list[str] = []
    for m in FILE_IN_TEXT.finditer(f"{title} {extra}"):
        name = m.group(1).lower()
        if name.lower() not in {x.lower() for x in out}:
            out.append(name)
    for keys, filename in COMPONENT_HINTS:
        if any(k in blob for k in keys):
            if filename.lower() not in {x.lower() for x in out}:
                out.append(filename)
    return out[:6]


def list_msrc_months(*, refresh: bool = False) -> list[dict[str, Any]]:
    cache = DATA_DIR / "cache" / "msrc" / "months.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not refresh and cache.is_file() and cache.stat().st_size > 20:
        try:
            data = json.loads(cache.read_text(encoding="utf-8"))
            months = data.get("months") if isinstance(data, dict) else data
            if isinstance(months, list) and months:
                return months
        except json.JSONDecodeError:
            pass
    catalog = json.loads(_http_get(MSRC_UPDATES))
    months = [x for x in catalog.get("value") or [] if MONTH_RE.match(str(x.get("ID") or ""))]
    months.sort(key=lambda x: x.get("InitialReleaseDate") or x.get("CurrentReleaseDate") or "", reverse=True)
    cache.write_text(
        json.dumps(
            {"fetched_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(), "months": months},
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return months


def _month_title(doc_id: str) -> str:
    parts = str(doc_id or "").split("-", 1)
    if len(parts) != 2:
        return doc_id
    year, mon = parts
    return f"{year} 年 {_MONTH_ZH.get(mon, mon)}"


_inbox_mem: dict[str, tuple[float, dict[str, Any]]] = {}
_days_mem: tuple[float, dict[str, Any]] | None = None


def list_patch_days(limit: int = 18, *, refresh: bool = False) -> dict[str, Any]:
    global _days_mem
    cache = DATA_DIR / "cache" / "msrc" / "days.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not refresh and cache.is_file() and cache.stat().st_size > 20:
        mtime = cache.stat().st_mtime
        if _days_mem and _days_mem[0] == mtime:
            return _days_mem[1]
        try:
            data = json.loads(cache.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("months"):
                data["cached"] = True
                _days_mem = (mtime, data)
                return data
        except json.JSONDecodeError:
            pass
    months = list_msrc_months(refresh=refresh)[: max(1, min(int(limit or 18), 36))]
    rows = []
    for item in months:
        doc_id = str(item.get("ID") or "")
        rows.append(
            {
                "id": doc_id,
                "title": _month_title(doc_id),
                "date": item.get("InitialReleaseDate") or item.get("CurrentReleaseDate"),
                "revised_at": item.get("CurrentReleaseDate"),
            }
        )
    out = {
        "months": rows,
        "fetched_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "cached": False,
    }
    cache.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    _days_mem = (cache.stat().st_mtime, out)
    return out


def _load_cvrf(doc_id: str, *, refresh: bool = False) -> dict[str, Any]:
    cache = DATA_DIR / "cache" / "msrc" / f"cvrf-{doc_id}.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not refresh and cache.is_file() and cache.stat().st_size > 1000:
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    cvrf = json.loads(_http_get(MSRC_CVRF.format(doc_id=doc_id), timeout=120))
    cache.write_text(json.dumps(cvrf, ensure_ascii=False), encoding="utf-8")
    return cvrf


def _bulletin_rows(cvrf: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for vuln in cvrf.get("Vulnerability") or []:
        cve = (vuln.get("CVE") or "").upper()
        title = _vuln_title(vuln)
        if not CVE_RE.match(cve) or SKIP_BULLETIN_TITLE.search(title):
            continue
        kbs = _vuln_kbs(vuln)
        if not kbs:
            continue
        if "windows" not in title.lower() and "win32k" not in title.lower() and not FILE_IN_TEXT.search(title):
            continue
        guesses = guess_filenames(title, _vuln_blob(vuln))
        filename = guesses[0] if guesses else ""
        impact = _vuln_impact(vuln, title)
        notes = _vuln_msrc_notes(vuln)
        row = {
            "cve": cve,
            "title": title,
            "kbs": kbs[:12],
            "filename_guess": filename,
            "guesses": guesses,
            "kernelish": kernelish_filename(filename),
            **impact,
            **notes,
        }
        attach_analysis_fit(row)
        rows.append(row)
    _sort_bulletin_rows(rows)
    return rows


def _sort_bulletin_rows(rows: list[dict[str, Any]]) -> None:
    rank_n = {"priority": 0, "ready": 1, "weak": 2}

    def key(r: dict[str, Any]) -> tuple:
        an = r.get("analysis") if isinstance(r.get("analysis"), dict) else {}
        return (
            rank_n.get(str(an.get("rank") or ""), 9),
            -int(an.get("score") or 0),
            not r.get("weaponizable"),
            not r.get("kernelish"),
            r.get("cve") or "",
        )

    rows.sort(key=key)


def _enrich_bulletin(data: dict[str, Any], persist: Path | None = None) -> dict[str, Any]:
    rows = data.get("cves") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return data
    dirty = False
    for r in rows:
        if not isinstance(r, dict):
            continue
        an = r.get("analysis")
        if not isinstance(an, dict) or "score" not in an or "rank" not in an:
            attach_analysis_fit(r)
            dirty = True
    if dirty:
        _sort_bulletin_rows(rows)
    data["priority_count"] = sum(1 for r in rows if isinstance(r, dict) and (r.get("analysis") or {}).get("rank") == "priority")
    data["ready_count"] = sum(1 for r in rows if isinstance(r, dict) and (r.get("analysis") or {}).get("auto_ok"))
    if dirty and persist is not None:
        try:
            persist.parent.mkdir(parents=True, exist_ok=True)
            persist.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass
    return data


def _bulletin_payload(wanted: str, meta: dict[str, Any], rows: list[dict[str, Any]], months: list[dict[str, Any]], *, cached: bool) -> dict[str, Any]:
    return {
        "bulletin": wanted,
        "release_date": meta.get("InitialReleaseDate") or meta.get("CurrentReleaseDate"),
        "revised_at": meta.get("CurrentReleaseDate"),
        "cve_count": len(rows),
        "kernel_count": sum(1 for r in rows if r.get("kernelish")),
        "weaponizable_count": sum(1 for r in rows if r.get("weaponizable")),
        "priority_count": sum(1 for r in rows if (r.get("analysis") or {}).get("rank") == "priority"),
        "ready_count": sum(1 for r in rows if (r.get("analysis") or {}).get("auto_ok")),
        "cves": rows,
        "recent": [{"id": m.get("ID"), "date": m.get("InitialReleaseDate")} for m in months[:8]],
        "fetched_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "cached": cached,
    }


def _inbox_ready(data: Any) -> bool:
    rows = data.get("cves") if isinstance(data, dict) else None
    if not isinstance(rows, list) or not rows:
        return False
    return all(isinstance(r, dict) and "weaponizable" in r and "description" in r for r in rows)


def _cached_inbox(wanted: str, *, refresh: bool) -> dict[str, Any] | None:
    inbox = DATA_DIR / "cache" / "msrc" / f"inbox-{wanted}.json"
    if refresh or not inbox.is_file() or inbox.stat().st_size <= 20:
        if refresh:
            _inbox_mem.pop(wanted, None)
        return None
    mtime = inbox.stat().st_mtime
    hit = _inbox_mem.get(wanted)
    if hit and hit[0] == mtime:
        return hit[1]
    try:
        data = json.loads(inbox.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not _inbox_ready(data):
        return None
    data["cached"] = True
    data = _enrich_bulletin(data, persist=inbox)
    _inbox_mem[wanted] = (inbox.stat().st_mtime, data)
    return data


def list_patch_tuesday(doc_id: str = "", *, refresh: bool = False) -> dict[str, Any]:
    wanted = (doc_id or "").strip()
    months: list[dict[str, Any]] | None = None

    def months_list() -> list[dict[str, Any]]:
        nonlocal months
        if months is None:
            months = list_msrc_months(refresh=refresh)
        if not months:
            raise PatchResolveError("MSRC 未返回月度公告")
        return months

    def meta_for(doc: str) -> dict[str, Any]:
        found = next((m for m in months_list() if str(m.get("ID")) == doc), None)
        if not found:
            raise PatchResolveError(f"没有公告 {doc}")
        return found

    if wanted:
        hit = _cached_inbox(wanted, refresh=refresh)
        if hit:
            return hit
    months_list()
    wanted = wanted or str(months_list()[0].get("ID") or "")
    hit = _cached_inbox(wanted, refresh=refresh)
    if hit:
        return hit
    meta = meta_for(wanted)
    inbox = DATA_DIR / "cache" / "msrc" / f"inbox-{wanted}.json"
    cvrf = _load_cvrf(wanted, refresh=refresh)
    rows = _bulletin_rows(cvrf)
    out = _bulletin_payload(wanted, meta, rows, months_list(), cached=False)
    inbox.parent.mkdir(parents=True, exist_ok=True)
    inbox.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    _inbox_mem[wanted] = (inbox.stat().st_mtime, out)
    return out


def _index_rows(index: dict[str, Any], filename: str, want_arch: str = "amd64") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sha, entry in (index or {}).items():
        fi = entry.get("fileInfo") or {}
        ver = parse_version(fi.get("version") or "")
        ts, vs = fi.get("timestamp"), fi.get("virtualSize")
        if not ver or not ts or not vs:
            continue
        arch = _entry_arch(entry)
        if want_arch and arch and arch != want_arch:
            continue
        rows.append(
            {
                "sha256": sha,
                "version": fi.get("version"),
                "ver": ver,
                "timestamp": ts,
                "virtual_size": vs,
                "kbs": sorted(_entry_kbs(entry)),
                "url": _binary_url(filename, int(ts), int(vs)),
                "arch": arch,
            }
        )
    return rows


def pick_patch_pair(rows: list[dict[str, Any]], kb_set: set[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    patched = [r for r in rows if kb_set & set(r.get("kbs") or [])]
    if not patched:
        raise PatchResolveError("Winbindex 上没有带这些 KB 的可下载构建")
    by_branch: dict[tuple[int, int, int], list[dict[str, Any]]] = {}
    for r in rows:
        by_branch.setdefault(r["ver"][:3], []).append(r)
    branches = sorted({r["ver"][:3] for r in patched}, key=lambda b: b[2], reverse=True)
    for branch in branches:
        news = sorted((r for r in patched if r["ver"][:3] == branch), key=lambda r: r["ver"])
        new = news[0]
        olds = [
            r
            for r in by_branch.get(branch, [])
            if r["ver"] < new["ver"] and not (kb_set & set(r.get("kbs") or []))
        ]
        if not olds:
            continue
        old = sorted(olds, key=lambda r: r["ver"])[-1]
        return old, new
    raise PatchResolveError("有修复构建，但找不到同分支更早的漏洞版（无法做 N vs N-1）")


def _fetch_pe(url: str, cache_name: str, dest: Path) -> None:
    cache_pe = DATA_DIR / "cache" / "binaries" / cache_name
    cache_pe.parent.mkdir(parents=True, exist_ok=True)
    with _pe_cache_lock(str(cache_pe)):
        if not cache_pe.exists() or cache_pe.stat().st_size < 1024:
            download_pdb(url, cache_pe)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(cache_pe.read_bytes())
    if dest.read_bytes()[:2] != b"MZ":
        dest.unlink(missing_ok=True)
        raise PatchResolveError(f"下载的 {dest.name} 不是有效 PE")


def resolve_pair_from_cve(
    cve: str,
    dest_old: Path,
    dest_new: Path,
    *,
    filename: str = "",
    want_arch: str = "amd64",
    progress_cb: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    """Download vulnerable + patched PE for a CVE from Winbindex / MSDL. No local sample required."""

    def step(msg: str, pct: int):
        if progress_cb:
            progress_cb(msg, pct)

    cve = normalize_cve(cve)
    step(f"查询 MSRC {cve}", 6)
    msrc = lookup_cve_msrc(cve)
    kb_set = set(msrc.get("kbs") or [])
    if not kb_set:
        raise PatchResolveError(f"{cve} 在 MSRC 中没有 KB 修复项")
    guesses = [filename] if filename else []
    guesses.extend(guess_filenames(msrc.get("title") or "", cve))
    seen: list[str] = []
    for g in guesses:
        try:
            name = sanitize_filename(g)
        except PatchResolveError:
            continue
        if name.lower() not in {x.lower() for x in seen}:
            seen.append(name)
    if not seen:
        raise PatchResolveError(
            f"已定位 {cve}（{msrc.get('title') or ''}），但无法从标题推断组件文件名。"
            "请填写 afd.sys / ntoskrnl.exe 这类文件名后再试。"
        )
    last_err: Exception | None = None
    for name in seen:
        try:
            step(f"检索 Winbindex {name}", 12)
            rows = _index_rows(_load_winbindex(name), name, want_arch=want_arch)
            old, new = pick_patch_pair(rows, kb_set)
            old_ver = str(old["version"]).split()[0]
            new_ver = str(new["version"]).split()[0]
            step(f"下载漏洞版 {name} {old_ver}", 14)
            _fetch_pe(old["url"], f"{name}_{old_ver}", dest_old)
            step(f"下载修复版 {name} {new_ver}", 18)
            _fetch_pe(new["url"], f"{name}_{new_ver}", dest_new)
            matched = sorted(kb_set & set(new.get("kbs") or []))
            return {
                "cve": msrc["cve"],
                "msrc_title": msrc["title"],
                "bulletin": msrc["bulletin"],
                "kbs": msrc["kbs"],
                "old_file": name,
                "old_version": old_ver,
                "new_version": new_ver,
                "old_url": old["url"],
                "new_url": new["url"],
                "matched_kbs": matched,
                "source": "winbindex+msdl-pair",
                "mode": "cve-pair",
                "guesses": seen,
            }
        except PatchResolveError as e:
            last_err = e
            continue
    raise PatchResolveError(str(last_err) if last_err else f"无法为 {cve} 下载成对样本")


def fetch_versioned_binary(
    filename: str,
    dest: Path,
    *,
    want_ver: tuple[int, int, int, int] | None = None,
    want_arch: str = "amd64",
) -> dict[str, Any]:
    """Download one inbox PE from Winbindex/MSDL, preferring the sample's FileVersion."""
    name = sanitize_filename(filename)
    rows = _index_rows(_load_winbindex(name), name, want_arch=want_arch)
    if not rows:
        raise PatchResolveError(f"Winbindex 没有 {name} 的可下载构建")
    chosen = None
    if want_ver:
        exact = [r for r in rows if r.get("ver") == want_ver]
        same = [r for r in rows if r.get("ver") and r["ver"][:3] == want_ver[:3]]
        pool = exact or same or rows
        chosen = min(pool, key=lambda r: tuple(abs(int(a) - int(b)) for a, b in zip(r["ver"], want_ver)))
    else:
        chosen = sorted(rows, key=lambda r: r["ver"], reverse=True)[0]
    short_ver = str(chosen["version"]).split()[0]
    _fetch_pe(chosen["url"], f"{name}_{short_ver}", dest)
    return {
        "filename": name,
        "version": short_ver,
        "url": chosen["url"],
        "source": "winbindex+msdl",
        "path": str(dest),
    }
