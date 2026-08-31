"""Public-source threat intel: CISA KEV, NVD, EPSS. No exploit details, no invented APTs."""
from __future__ import annotations

import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from .mdutil import demote_h2

import httpx

from .ioc import CVE_RE
from .web_search import web_search_intel

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Patchalyzer.ai/1.0"
)
KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/momokii/kev-mirror/main/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/BenjiTrapp/cisa-known-vuln-scraper/main/cisa-kev.json",
)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
TIMEOUT = 16.0
KEV_TTL_SEC = 6 * 3600

_KEV_LOCK = threading.Lock()
_KEV_CACHE: dict[str, Any] = {"at": 0.0, "index": {}, "error": ""}

TRUSTED_REF_HOSTS = (
    "cisa.gov",
    "nist.gov",
    "nvd.nist.gov",
    "microsoft.com",
    "msrc.microsoft.com",
    "security.microsoft.com",
    "cert.org",
    "first.org",
    "cve.org",
)


def extract_cve(*sources: Any) -> str:
    blobs: list[str] = []
    for src in sources:
        if isinstance(src, str):
            blobs.append(src)
        elif isinstance(src, dict):
            for key in ("cve", "cveID", "cve_id", "title", "vulnerabilityName"):
                val = src.get(key)
                if isinstance(val, str):
                    blobs.append(val)
            blobs.append(str(src.get("cve") or ""))
    for blob in blobs:
        m = CVE_RE.search(blob or "")
        if m:
            return m.group(0).upper()
    return ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _client() -> httpx.Client:
    headers = {
        "User-Agent": UA,
        "Accept": "application/json,text/plain,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    nvd_key = (os.getenv("NVD_API_KEY") or "").strip()
    if nvd_key:
        headers["apiKey"] = nvd_key
    return httpx.Client(timeout=TIMEOUT, follow_redirects=True, headers=headers)


def _parse_kev_payload(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for item in data.get("vulnerabilities") or []:
        cid = str(item.get("cveID") or "").upper()
        if cid:
            index[cid] = item
    return index


def _load_kev_index() -> tuple[dict[str, dict[str, Any]], str]:
    now = time.time()
    with _KEV_LOCK:
        if _KEV_CACHE["index"] and now - float(_KEV_CACHE["at"] or 0) < KEV_TTL_SEC:
            return dict(_KEV_CACHE["index"]), str(_KEV_CACHE.get("error") or "")
    errors: list[str] = []
    index: dict[str, dict[str, Any]] = {}
    with _client() as client:
        for url in KEV_URLS:
            try:
                resp = client.get(url)
                resp.raise_for_status()
                index = _parse_kev_payload(resp.json())
                if index:
                    break
                errors.append(f"CISA KEV empty: {url}")
            except Exception as e:
                errors.append(f"CISA KEV: {e}"[:200])
    err = "" if index else "；".join(errors)[:400]
    if index:
        with _KEV_LOCK:
            _KEV_CACHE["at"] = now
            _KEV_CACHE["index"] = index
            _KEV_CACHE["error"] = ""
        return dict(index), ""
    with _KEV_LOCK:
        if _KEV_CACHE["index"]:
            return dict(_KEV_CACHE["index"]), err
    return {}, err


def _nvd_lookup(cve: str) -> tuple[dict[str, Any], str]:
    try:
        with _client() as client:
            resp = client.get(NVD_URL, params={"cveId": cve})
            resp.raise_for_status()
            vulns = (resp.json() or {}).get("vulnerabilities") or []
        if not vulns:
            return {}, ""
        cve_obj = (vulns[0] or {}).get("cve") or {}
        metrics = cve_obj.get("metrics") or {}
        cvss = ""
        severity = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            rows = metrics.get(key) or []
            if not rows:
                continue
            data = (rows[0] or {}).get("cvssData") or {}
            cvss = str(data.get("baseScore") or "")
            severity = str(data.get("baseSeverity") or (rows[0] or {}).get("baseSeverity") or "")
            break
        descs = cve_obj.get("descriptions") or []
        description = ""
        for d in descs:
            if (d.get("lang") or "").lower() == "en":
                description = (d.get("value") or "").strip()
                break
        if not description and descs:
            description = str((descs[0] or {}).get("value") or "").strip()
        cwes = []
        for w in (cve_obj.get("weaknesses") or [])[:4]:
            for desc in w.get("description") or []:
                val = (desc.get("value") or "").strip()
                if val and val not in cwes:
                    cwes.append(val)
        refs = []
        for r in (cve_obj.get("references") or [])[:24]:
            url = str(r.get("url") or "")
            host = url.split("/")[2].lower() if "://" in url else ""
            if any(host == h or host.endswith("." + h) for h in TRUSTED_REF_HOSTS):
                refs.append({"url": url, "tags": r.get("tags") or []})
            if len(refs) >= 8:
                break
        cisa = {}
        if cve_obj.get("cisaExploitAdd"):
            cisa = {
                "date_added": cve_obj.get("cisaExploitAdd") or "",
                "due_date": cve_obj.get("cisaActionDue") or "",
                "required_action": cve_obj.get("cisaRequiredAction") or "",
                "name": cve_obj.get("cisaVulnerabilityName") or "",
            }
        return {
            "published": cve_obj.get("published") or "",
            "last_modified": cve_obj.get("lastModified") or "",
            "cvss": cvss,
            "severity": severity,
            "cwe": cwes,
            "description": description[:1200],
            "references": refs,
            "cisa_kev": cisa,
        }, ""
    except Exception as e:
        return {}, f"NVD: {e}"[:240]


def _epss_lookup(cve: str) -> tuple[dict[str, Any], str]:
    try:
        with _client() as client:
            resp = client.get(EPSS_URL, params={"cve": cve})
            resp.raise_for_status()
            rows = (resp.json() or {}).get("data") or []
        if not rows:
            return {}, ""
        row = rows[0] or {}
        return {
            "epss": row.get("epss"),
            "percentile": row.get("percentile"),
            "date": row.get("date") or "",
        }, ""
    except Exception as e:
        return {}, f"EPSS: {e}"[:240]


def lookup_threat_intel(cve: str, *, title: str = "", component: str = "") -> dict[str, Any]:
    """Search the open web, then overlay CISA/NVD/EPSS catalogs."""
    cve = (cve or "").strip().upper()
    title = (title or "").strip()
    component = (component or "").strip()
    pack: dict[str, Any] = {
        "cve": cve,
        "title": title,
        "component": component,
        "status": "no_cve",
        "in_kev": False,
        "in_the_wild": False,
        "ransomware_campaign": "",
        "named_groups": [],
        "kev": {},
        "nvd": {},
        "epss": {},
        "search_engine": "",
        "search_queries": [],
        "search_hits": [],
        "search_pages": [],
        "sources": [],
        "errors": [],
        "fetched_at": _now_iso(),
        "threat_notes": "",
        "has_analyst": False,
    }
    if not cve and not title:
        pack["summary"] = "标题与样本元数据中未解析到 CVE，无法检索相关情报。"
        return pack

    errors: list[str] = []
    sources: list[dict[str, str]] = []
    kev_index: dict[str, dict[str, Any]] = {}
    nvd: dict[str, Any] = {}
    epss: dict[str, Any] = {}
    search: dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_search = pool.submit(web_search_intel, cve, title, component)
        f_kev = pool.submit(_load_kev_index) if cve else None
        f_nvd = pool.submit(_nvd_lookup, cve) if cve else None
        f_epss = pool.submit(_epss_lookup, cve) if cve else None
        search = f_search.result() or {}
        if f_kev:
            kev_index, kev_err = f_kev.result()
            if kev_err:
                errors.append(kev_err)
        if f_nvd:
            nvd, nvd_err = f_nvd.result()
            if nvd_err:
                errors.append(nvd_err)
        if f_epss:
            epss, epss_err = f_epss.result()
            if epss_err:
                errors.append(epss_err)

    for err in search.get("errors") or []:
        errors.append(str(err))
    pack["search_engine"] = search.get("engine") or ""
    pack["search_queries"] = search.get("queries") or []
    pack["search_hits"] = search.get("hits") or []
    pack["search_pages"] = [
        {"url": p.get("url"), "text": (p.get("text") or "")[:1800]}
        for p in (search.get("pages") or [])
    ]

    kev = kev_index.get(cve) or {} if cve else {}
    nvd_cisa = (nvd or {}).get("cisa_kev") or {}
    if kev:
        pack["in_kev"] = True
        pack["in_the_wild"] = True
        pack["status"] = "confirmed_exploited"
        pack["ransomware_campaign"] = str(kev.get("knownRansomwareCampaignUse") or "")
        pack["kev"] = {
            "vendor": kev.get("vendorProject") or "",
            "product": kev.get("product") or "",
            "name": kev.get("vulnerabilityName") or "",
            "date_added": kev.get("dateAdded") or "",
            "due_date": kev.get("dueDate") or "",
            "description": (kev.get("shortDescription") or "")[:800],
            "required_action": kev.get("requiredAction") or "",
            "notes": (kev.get("notes") or "")[:800],
            "ransomware": kev.get("knownRansomwareCampaignUse") or "",
            "source": "CISA KEV catalog",
        }
        sources.append({
            "name": "CISA Known Exploited Vulnerabilities",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        })
    elif nvd_cisa.get("date_added"):
        pack["in_kev"] = True
        pack["in_the_wild"] = True
        pack["status"] = "confirmed_exploited"
        pack["kev"] = {
            "name": nvd_cisa.get("name") or "",
            "date_added": nvd_cisa.get("date_added") or "",
            "due_date": nvd_cisa.get("due_date") or "",
            "required_action": nvd_cisa.get("required_action") or "",
            "description": "",
            "notes": "",
            "ransomware": "",
            "source": "NVD CISA KEV fields",
        }
        sources.append({
            "name": "CISA KEV via NVD",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        })
    elif pack["search_hits"]:
        pack["status"] = "searched"
    elif not cve:
        pack["status"] = "searched"
    elif kev_index:
        pack["status"] = "not_in_kev"
    elif nvd or epss:
        pack["status"] = "kev_unavailable"
    else:
        pack["status"] = "lookup_failed"

    if nvd:
        pack["nvd"] = nvd
        sources.append({"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"})
        for ref in nvd.get("references") or []:
            url = ref.get("url") or ""
            if url:
                sources.append({"name": "NVD reference", "url": url})
    if epss:
        pack["epss"] = epss
        sources.append({"name": "FIRST EPSS", "url": f"https://api.first.org/data/v1/epss?cve={cve}"})
    for h in pack["search_hits"]:
        sources.append({"name": h.get("title") or "web", "url": h.get("url") or ""})

    seen = set()
    uniq = []
    for s in sources:
        u = s.get("url") or ""
        if not u or u in seen:
            continue
        seen.add(u)
        uniq.append(s)
    pack["sources"] = uniq[:16]
    pack["errors"] = errors
    pack["named_groups"] = []
    pack["summary"] = _summary_line(pack)
    if pack["status"] == "lookup_failed" and not pack["search_hits"]:
        pack["summary"] = "公开情报检索失败：" + ("；".join(errors) or "网络不可用")
    return pack


def _summary_line(pack: dict[str, Any]) -> str:
    cve = pack.get("cve") or pack.get("title") or ""
    n_hits = len(pack.get("search_hits") or [])
    if pack.get("in_kev"):
        rans = pack.get("ransomware_campaign") or ""
        extra = "；CISA 标注勒索软件活动中被利用" if str(rans).lower() == "known" else ""
        search = f"另检索到 {n_hits} 条公开报道。" if n_hits else ""
        return f"{cve} 已列入 CISA KEV，属于已知在野利用{extra}。{search}".strip()
    if n_hits:
        return f"已检索到 {n_hits} 条公开报道，详见检索结果与分析师解读。"
    if pack.get("status") == "kev_unavailable":
        return f"{cve} 联网检索无结果，CISA KEV 目录也暂不可用。"
    if pack.get("status") == "not_in_kev":
        return f"{cve} 联网检索无相关报道，且未列入 CISA KEV。"
    return f"{cve} 公开情报查询不完整。"


def threat_section_markdown(pack: dict[str, Any] | None) -> str:
    pack = pack or {}
    cve = pack.get("cve") or "（未解析到 CVE）"
    status = pack.get("status") or "no_cve"
    status_label = {
        "confirmed_exploited": "已确认在野利用（CISA KEV）",
        "searched": "已完成公开检索",
        "not_in_kev": "未列入 CISA KEV",
        "no_cve": "无 CVE",
        "lookup_failed": "检索失败",
        "kev_unavailable": "CISA KEV 目录暂不可用",
    }.get(status, status)
    kev = pack.get("kev") or {}
    nvd = pack.get("nvd") or {}
    epss = pack.get("epss") or {}
    notes = demote_h2((pack.get("threat_notes") or "").strip())
    if notes.startswith("（跳过") or notes.startswith("（失败"):
        notes = ""

    kev_cell = "—"
    if pack.get("in_kev"):
        kev_cell = "是 · " + (kev.get("date_added") or "")
    elif status == "not_in_kev":
        kev_cell = "否"
    elif status == "kev_unavailable":
        kev_cell = "未能查询目录"

    hit_lines = []
    for h in pack.get("search_hits") or []:
        title = h.get("title") or h.get("url") or "结果"
        url = h.get("url") or ""
        snippet = (h.get("snippet") or "").strip()
        link = f"[{title}]({url})" if url else title
        hit_lines.append(f"- {link}" + (f"  \n  {snippet}" if snippet else ""))

    catalog_rows = [
        f"| CVE | `{cve}` |",
        f"| 结论 | {status_label} |",
        f"| CISA KEV | {kev_cell} |",
        f"| 勒索软件活动（CISA） | {kev.get('ransomware') or pack.get('ransomware_campaign') or '—'} |",
        f"| NVD CVSS | {nvd.get('cvss') or '—'} {nvd.get('severity') or ''} |",
        f"| EPSS | {epss.get('epss') or '—'}（percentile {epss.get('percentile') or '—'}） |",
        f"| 检索时间 | {pack.get('fetched_at') or '—'} |",
    ]
    err_lines = [f"- {e}" for e in (pack.get("errors") or [])]
    parts = [
        "## 17. 在野利用 / 威胁情报",
        "",
        pack.get("summary") or "",
        "",
        "### 17.1 分析师解读",
        "",
        notes or "尚无分析师解读。检索结果见下节。",
        "",
        "### 17.2 检索结果",
        "",
        *(hit_lines or ["- 未检索到相关公开报道"]),
        "",
        "### 17.3 目录对照",
        "",
        "| 项 | 值 |",
        "|---|---|",
        *catalog_rows,
        "",
    ]
    if err_lines:
        parts += ["**查询告警**", "", *err_lines, ""]
    return "\n".join(parts).rstrip() + "\n"


def ensure_threat_section(report: str, pack: dict[str, Any] | None) -> str:
    section = threat_section_markdown(pack)
    text = report or ""
    if re.search(r"(?m)^##\s*17\.\s*", text):
        return re.sub(
            r"(?ms)^##\s*17\.\s*.*?(?=^##\s*\d+\.|\Z)",
            lambda _m: section.rstrip() + "\n\n",
            text,
        )
    return text.rstrip() + "\n\n" + section


def resolve_cve_from_artifacts(art: dict[str, Any] | None, title: str = "") -> str:
    art = art or {}
    return extract_cve(
        title,
        art.get("title") or "",
        art.get("patch_resolve") or {},
        art.get("ioc_pack") or {},
        (art.get("threat_intel") or {}).get("cve") or "",
    )


def component_from_artifacts(art: dict[str, Any] | None) -> str:
    art = art or {}
    pr = art.get("patch_resolve") if isinstance(art.get("patch_resolve"), dict) else {}
    pe = art.get("old_pe") if isinstance(art.get("old_pe"), dict) else {}
    return str(pr.get("old_file") or pe.get("original_filename") or "")


def threat_intel_for_artifacts(art: dict[str, Any] | None, title: str = "") -> dict[str, Any]:
    art = art or {}
    pack = art.get("threat_intel")
    if isinstance(pack, dict) and pack.get("fetched_at") and "search_hits" in pack:
        return pack
    return lookup_threat_intel(
        resolve_cve_from_artifacts(art, title),
        title=title or art.get("title") or "",
        component=component_from_artifacts(art),
    )


def attach_analyst_notes(pack: dict[str, Any], notes: str) -> dict[str, Any]:
    out = dict(pack or {})
    text = (notes or "").strip()
    if text.startswith("（跳过") or text.startswith("（失败"):
        out["threat_notes"] = ""
        out["has_analyst"] = False
        return out
    out["threat_notes"] = text
    out["has_analyst"] = bool(text)
    return out
