"""Search `{CVE} APT` and return the first two result pages."""
from __future__ import annotations

import html as html_lib
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import httpx

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
TIMEOUT = 12.0


def _client() -> httpx.Client:
    return httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=True,
        headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8",
        },
    )


def _unescape(s: str) -> str:
    text = html_lib.unescape(re.sub(r"<[^>]+>", " ", s or ""))
    return re.sub(r"\s+", " ", text).strip()


def _unwrap_url(href: str) -> str:
    href = html_lib.unescape(href or "").strip()
    parsed = urlparse(href)
    qs = parse_qs(parsed.query)
    for key in ("u", "url", "r", "uddg"):
        vals = qs.get(key) or []
        if not vals:
            continue
        raw = unquote(vals[0])
        if raw.startswith("http"):
            return raw
    return href if href.startswith("http") else ""


def _parse_bing(html: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    seen: set[str] = set()
    for m in re.finditer(
        r'<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
        html,
        re.I | re.S,
    ):
        url = _unwrap_url(m.group(1))
        title = _unescape(m.group(2))
        if not title:
            continue
        tail = html[m.end() : m.end() + 900]
        sm = re.search(r"<p[^>]*>(.*?)</p>", tail, re.I | re.S)
        snippet = _unescape(sm.group(1)) if sm else ""
        key = url or title
        if key in seen:
            continue
        seen.add(key)
        hits.append({"title": title[:200], "url": url, "snippet": snippet[:400]})
    return hits


def _bing_page(query: str, first: int) -> tuple[list[dict[str, str]], str]:
    try:
        with _client() as client:
            resp = client.get(
                "https://www.bing.com/search",
                params={"q": query, "first": first, "mkt": "en-US"},
            )
            resp.raise_for_status()
            return _parse_bing(resp.text), ""
    except Exception as e:
        return [], str(e)[:200]


def web_search_intel(cve: str = "", title: str = "", component: str = "") -> dict[str, Any]:
    """One query `{CVE} APT`, first two Bing pages. Empty hits → caller uses catalogs."""
    _ = component
    cve = (cve or "").strip().upper()
    query = f"{cve} APT" if cve else ""
    if not query:
        return {"engine": "", "queries": [], "hits": [], "pages": [], "errors": []}

    errors: list[str] = []
    page1, err1 = [], ""
    page2, err2 = [], ""
    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_bing_page, query, 1)
        f2 = pool.submit(_bing_page, query, 11)
        page1, err1 = f1.result()
        page2, err2 = f2.result()
    if err1:
        errors.append(f"第1页: {err1}")
    if err2:
        errors.append(f"第2页: {err2}")

    seen: set[str] = set()
    hits: list[dict[str, str]] = []
    for h in page1 + page2:
        key = h.get("url") or h.get("title") or ""
        if not key or key in seen:
            continue
        seen.add(key)
        hits.append(h)

    return {
        "engine": "bing" if hits else "",
        "queries": [query],
        "hits": hits,
        "pages": [],
        "errors": errors,
    }
