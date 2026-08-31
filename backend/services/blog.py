"""Publish analysis reports to the public research blog."""
from __future__ import annotations

import re
import uuid
from typing import Any

from fastapi import HTTPException

from ..database import (
    extract_job_cve,
    get_blog_by_job,
    get_job,
    insert_blog_post,
    slug_taken,
    update_blog_post,
)

_SLUG_OK = re.compile(r"[^a-z0-9]+")
_MD_NOISE = re.compile(r"[#*_>`\[\]()]+")
_LOCAL_PATH = re.compile(r"[A-Za-z]:\\[^\s|]+")
_SCRIPT = re.compile(r"<script[\s\S]*?</script>", re.I)
_CVE = re.compile(r"CVE-\d{4}-\d+", re.I)


def sanitize_markdown(text: str) -> str:
    s = _SCRIPT.sub("", text or "")
    s = _LOCAL_PATH.sub("[path]", s)
    return s.strip()


def excerpt_from_markdown(text: str, limit: int = 420) -> str:
    body = sanitize_markdown(text)
    chunk = body
    m = re.search(r"^##\s*1\.[^\n]*\n([\s\S]+?)(?=^##\s*\d+\.|\Z)", body, re.M)
    if m:
        chunk = m.group(1)
    chunk = re.sub(r"```[\s\S]*?```", " ", chunk)
    chunk = re.sub(r"^\|.+\|$", " ", chunk, flags=re.M)
    chunk = re.sub(r"^[-:]{3,}$", " ", chunk, flags=re.M)
    chunk = _MD_NOISE.sub(" ", chunk)
    chunk = re.sub(r"\s+", " ", chunk).strip()
    if len(chunk) <= limit:
        return chunk
    return chunk[: limit - 1].rstrip() + "…"


def make_slug(title: str, cve: str = "", exclude_id: str = "") -> str:
    if _CVE.fullmatch((cve or "").strip()):
        base = cve.strip().lower()
    else:
        found = _CVE.search(title or "")
        base = found.group(0).lower() if found else _SLUG_OK.sub("-", (title or "").lower()).strip("-")
    base = (base or "report")[:60]
    slug = base
    n = 2
    while slug_taken(slug, exclude_id=exclude_id):
        slug = f"{base}-{n}"
        n += 1
        if n > 50:
            slug = f"{base}-{uuid.uuid4().hex[:6]}"
            break
    return slug


def public_post(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not row or row.get("status") != "published":
        return None
    body = row.get("body_md") or ""
    return {
        "id": row.get("id"),
        "slug": row.get("slug"),
        "title": row.get("title"),
        "excerpt": excerpt_from_markdown(body, 420) or (row.get("excerpt") or ""),
        "body_md": body,
        "cve": row.get("cve") or "",
        "author_name": row.get("author_name") or "",
        "published_at": row.get("published_at") or row.get("updated_at"),
    }


def public_post_card(row: dict[str, Any]) -> dict[str, Any]:
    item = public_post({**row, "body_md": row.get("body_md") or "", "status": row.get("status") or "published"}) or {}
    item.pop("body_md", None)
    head = row.get("body_head") or row.get("body_md") or row.get("excerpt") or ""
    intro = excerpt_from_markdown(str(head), 420) or (row.get("excerpt") or "")
    if intro:
        item["excerpt"] = intro
    return item


def job_report_markdown(job: dict[str, Any]) -> str:
    art = (job.get("result") or {}).get("artifacts") or {}
    return sanitize_markdown(str(art.get("llm_report") or ""))


def publish_job_report(
    job_id: str,
    actor: dict[str, Any],
    *,
    title: str | None = None,
    excerpt: str | None = None,
    status: str = "published",
) -> dict[str, Any]:
    st = (status or "published").strip().lower()
    if st not in {"draft", "published"}:
        raise HTTPException(400, "状态只能是 draft 或 published")
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "任务不存在")
    if job.get("status") != "completed":
        raise HTTPException(400, "任务尚未完成，不能发布")
    body = job_report_markdown(job)
    if not body:
        raise HTTPException(400, "还没有可发布的报告正文")
    cve = extract_job_cve(job.get("title") or "") or extract_job_cve(title or "")
    heading = (title or "").strip() or (job.get("title") or "补丁分析报告")
    summary = (excerpt or "").strip() or excerpt_from_markdown(body)
    author = (actor.get("display_name") or actor.get("username") or "").strip()
    existing = get_blog_by_job(job_id)
    published_at = None
    if st == "published":
        from datetime import datetime, timezone

        published_at = datetime.now(timezone.utc).isoformat()
    if existing:
        slug = make_slug(heading, cve, exclude_id=existing["id"])
        fields: dict[str, Any] = {
            "slug": slug,
            "title": heading,
            "excerpt": summary,
            "body_md": body,
            "status": st,
            "author_id": actor.get("id"),
            "author_name": author,
            "cve": cve,
        }
        if st == "published":
            fields["published_at"] = existing.get("published_at") or published_at
        else:
            fields["published_at"] = None
        return update_blog_post(existing["id"], **fields) or existing
    post_id = uuid.uuid4().hex[:12]
    slug = make_slug(heading, cve)
    return insert_blog_post(
        {
            "id": post_id,
            "slug": slug,
            "title": heading,
            "excerpt": summary,
            "body_md": body,
            "status": st,
            "source_job_id": job_id,
            "author_id": actor.get("id"),
            "author_name": author,
            "cve": cve,
            "published_at": published_at if st == "published" else None,
        }
    )
