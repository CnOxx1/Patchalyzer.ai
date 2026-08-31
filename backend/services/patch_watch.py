"""Watch Microsoft Patch Tuesday (MSRC monthly CVRF) and optionally enqueue jobs."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Callable

from ..config import DATA_DIR
from ..database import connect, extract_job_cve, init_db
from .patch_resolver import PatchResolveError, kernelish_filename, list_patch_tuesday

WATCH_INTERVAL_SEC = 3 * 60 * 60
DEFAULT_WATCH = {
    "enabled": True,
    "auto_kernel": False,
    "last_bulletin": "",
    "last_release_date": "",
    "ingested": [],
    "last_check": "",
    "last_error": "",
}

_enqueue: Callable[..., str] | None = None


def bind_enqueue(fn: Callable[..., str]) -> None:
    global _enqueue
    _enqueue = fn


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


_watch_mem: dict[str, Any] | None = None


def get_watch_config() -> dict[str, Any]:
    global _watch_mem
    if _watch_mem is not None:
        out = dict(_watch_mem)
        out["ingested"] = list(out.get("ingested") or [])
        return out
    init_db()
    with connect() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS app_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)"
        )
        row = conn.execute("SELECT v FROM app_kv WHERE k = 'watch'").fetchone()
    if not row:
        _watch_mem = dict(DEFAULT_WATCH)
        return dict(_watch_mem)
    try:
        data = json.loads(row["v"])
    except (TypeError, json.JSONDecodeError):
        _watch_mem = dict(DEFAULT_WATCH)
        return dict(_watch_mem)
    out = {**DEFAULT_WATCH, **(data or {})}
    out["ingested"] = list(out.get("ingested") or [])
    _watch_mem = out
    return dict(out)


def save_watch_config(cfg: dict[str, Any]) -> dict[str, Any]:
    global _watch_mem
    merged = {**get_watch_config(), **(cfg or {})}
    merged["ingested"] = list(merged.get("ingested") or [])[:400]
    init_db()
    with connect() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS app_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO app_kv (k, v) VALUES ('watch', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (json.dumps(merged, ensure_ascii=False),),
        )
    _watch_mem = merged
    return merged


def job_has_cve(cve: str) -> bool:
    needle = (cve or "").upper()
    if not needle:
        return False
    init_db()
    with connect() as conn:
        rows = conn.execute("SELECT title FROM jobs").fetchall()
    return any(extract_job_cve(row["title"] if row["title"] else "") == needle for row in rows)


def refresh_bulletin(doc_id: str = "", *, refresh: bool = False) -> dict[str, Any]:
    bulletin = list_patch_tuesday(doc_id, refresh=refresh)
    cfg = get_watch_config()
    cfg["last_check"] = _utcnow()
    cfg["last_error"] = ""
    if not cfg.get("last_bulletin"):
        # First sighting: remember the current month, do not flood auto-jobs.
        cfg["last_bulletin"] = bulletin["bulletin"]
        cfg["last_release_date"] = bulletin.get("release_date") or ""
    save_watch_config(cfg)
    cache = DATA_DIR / "cache" / "msrc" / f"inbox-{bulletin['bulletin']}.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(bulletin, ensure_ascii=False), encoding="utf-8")
    return bulletin


def auto_ingest(bulletin: dict[str, Any], *, force: bool = False) -> list[dict[str, Any]]:
    if _enqueue is None:
        return []
    cfg = get_watch_config()
    if not cfg.get("auto_kernel") and not force:
        return []
    started: list[dict[str, Any]] = []
    ingested = [str(x).upper() for x in (cfg.get("ingested") or [])]
    queued = 0
    rows = sorted(
        bulletin.get("cves") or [],
        key=lambda r: -int(((r.get("analysis") or {}).get("score") if isinstance(r.get("analysis"), dict) else 0) or 0),
    )
    for row in rows:
        if queued >= 6:
            break
        cve = (row.get("cve") or "").upper()
        filename = row.get("filename_guess") or ""
        analysis = row.get("analysis") if isinstance(row.get("analysis"), dict) else {}
        auto_ok = analysis.get("auto_ok")
        if auto_ok is None:
            auto_ok = bool(cve and kernelish_filename(filename) and row.get("weaponizable") is not False)
        if not cve or not auto_ok:
            continue
        if cve in ingested or job_has_cve(cve):
            continue
        try:
            job_id = _enqueue(cve, filename=filename, run_llm=None)
        except Exception as e:
            started.append({"cve": cve, "error": str(e)})
            continue
        queued += 1
        ingested.append(cve)
        started.append({"cve": cve, "job_id": job_id, "filename": filename})
    cfg["ingested"] = ingested
    cfg["last_bulletin"] = bulletin.get("bulletin") or cfg.get("last_bulletin")
    cfg["last_release_date"] = bulletin.get("release_date") or cfg.get("last_release_date")
    cfg["last_check"] = _utcnow()
    save_watch_config(cfg)
    return started


def watch_tick() -> dict[str, Any]:
    cfg = get_watch_config()
    if not cfg.get("enabled"):
        return {"skipped": True, "reason": "监控已关闭"}
    prev = cfg.get("last_bulletin") or ""
    try:
        bulletin = refresh_bulletin(refresh=True)
    except Exception as e:
        save_watch_config({"last_check": _utcnow(), "last_error": str(e)})
        return {"ok": False, "error": str(e)}
    is_new = bool(prev) and prev != bulletin.get("bulletin")
    started: list[dict[str, Any]] = []
    if is_new:
        started = auto_ingest(bulletin)
    save_watch_config(
        {
            "last_bulletin": bulletin.get("bulletin") or prev,
            "last_release_date": bulletin.get("release_date") or "",
            "last_check": _utcnow(),
            "last_error": "",
        }
    )
    return {
        "ok": True,
        "bulletin": bulletin.get("bulletin"),
        "cve_count": bulletin.get("cve_count"),
        "new_bulletin": is_new,
        "started": started,
        "watch": get_watch_config(),
    }


async def watch_loop() -> None:
    await asyncio.sleep(25)
    while True:
        try:
            await asyncio.to_thread(watch_tick)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        await asyncio.sleep(WATCH_INTERVAL_SEC)
