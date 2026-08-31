"""SQLite persistence for jobs and LLM settings."""
import json
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from .atomic_io import write_text_replace
from .config import DB_PATH, DEFAULT_AGENT_PROMPTS, DEFAULT_LLM, JOBS_DIR, ensure_dirs


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connect():
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=4000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS llm_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                config_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                old_label TEXT,
                new_label TEXT,
                old_filename TEXT,
                new_filename TEXT,
                mid_label TEXT,
                mid_filename TEXT,
                error TEXT,
                result_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        row = conn.execute("SELECT 1 FROM llm_config WHERE id = 1").fetchone()
        if not row:
            conn.execute(
                "INSERT INTO llm_config (id, config_json, updated_at) VALUES (1, ?, ?)",
                (json.dumps(DEFAULT_LLM, ensure_ascii=False), _utcnow()),
            )
        cols = {r[1] for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
        if "mid_filename" not in cols:
            conn.execute("ALTER TABLE jobs ADD COLUMN mid_filename TEXT")
        if "mid_label" not in cols:
            conn.execute("ALTER TABLE jobs ADD COLUMN mid_label TEXT")
        if "agents_json" not in cols:
            conn.execute("ALTER TABLE jobs ADD COLUMN agents_json TEXT")
        if "in_kev" not in cols:
            conn.execute("ALTER TABLE jobs ADD COLUMN in_kev INTEGER")
        if "bypass_verdict" not in cols:
            conn.execute("ALTER TABLE jobs ADD COLUMN bypass_verdict TEXT")
        if "residual_verdict" not in cols:
            conn.execute("ALTER TABLE jobs ADD COLUMN residual_verdict TEXT")
        if "kind" not in cols:
            conn.execute("ALTER TABLE jobs ADD COLUMN kind TEXT NOT NULL DEFAULT 'patch_diff'")
        if "audit_verdict" not in cols:
            conn.execute("ALTER TABLE jobs ADD COLUMN audit_verdict TEXT")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS app_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)"
        )
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT 'user',
                disabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS blog_posts (
                id TEXT PRIMARY KEY,
                slug TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                excerpt TEXT NOT NULL DEFAULT '',
                body_md TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'draft',
                source_job_id TEXT,
                author_id TEXT,
                author_name TEXT NOT NULL DEFAULT '',
                cve TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                published_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_blog_status ON blog_posts(status, published_at);
            CREATE INDEX IF NOT EXISTS idx_blog_job ON blog_posts(source_job_id);
            """
        )


def _normalize_llm_cfg(cfg: dict[str, Any]) -> dict[str, Any]:
    merged = {**DEFAULT_LLM, **(cfg or {})}
    merged["prompts"] = {**DEFAULT_AGENT_PROMPTS, **(cfg.get("prompts") or {})}
    rs = (merged.get("report_structure") or "").strip()
    # Upgrade legacy outlines so detail / 漏洞链 constraints take effect.
    if (
        not rs
        or len(rs) < 800
        or "各节最低要求" not in rs
        or "## 6. 漏洞链" not in rs
        or "前端会直接渲染" not in rs
        or "## 16. IOC" not in rs
        or "## 17. 在野" not in rs
        or "## 18." not in rs
        or "## 19." not in rs
        or "检索结果" not in rs
        or "各节只写本职" not in rs
        or "禁止另开一级标题" not in rs
        or "函数逻辑链" not in rs
        or "第一个一级标题必须是" not in rs
    ):
        merged["report_structure"] = DEFAULT_LLM["report_structure"]
    if not (merged.get("system_prompt") or "").strip():
        merged["system_prompt"] = DEFAULT_LLM["system_prompt"]
    elif "详尽中文技术报告" in merged["system_prompt"] and "各节只写本职" not in merged["system_prompt"]:
        merged["system_prompt"] = DEFAULT_LLM["system_prompt"]
    # Prefer current specialist prompts unless clearly customized.
    for agent_id, default_prompt in DEFAULT_AGENT_PROMPTS.items():
        cur = (merged["prompts"].get(agent_id) or "").strip()
        legacy = {
            "ReportWriter": "补丁分析报告执笔人。结构必须完整。",
            "RootCauseAnalyst": "根因综合专家。",
        }
        if not cur or cur == legacy.get(agent_id) or (
            agent_id in ("ReportWriter", "RootCauseAnalyst") and "漏洞链" not in cur
        ) or (
            agent_id == "ReportWriter" and "IOC" not in cur
        ) or (
            agent_id == "ReportWriter" and "在野" not in cur
        ) or (
            agent_id == "ReportWriter" and "检索" not in cur
        ) or (
            agent_id == "ReportWriter" and "§18" not in cur and "18." not in cur
        ) or (
            agent_id == "ReportWriter" and ("不重复" not in cur or "禁止另开" not in cur)
        ) or (
            agent_id == "ReportWriter" and "函数调用图" not in cur
        ) or (
            agent_id == "ReportWriter" and "禁止只输出 §16" not in cur
        ) or (
            agent_id == "DetectionAnalyst" and len(cur) < 40
        ) or (
            agent_id == "DetectionAnalyst" and "一级标题" not in cur
        ) or (
            agent_id == "ThreatIntelAnalyst" and ("搜索" not in cur and "检索" not in cur or len(cur) < 40)
        ) or (
            agent_id == "ThreatIntelAnalyst" and "一级标题" not in cur
        ) or (
            agent_id == "BypassAnalyst" and len(cur) < 40
        ) or (
            agent_id == "BypassAnalyst" and "禁止按函数名推断" not in cur
        ) or (
            agent_id == "ResidualVulnAnalyst" and len(cur) < 40
        ) or (
            agent_id == "ResidualVulnAnalyst" and "禁止把 similar" not in cur
        ) or (
            agent_id == "AliasSiteAnalyst" and len(cur) < 40
        ) or (
            agent_id == "AliasSiteAnalyst" and "禁止按函数名推断" not in cur
        ) or (
            agent_id == "FeatureOffAnalyst" and len(cur) < 40
        ) or (
            agent_id in (
                "PEAnalyst", "SymbolAnalyst", "DisasmAnalyst", "FeatureAnalyst",
                "ControlPathAnalyst", "RootCauseAnalyst", "DetectionAnalyst", "ThreatIntelAnalyst",
            ) and "禁止输出 JSON" not in cur
        ) or (
            agent_id in ("BypassAnalyst", "ResidualVulnAnalyst", "AliasSiteAnalyst", "FeatureOffAnalyst")
            and "不要开场白" not in cur
        ):
            merged["prompts"][agent_id] = default_prompt
    if not merged.get("language"):
        merged["language"] = "zh"
    if merged.get("extra_focus") is None:
        merged["extra_focus"] = ""
    try:
        mt = int(merged.get("max_tokens") or 0)
        # Old default was 8192; bump so detailed reports are not truncated.
        if mt < 8192 or mt == 8192:
            merged["max_tokens"] = DEFAULT_LLM["max_tokens"]
    except (TypeError, ValueError):
        merged["max_tokens"] = DEFAULT_LLM["max_tokens"]
    try:
        if float(merged.get("temperature", 0.2)) == 0.2:
            merged["temperature"] = DEFAULT_LLM["temperature"]
    except (TypeError, ValueError):
        merged["temperature"] = DEFAULT_LLM["temperature"]
    return merged


def get_llm_config() -> dict[str, Any]:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT config_json FROM llm_config WHERE id = 1").fetchone()
        cfg = json.loads(row["config_json"])
        return _normalize_llm_cfg(cfg)


def save_llm_config(cfg: dict[str, Any]) -> dict[str, Any]:
    init_db()
    merged = _normalize_llm_cfg(cfg)
    with connect() as conn:
        conn.execute(
            "UPDATE llm_config SET config_json = ?, updated_at = ? WHERE id = 1",
            (json.dumps(merged, ensure_ascii=False), _utcnow()),
        )
    return merged


KIND_PATCH = "patch_diff"
KIND_AUDIT = "kernel_audit"


def normalize_kind(kind: str | None) -> str:
    k = (kind or "").strip().lower().replace("-", "_")
    if k in {KIND_AUDIT, "audit", "solo", "solo_hunt"}:
        return KIND_AUDIT
    return KIND_PATCH


def create_job(
    job_id: str,
    title: str,
    old_label: str,
    new_label: str,
    old_filename: str,
    new_filename: str,
    mid_label: str | None = None,
    mid_filename: str | None = None,
    enabled_agents: list[str] | None = None,
    kind: str = KIND_PATCH,
) -> dict[str, Any]:
    init_db()
    now = _utcnow()
    agents_json = json.dumps(enabled_agents, ensure_ascii=False) if enabled_agents is not None else None
    kind = normalize_kind(kind)
    with connect() as conn:
        conn.execute(
            """INSERT INTO jobs (id, title, status, old_label, new_label,
               old_filename, new_filename, mid_label, mid_filename, agents_json,
               kind, error, result_json, created_at, updated_at)
               VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)""",
            (
                job_id,
                title,
                old_label,
                new_label,
                old_filename,
                new_filename,
                mid_label,
                mid_filename,
                agents_json,
                kind,
                now,
                now,
            ),
        )
    invalidate_jobs_cache()
    return get_job(job_id)


def _verdicts_from_result_json(raw: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not raw:
        return out
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return out
    art = (data or {}).get("artifacts") if isinstance(data, dict) else None
    if not isinstance(art, dict):
        return out
    intel = art.get("threat_intel") if isinstance(art.get("threat_intel"), dict) else {}
    out["in_kev"] = 1 if intel.get("in_kev") else 0
    bypass = art.get("bypass_pack") if isinstance(art.get("bypass_pack"), dict) else {}
    residual = art.get("residual_pack") if isinstance(art.get("residual_pack"), dict) else {}
    out["bypass_verdict"] = str(bypass.get("verdict") or "") or None
    out["residual_verdict"] = str(residual.get("verdict") or "") or None
    audit = art.get("kernel_audit") if isinstance(art.get("kernel_audit"), dict) else {}
    out["audit_verdict"] = str(audit.get("verdict") or "") or None
    return out


def _result_path(job_id: str):
    return JOBS_DIR / job_id / "job_result.json"


def save_job_result(job_id: str, result_json: Any) -> None:
    if result_json is None or result_json == "":
        return
    text = result_json if isinstance(result_json, str) else json.dumps(result_json, ensure_ascii=False)
    write_text_replace(_result_path(job_id), text)


def load_job_result(job_id: str, fallback_raw: str | None = None) -> dict[str, Any] | None:
    path = _result_path(job_id)
    raw = None
    if path.is_file() and path.stat().st_size > 2:
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            raw = None
    if raw is None and fallback_raw:
        raw = fallback_raw
        try:
            save_job_result(job_id, fallback_raw)
        except OSError:
            pass
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if "artifacts" not in data and ("old_pe" in data or "symbol_diff" in data or "llm_report" in data):
        data = {"artifacts": data}
    return data


def update_job(job_id: str, **fields) -> None:
    fields["updated_at"] = _utcnow()
    if "result_json" in fields:
        raw = fields.pop("result_json")
        if raw:
            save_job_result(job_id, raw)
            if not isinstance(raw, str):
                raw = json.dumps(raw, ensure_ascii=False)
            fields.update(_verdicts_from_result_json(raw))
        fields["result_json"] = None
    cols = ", ".join(f"{k} = ?" for k in fields)
    with connect() as conn:
        conn.execute(
            f"UPDATE jobs SET {cols} WHERE id = ?",
            (*fields.values(), job_id),
        )
    invalidate_jobs_cache()


def _parse_job_row(row: sqlite3.Row, *, lite: bool = False) -> dict[str, Any]:
    d = dict(row)
    raw_agents = d.pop("agents_json", None)
    if raw_agents:
        try:
            d["enabled_agents"] = json.loads(raw_agents)
        except (TypeError, ValueError):
            d["enabled_agents"] = None
    else:
        d["enabled_agents"] = None
    raw = d.pop("result_json", None)
    d["kind"] = normalize_kind(d.get("kind"))
    if lite:
        d["result"] = None
        return d
    d["result"] = load_job_result(d.get("id") or "", raw)
    return d


def get_job(job_id: str, *, lite: bool = False) -> dict[str, Any] | None:
    init_db()
    path = _result_path(job_id)
    need_blob = (not lite) and not (path.is_file() and path.stat().st_size > 2)
    sql = (
        "SELECT id, title, status, old_label, new_label, mid_label, old_filename, new_filename, "
        "mid_filename, error, created_at, updated_at, agents_json, kind, audit_verdict"
        + (", result_json" if need_blob else "")
        + " FROM jobs WHERE id = ?"
    )
    with connect() as conn:
        row = conn.execute(sql, (job_id,)).fetchone()
    if not row:
        return None
    return _parse_job_row(row, lite=lite)


def fail_stale_jobs(message: str = "服务重启或进程中断，任务未完成") -> int:
    """Fail running jobs whose worker pid is gone. Pending jobs without a worker
    are left pending so the API process can start them after the event loop is up.
    """
    from .worker_proc import pid_alive, read_worker_pid

    init_db()
    now = _utcnow()
    with connect() as conn:
        rows = conn.execute("SELECT id FROM jobs WHERE status = 'running'").fetchall()
    n = 0
    for row in rows:
        job_id = row["id"]
        if pid_alive(read_worker_pid(job_id)):
            continue
        with connect() as conn:
            conn.execute(
                "UPDATE jobs SET status = 'failed', error = ?, updated_at = ? "
                "WHERE id = ? AND status = 'running'",
                (message, now, job_id),
            )
        n += 1
    if n:
        invalidate_jobs_cache()
    return n


_CVE_IN_TITLE = re.compile(r"CVE-\d{4}-\d+", re.I)


def extract_job_cve(title: str) -> str:
    m = _CVE_IN_TITLE.search(title or "")
    return m.group(0).upper() if m else ""


_jobs_cache: list[dict[str, Any]] = []
_jobs_cache_at = 0.0
_jobs_cache_lock = threading.Lock()
_JOBS_CACHE_TTL = 1.0


def invalidate_jobs_cache() -> None:
    global _jobs_cache_at
    with _jobs_cache_lock:
        _jobs_cache_at = 0.0


def peek_jobs_cache(limit: int = 500) -> list[dict[str, Any]] | None:
    with _jobs_cache_lock:
        if not _jobs_cache or (time.monotonic() - _jobs_cache_at) >= _JOBS_CACHE_TTL:
            return None
        return [dict(j) for j in _jobs_cache[: max(1, limit)]]


def list_jobs_cached(limit: int = 500) -> list[dict[str, Any]]:
    global _jobs_cache_at
    hit = peek_jobs_cache(limit)
    if hit is not None:
        return hit
    rows = list_jobs(limit=max(limit, 500))
    with _jobs_cache_lock:
        _jobs_cache[:] = rows
        _jobs_cache_at = time.monotonic()
        return [dict(j) for j in _jobs_cache[: max(1, limit)]]


def list_jobs(limit: int = 500) -> list[dict[str, Any]]:
    init_db()
    sql = (
        "SELECT id, title, status, old_label, new_label, mid_label, error, created_at, updated_at, "
        "in_kev, bypass_verdict, residual_verdict, kind, audit_verdict "
        "FROM jobs ORDER BY created_at DESC LIMIT ?"
    )
    fallback = (
        "SELECT id, title, status, old_label, new_label, mid_label, error, created_at, updated_at "
        "FROM jobs ORDER BY created_at DESC LIMIT ?"
    )
    with connect() as conn:
        try:
            rows = conn.execute(sql, (limit,)).fetchall()
        except Exception:
            rows = conn.execute(fallback, (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["cve"] = extract_job_cve(d.get("title") or "")
        d["kind"] = normalize_kind(d.get("kind"))
        out.append(d)
    return out


def _user_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if not row:
        return None
    d = dict(row)
    d["disabled"] = bool(d.get("disabled"))
    return d


def public_user(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not row:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "display_name": row.get("display_name") or row["username"],
        "role": row.get("role") or "user",
        "disabled": bool(row.get("disabled")),
        "created_at": row.get("created_at") or "",
        "updated_at": row.get("updated_at") or "",
    }


def count_users() -> int:
    init_db()
    with connect() as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
    return int(n["n"] if n else 0)


def count_admins(*, exclude_id: str = "") -> int:
    init_db()
    with connect() as conn:
        if exclude_id:
            n = conn.execute(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?",
                (exclude_id,),
            ).fetchone()
        else:
            n = conn.execute(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0"
            ).fetchone()
    return int(n["n"] if n else 0)


def list_users() -> list[dict[str, Any]]:
    init_db()
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, username, display_name, role, disabled, created_at, updated_at "
            "FROM users ORDER BY role = 'admin' DESC, created_at ASC"
        ).fetchall()
    return [public_user(dict(r)) for r in rows if public_user(dict(r))]


def get_user(user_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _user_row(row)


def get_user_by_username(username: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE lower(username) = lower(?)",
            (username or "",),
        ).fetchone()
    return _user_row(row)


def insert_user(
    user_id: str,
    username: str,
    password_hash: str,
    *,
    display_name: str = "",
    role: str = "user",
) -> dict[str, Any]:
    init_db()
    now = _utcnow()
    name = (display_name or username).strip()
    with connect() as conn:
        conn.execute(
            "INSERT INTO users (id, username, password_hash, display_name, role, disabled, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
            (user_id, username, password_hash, name, role, now, now),
        )
    return public_user(get_user(user_id)) or {}


def update_user(user_id: str, **fields: Any) -> dict[str, Any] | None:
    init_db()
    allowed = {"display_name", "role", "disabled", "password_hash"}
    sets = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if "disabled" in sets:
        sets["disabled"] = 1 if sets["disabled"] else 0
    if not sets:
        return public_user(get_user(user_id))
    sets["updated_at"] = _utcnow()
    cols = ", ".join(f"{k} = ?" for k in sets)
    with connect() as conn:
        conn.execute(f"UPDATE users SET {cols} WHERE id = ?", (*sets.values(), user_id))
    return public_user(get_user(user_id))


def delete_user(user_id: str) -> None:
    init_db()
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def create_session(token_hash: str, user_id: str, expires_at: str) -> None:
    init_db()
    with connect() as conn:
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, user_id, _utcnow(), expires_at),
        )


def get_session_user(token_hash: str) -> dict[str, Any] | None:
    init_db()
    now = _utcnow()
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = ? AND s.expires_at >= ?",
            (token_hash, now),
        ).fetchone()
    return _user_row(row)


def delete_session(token_hash: str) -> None:
    init_db()
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def delete_user_sessions(user_id: str, *, keep_hash: str = "") -> None:
    init_db()
    with connect() as conn:
        if keep_hash:
            conn.execute(
                "DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
                (user_id, keep_hash),
            )
        else:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def _blog_row(row: sqlite3.Row | None, *, public: bool = False) -> dict[str, Any] | None:
    if not row:
        return None
    d = dict(row)
    if public:
        d.pop("author_id", None)
        d.pop("source_job_id", None)
        if d.get("status") != "published":
            return None
    return d


def list_blog_posts(*, status: str | None = None, limit: int = 50, with_intro: bool = False) -> list[dict[str, Any]]:
    init_db()
    limit = max(1, min(int(limit or 50), 200))
    sql = (
        "SELECT id, slug, title, excerpt, status, source_job_id, author_id, author_name, "
        "cve, created_at, updated_at, published_at"
        + (", substr(body_md, 1, 12000) AS body_head" if with_intro else "")
        + " FROM blog_posts"
    )
    args: list[Any] = []
    if status:
        sql += " WHERE status = ?"
        args.append(status)
    sql += " ORDER BY COALESCE(published_at, updated_at) DESC LIMIT ?"
    args.append(limit)
    with connect() as conn:
        rows = conn.execute(sql, args).fetchall()
    return [dict(r) for r in rows]


def get_blog_post(post_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM blog_posts WHERE id = ?", (post_id,)).fetchone()
    return dict(row) if row else None


def get_blog_by_slug(slug: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM blog_posts WHERE slug = ?", (slug,)).fetchone()
    return dict(row) if row else None


def get_blog_by_job(job_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM blog_posts WHERE source_job_id = ? ORDER BY updated_at DESC LIMIT 1",
            (job_id,),
        ).fetchone()
    return dict(row) if row else None


def slug_taken(slug: str, exclude_id: str = "") -> bool:
    init_db()
    with connect() as conn:
        if exclude_id:
            row = conn.execute(
                "SELECT 1 FROM blog_posts WHERE slug = ? AND id != ?",
                (slug, exclude_id),
            ).fetchone()
        else:
            row = conn.execute("SELECT 1 FROM blog_posts WHERE slug = ?", (slug,)).fetchone()
    return bool(row)


def insert_blog_post(post: dict[str, Any]) -> dict[str, Any]:
    init_db()
    now = _utcnow()
    row = {
        "id": post["id"],
        "slug": post["slug"],
        "title": post["title"],
        "excerpt": post.get("excerpt") or "",
        "body_md": post.get("body_md") or "",
        "status": post.get("status") or "draft",
        "source_job_id": post.get("source_job_id"),
        "author_id": post.get("author_id"),
        "author_name": post.get("author_name") or "",
        "cve": post.get("cve") or "",
        "created_at": now,
        "updated_at": now,
        "published_at": post.get("published_at"),
    }
    with connect() as conn:
        conn.execute(
            "INSERT INTO blog_posts (id, slug, title, excerpt, body_md, status, source_job_id, "
            "author_id, author_name, cve, created_at, updated_at, published_at) "
            "VALUES (:id, :slug, :title, :excerpt, :body_md, :status, :source_job_id, "
            ":author_id, :author_name, :cve, :created_at, :updated_at, :published_at)",
            row,
        )
    return get_blog_post(row["id"]) or row


def update_blog_post(post_id: str, **fields) -> dict[str, Any] | None:
    if not fields:
        return get_blog_post(post_id)
    fields["updated_at"] = _utcnow()
    cols = ", ".join(f"{k} = ?" for k in fields)
    with connect() as conn:
        conn.execute(
            f"UPDATE blog_posts SET {cols} WHERE id = ?",
            (*fields.values(), post_id),
        )
    return get_blog_post(post_id)


def delete_blog_post(post_id: str) -> bool:
    init_db()
    with connect() as conn:
        cur = conn.execute("DELETE FROM blog_posts WHERE id = ?", (post_id,))
        return cur.rowcount > 0
