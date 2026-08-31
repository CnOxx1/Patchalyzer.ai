"""Patchalyzer.ai — Windows driver patch diff web API."""
from __future__ import annotations

import asyncio
import functools
import json
import re
import shutil
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
import zipfile
import io
from pydantic import BaseModel, Field

from .config import ANALYSIS_CONCURRENCY, DEFAULT_LLM, JOBS_DIR, MAX_UPLOAD_MB, SESSION_COOKIE, SESSION_DAYS, WEBAPP_ROOT, ensure_dirs, llm_defaults_public, normalize_enabled_agents
from .auth import (
    create_account,
    current_user,
    ensure_default_admin,
    is_public_api,
    login as auth_login,
    logout as auth_logout,
    patch_account,
    public_user,
    remove_account,
    require_admin,
    resolve_user,
    token_from_request,
    users_for_admin,
)
from .database import (
    create_job,
    delete_blog_post,
    extract_job_cve,
    fail_stale_jobs,
    get_blog_by_job,
    get_blog_by_slug,
    get_blog_post,
    get_job,
    get_llm_config,
    init_db,
    insert_blog_post,
    list_blog_posts,
    list_jobs_cached,
    peek_jobs_cache,
    save_llm_config,
    update_blog_post,
    update_job,
    KIND_AUDIT,
    normalize_kind,
)
from .services.pipeline import (
    clear_cancel,
    request_cancel,
    save_routing_mode,
    read_progress_file,
)
from .services.blog import (
    excerpt_from_markdown,
    make_slug,
    public_post,
    public_post_card,
    publish_job_report,
    sanitize_markdown,
)
from .services.ioc import build_ioc_pack_from_artifacts, ensure_ioc_section
from .services.report_complete import complete_llm_report, heal_artifacts_report
from .services.patch_review import (
    build_bypass_pack,
    build_residual_pack,
    ensure_bypass_section,
    ensure_residual_section,
    notes_without_json,
    sanitize_bypass_pack,
    sanitize_residual_pack,
)
from .services.threat_intel import (
    attach_analyst_notes,
    component_from_artifacts,
    ensure_threat_section,
    lookup_threat_intel,
    resolve_cve_from_artifacts,
    threat_intel_for_artifacts,
)
from .services.analyzer import write_verify_pack
from .services.llm_service import LLMError, llm_configured, test_connection
from .services.job_view import slim_job
from .services.func_logic import ensure_func_logic_section
from .services.patch_resolver import (
    PatchResolveError,
    list_patch_days,
    list_patch_tuesday,
    resolve_pair_from_cve,
    resolve_patched_binary,
)
from .services.hunt_lab import (
    archive_hunt_run,
    ensure_hunt_index,
    load_current_hunt_lab,
    load_hunt_run,
    run_hunt_lab,
    stamp_hunt_pack,
)
from .services.research_lab import run_research_lab
from .services.patch_watch import (
    auto_ingest,
    bind_enqueue,
    get_watch_config,
    refresh_bulletin,
    save_watch_config,
    watch_loop,
)

# In-memory job progress (message / percent)
JOB_PROGRESS: dict[str, dict] = {}
HUNT_LAB_PROGRESS: dict[str, dict] = {}
RESEARCH_LAB_PROGRESS: dict[str, dict] = {}
_MAIN_LOOP: asyncio.AbstractEventLoop | None = None
_ANALYSIS_GATE: asyncio.Semaphore | None = None
_ANALYSIS_ACTIVE = 0
_JOB_TASKS: set[asyncio.Task] = set()
_SUPERVISING: set[str] = set()
_API_EXECUTOR: ThreadPoolExecutor | None = None
_FINISHED_EVENTS: list[tuple[float, dict]] = []


def _api_exec() -> ThreadPoolExecutor:
    """Short SQLite / HTTP helpers. Never share this with LangGraph."""
    global _API_EXECUTOR
    if _API_EXECUTOR is None:
        _API_EXECUTOR = ThreadPoolExecutor(max_workers=16, thread_name_prefix="pa-api")
    return _API_EXECUTOR


async def _run_api(fn, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_api_exec(), functools.partial(fn, *args, **kwargs))


def _note_finished(job_id: str, status: str, error: str = "") -> None:
    now = time.monotonic()
    _FINISHED_EVENTS.append((now, {"id": job_id, "status": status, "error": error or ""}))
    cutoff = now - 30
    _FINISHED_EVENTS[:] = [x for x in _FINISHED_EVENTS if x[0] >= cutoff][-20:]


def _runtime_progress(job_id: str) -> dict | None:
    return JOB_PROGRESS.get(job_id) or read_progress_file(job_id)


def _live_event_payload() -> dict:
    rows = peek_jobs_cache(5000)
    if rows is None:
        rows = list_jobs_cached(500)
    live = []
    for job in rows:
        if job.get("status") not in ("running", "pending"):
            continue
        item = dict(job)
        jid = item.get("id") or ""
        prog = _runtime_progress(jid)
        if prog:
            item["progress"] = prog
        if jid in HUNT_LAB_PROGRESS:
            item["hunt_lab_progress"] = HUNT_LAB_PROGRESS[jid]
        if jid in RESEARCH_LAB_PROGRESS:
            item["research_lab_progress"] = RESEARCH_LAB_PROGRESS[jid]
        live.append(item)
    return {
        "live": live,
        "finished": [ev for _, ev in _FINISHED_EVENTS],
    }


def _analysis_gate() -> asyncio.Semaphore:
    """Cap concurrent full analyses (default 2). Extra jobs wait for a free slot."""
    global _ANALYSIS_GATE
    if _ANALYSIS_GATE is None:
        _ANALYSIS_GATE = asyncio.Semaphore(ANALYSIS_CONCURRENCY)
    return _ANALYSIS_GATE


def spawn_analysis_job(
    job_id: str,
    run_llm: bool,
    cve: str = "",
    *,
    resume: bool = False,
    force_nodes: list[str] | None = None,
) -> None:
    """Schedule analysis on the server loop. Do not use FastAPI BackgroundTasks:

    those run after the HTTP response and hold HTTP/1.1 keep-alive, so a second
    job started from the same tab would wait until the first finished.
    """
    spawn_job_worker(job_id, run_llm, cve, resume=resume, force_nodes=force_nodes)


def spawn_audit_job(job_id: str, run_llm: bool, *, resume: bool = False) -> None:
    spawn_job_worker(job_id, run_llm, "", resume=resume, kind="audit")


def spawn_job_worker(
    job_id: str,
    run_llm: bool,
    cve: str = "",
    *,
    resume: bool = False,
    force_nodes: list[str] | None = None,
    kind: str | None = None,
) -> None:
    if job_id in _SUPERVISING:
        return
    worker_kind = kind or _job_worker_kind(job_id)
    coro = _supervise_job(
        worker_kind,
        {
            "job_id": job_id,
            "run_llm": run_llm,
            "cve": cve or "",
            "resume": resume,
            "force_nodes": force_nodes,
        },
    )
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = _MAIN_LOOP
        if not loop or not loop.is_running():
            raise RuntimeError("分析服务尚未就绪")
        asyncio.run_coroutine_threadsafe(coro, loop)
        return
    task = loop.create_task(coro)
    _JOB_TASKS.add(task)
    task.add_done_callback(_JOB_TASKS.discard)


def _job_worker_kind(job_id: str, job: dict | None = None) -> str:
    row = job or get_job(job_id, lite=True) or {}
    if normalize_kind(row.get("kind")) == KIND_AUDIT:
        return "audit"
    ingest = JOBS_DIR / job_id / "ingest.json"
    if ingest.is_file():
        try:
            data = json.loads(ingest.read_text(encoding="utf-8"))
            if normalize_kind(data.get("kind")) == KIND_AUDIT:
                return "audit"
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    return "full"


def _job_cve(job_id: str, title: str = "") -> str:
    path = JOBS_DIR / job_id / "ingest.json"
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            cve = str(data.get("cve") or "").strip()
            if cve:
                return cve
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    return extract_job_cve(title)


def _kick_orphan_pending_jobs() -> int:
    """Start pending jobs that have no live worker and no in-process supervisor."""
    from .worker_proc import pid_alive, read_worker_pid

    n = 0
    for job in list_jobs_cached(500):
        if job.get("status") != "pending":
            continue
        job_id = str(job.get("id") or "")
        if not job_id or job_id in _SUPERVISING or pid_alive(read_worker_pid(job_id)):
            continue
        print(f"[analysis] kick orphan pending {job_id}", flush=True)
        spawn_job_worker(
            job_id,
            llm_configured(),
            _job_cve(job_id, str(job.get("title") or "")),
            resume=True,
            kind=_job_worker_kind(job_id, job),
        )
        n += 1
    return n


async def _orphan_kick_loop() -> None:
    while True:
        await asyncio.sleep(8)
        try:
            _kick_orphan_pending_jobs()
        except Exception as e:
            print(f"[analysis] orphan kick failed: {e}", flush=True)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _MAIN_LOOP
    _MAIN_LOOP = asyncio.get_running_loop()
    _api_exec()
    bind_enqueue(enqueue_cve_job)
    fail_stale_hunt_labs()
    await _reattach_live_workers()
    _kick_orphan_pending_jobs()
    task = asyncio.create_task(watch_loop())
    kick = asyncio.create_task(_orphan_kick_loop())
    try:
        yield
    finally:
        kick.cancel()
        task.cancel()
        for t in (kick, task):
            try:
                await t
            except asyncio.CancelledError:
                pass
        # Detached analysis children keep running; do not kill them.


app = FastAPI(
    title="Patchalyzer.ai",
    description="Windows 驱动补丁静态分析 + LLM 报告",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ensure_dirs()
init_db()
ensure_default_admin()
fail_stale_jobs()
save_llm_config(get_llm_config())


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=max(1, SESSION_DAYS) * 86400,
        path="/",
    )


@app.middleware("http")
async def require_login(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)
    path = request.url.path
    if path.startswith("/api/") and not is_public_api(request.method, path):
        user = resolve_user(request)
        if not user:
            return JSONResponse({"detail": "未登录"}, status_code=401)
        request.state.user = user
    return await call_next(request)


class LLMConfigUpdate(BaseModel):
    provider: str = "openai"
    base_url: str = "https://api.openai.com/v1"
    api_key: str | None = None
    model: str = "gpt-4o-mini"
    temperature: float = 0.15
    max_tokens: int = 16384
    language: str = "zh"
    extra_focus: str = ""
    system_prompt: str = Field(default_factory=lambda: DEFAULT_LLM["system_prompt"])
    report_structure: str = Field(default_factory=lambda: DEFAULT_LLM["report_structure"])
    prompts: dict[str, str] = Field(default_factory=dict)


class GepaOptimizeRequest(BaseModel):
    agent_id: str
    max_metric_calls: int = 16
    apply: bool = True


class LoginBody(BaseModel):
    username: str = ""
    password: str = ""


class UserCreateBody(BaseModel):
    username: str
    password: str
    display_name: str = ""
    role: str = "user"


class UserUpdateBody(BaseModel):
    display_name: str | None = None
    role: str | None = None
    disabled: bool | None = None
    password: str | None = None
    old_password: str | None = None


class BlogPublishBody(BaseModel):
    title: str | None = None
    excerpt: str | None = None
    status: str = "published"


class BlogCreateBody(BaseModel):
    title: str
    body_md: str
    excerpt: str = ""
    status: str = "draft"
    slug: str = ""
    cve: str = ""


class BlogUpdateBody(BaseModel):
    title: str | None = None
    excerpt: str | None = None
    body_md: str | None = None
    status: str | None = None
    slug: str | None = None
    cve: str | None = None


def _mask_config(cfg: dict) -> dict:
    out = dict(cfg)
    key = out.get("api_key") or ""
    if key:
        out["api_key_set"] = True
        out["api_key_preview"] = key[:4] + "..." + key[-4:] if len(key) > 8 else "****"
    else:
        out["api_key_set"] = False
        out["api_key_preview"] = ""
    out.pop("api_key", None)
    return out


def _save_upload_sync(upload: UploadFile, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    upload.file.seek(0)
    size = 0
    limit = MAX_UPLOAD_MB * 1024 * 1024
    with dest.open("wb") as f:
        while chunk := upload.file.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise HTTPException(413, f"File exceeds {MAX_UPLOAD_MB}MB limit")
            f.write(chunk)
    upload.file.seek(0)


_WORKER_KINDS = {"full", "hotspot", "llm", "audit"}


async def _reattach_live_workers() -> None:
    """Resume progress polling for analysis children that survived the previous API process."""
    from .worker_proc import pid_alive, read_worker_payload, read_worker_pid

    for job in list_jobs_cached(500):
        if job.get("status") not in ("pending", "running"):
            continue
        job_id = str(job.get("id") or "")
        if not job_id or not pid_alive(read_worker_pid(job_id)):
            continue
        payload = read_worker_payload(job_id) or {"job_id": job_id, "_kind": "full"}
        kind = str(payload.get("_kind") or "full")
        if kind not in _WORKER_KINDS:
            kind = "full"
        print(f"[analysis] reattach {job_id} kind={kind}", flush=True)
        task = asyncio.create_task(_supervise_job(kind, payload))
        _JOB_TASKS.add(task)
        task.add_done_callback(_JOB_TASKS.discard)


async def _await_worker(job_id: str, proc) -> dict:
    from .worker_proc import pid_alive, read_worker_pid, read_worker_result

    while True:
        prog = read_progress_file(job_id)
        if prog:
            JOB_PROGRESS[job_id] = prog
        if proc is not None:
            if proc.poll() is not None:
                break
        elif not pid_alive(read_worker_pid(job_id)):
            break
        await asyncio.sleep(0.4)

    result = read_worker_result(job_id)
    if result is not None:
        return result
    job = get_job(job_id, lite=True)
    status = str((job or {}).get("status") or "")
    if status in ("completed", "cancelled"):
        return {"ok": status == "completed", "status": status}
    err = str((job or {}).get("error") or "分析进程已退出，但没有写出结果")
    if job and status in ("running", "pending"):
        update_job(job_id, status="failed", error=err)
    return {"ok": False, "status": "failed", "error": err}


async def _supervise_job(kind: str, payload: dict) -> dict:
    """Run graph/LLM in a detached child; copy progress.json into RAM for SSE."""
    global _ANALYSIS_ACTIVE
    from .worker_proc import pid_alive, read_worker_pid, spawn_worker

    job_id = str(payload.get("job_id") or "")
    if not job_id:
        return {"ok": False, "status": "failed", "error": "missing job_id"}
    if kind not in _WORKER_KINDS:
        return {"ok": False, "status": "failed", "error": f"unknown worker {kind}"}
    if job_id in _SUPERVISING:
        return {"ok": True, "status": "pending"}
    _SUPERVISING.add(job_id)
    try:
        body = dict(payload)
        body["_kind"] = kind
        gate = _analysis_gate()
        already = pid_alive(read_worker_pid(job_id))
        if not already and _ANALYSIS_ACTIVE >= ANALYSIS_CONCURRENCY:
            JOB_PROGRESS[job_id] = {
                "message": f"排队等待空闲分析槽（最多同时 {ANALYSIS_CONCURRENCY} 个）…",
                "percent": 0,
            }
        async with gate:
            _ANALYSIS_ACTIVE += 1
            print(
                f"[analysis] start {job_id} kind={kind} active={_ANALYSIS_ACTIVE}/{ANALYSIS_CONCURRENCY}"
                + (" reattach" if already else ""),
                flush=True,
            )
            proc = None
            result: dict = {"ok": False, "status": "failed", "error": "worker did not start"}
            try:
                if not already:
                    proc = spawn_worker(job_id, body)
                    for _ in range(80):
                        if read_worker_pid(job_id):
                            break
                        if proc.poll() is not None:
                            break
                        await asyncio.sleep(0.1)
                result = await _await_worker(job_id, proc if not already else None)
            except Exception as e:
                job = get_job(job_id, lite=True)
                if job and job.get("status") in ("running", "pending"):
                    update_job(job_id, status="failed", error=str(e))
                result = {"ok": False, "status": "failed", "error": str(e)}
            finally:
                JOB_PROGRESS.pop(job_id, None)
                _ANALYSIS_ACTIVE = max(0, _ANALYSIS_ACTIVE - 1)
                print(
                    f"[analysis] end {job_id} kind={kind} active={_ANALYSIS_ACTIVE}/{ANALYSIS_CONCURRENCY}",
                    flush=True,
                )
            status = str(result.get("status") or ("completed" if result.get("ok") else "failed"))
            _note_finished(job_id, status, str(result.get("error") or ""))
            return result
    finally:
        _SUPERVISING.discard(job_id)


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "patchalyzer", "graph": "langgraph-multi-agent", "audit": True}


@app.post("/api/jobs/audit")
async def api_create_audit_job(
    title: str = Form(""),
    run_llm: bool = Form(True),
    sample: UploadFile | None = File(None),
):
    has_sample = sample is not None and bool(sample.filename)
    if not has_sample:
        raise HTTPException(400, "请上传一个 .sys / .dll / .exe 内核或驱动文件")
    job_id = uuid.uuid4().hex[:12]
    work = JOBS_DIR / job_id
    work.mkdir(parents=True, exist_ok=True)
    sample_name = f"sample_{sample.filename}"
    title = (title or "").strip() or Path(sample.filename or "kernel").stem
    try:
        await asyncio.to_thread(_save_upload_sync, sample, work / sample_name)
    except HTTPException:
        shutil.rmtree(work, ignore_errors=True)
        raise
    (work / "ingest.json").write_text(
        json.dumps({"kind": KIND_AUDIT, "filename": sample.filename, "run_llm": run_llm}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    create_job(
        job_id,
        title,
        Path(sample.filename or "sample").name,
        "单文件审计",
        sample_name,
        "",
        kind=KIND_AUDIT,
    )
    spawn_audit_job(job_id, run_llm)
    return {"job_id": job_id, "status": "pending", "kind": KIND_AUDIT}


@app.post("/api/auth/login")
def api_login(body: LoginBody, request: Request):
    user, token = auth_login(body.username, body.password, request)
    resp = JSONResponse({"user": user})
    _set_session_cookie(resp, token)
    return resp


@app.post("/api/auth/logout")
def api_logout(request: Request):
    auth_logout(request)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/api/auth/me")
def api_me(request: Request):
    user = resolve_user(request)
    return {"user": public_user(user) if user else None}


@app.get("/api/public/blog")
def api_public_blog_list(limit: int = Query(20, ge=1, le=100)):
    rows = list_blog_posts(status="published", limit=limit, with_intro=True)
    return {"items": [public_post_card(r) for r in rows]}


@app.get("/api/public/blog/{slug}")
def api_public_blog_post(slug: str):
    row = get_blog_by_slug(slug)
    post = public_post(row)
    if not post:
        raise HTTPException(404, "文章不存在")
    return post


@app.get("/api/blog")
def api_blog_admin_list(request: Request, status: str = Query(""), limit: int = Query(80, ge=1, le=200)):
    current_user(request)
    st = status.strip().lower() or None
    if st and st not in {"draft", "published"}:
        raise HTTPException(400, "status 只能是 draft 或 published")
    return {"items": list_blog_posts(status=st, limit=limit)}


@app.get("/api/blog/{post_id}")
def api_blog_admin_get(post_id: str, request: Request):
    current_user(request)
    row = get_blog_post(post_id)
    if not row:
        raise HTTPException(404, "文章不存在")
    return row


@app.post("/api/blog")
def api_blog_create(body: BlogCreateBody, request: Request):
    user = current_user(request)
    title = (body.title or "").strip()
    md = sanitize_markdown(body.body_md or "")
    if not title or not md:
        raise HTTPException(400, "标题和正文不能为空")
    st = (body.status or "draft").strip().lower()
    if st not in {"draft", "published"}:
        raise HTTPException(400, "状态只能是 draft 或 published")
    from datetime import datetime, timezone

    slug = (body.slug or "").strip().lower() or make_slug(title, body.cve or "")
    slug = re.sub(r"[^a-z0-9-]+", "-", slug).strip("-") or make_slug(title, body.cve or "")
    if get_blog_by_slug(slug):
        slug = make_slug(title, body.cve or "")
    published_at = datetime.now(timezone.utc).isoformat() if st == "published" else None
    return insert_blog_post(
        {
            "id": uuid.uuid4().hex[:12],
            "slug": slug,
            "title": title,
            "excerpt": (body.excerpt or "").strip() or excerpt_from_markdown(md),
            "body_md": md,
            "status": st,
            "source_job_id": None,
            "author_id": user.get("id"),
            "author_name": (user.get("display_name") or user.get("username") or "").strip(),
            "cve": (body.cve or "").strip().upper(),
            "published_at": published_at,
        }
    )


@app.patch("/api/blog/{post_id}")
def api_blog_update(post_id: str, body: BlogUpdateBody, request: Request):
    current_user(request)
    row = get_blog_post(post_id)
    if not row:
        raise HTTPException(404, "文章不存在")
    fields: dict = {}
    if body.title is not None:
        title = body.title.strip()
        if not title:
            raise HTTPException(400, "标题不能为空")
        fields["title"] = title
    if body.excerpt is not None:
        fields["excerpt"] = body.excerpt.strip()
    if body.body_md is not None:
        md = sanitize_markdown(body.body_md)
        if not md:
            raise HTTPException(400, "正文不能为空")
        fields["body_md"] = md
    if body.cve is not None:
        fields["cve"] = body.cve.strip().upper()
    if body.slug is not None:
        slug = re.sub(r"[^a-z0-9-]+", "-", (body.slug or "").strip().lower()).strip("-")
        if not slug:
            raise HTTPException(400, "slug 无效")
        if get_blog_by_slug(slug) and get_blog_by_slug(slug).get("id") != post_id:
            raise HTTPException(400, "slug 已被占用")
        fields["slug"] = slug
    if body.status is not None:
        st = body.status.strip().lower()
        if st not in {"draft", "published"}:
            raise HTTPException(400, "状态只能是 draft 或 published")
        fields["status"] = st
        from datetime import datetime, timezone

        if st == "published":
            fields["published_at"] = row.get("published_at") or datetime.now(timezone.utc).isoformat()
        else:
            fields["published_at"] = None
    return update_blog_post(post_id, **fields) or row


@app.delete("/api/blog/{post_id}")
def api_blog_delete(post_id: str, request: Request):
    current_user(request)
    if not delete_blog_post(post_id):
        raise HTTPException(404, "文章不存在")
    return {"ok": True}


@app.get("/api/jobs/{job_id}/blog")
def api_job_blog(job_id: str, request: Request):
    current_user(request)
    row = get_blog_by_job(job_id)
    return {"post": row}


@app.post("/api/jobs/{job_id}/blog")
def api_publish_job_blog(job_id: str, body: BlogPublishBody, request: Request):
    user = current_user(request)
    return publish_job_report(
        job_id,
        user,
        title=body.title,
        excerpt=body.excerpt,
        status=body.status,
    )


@app.get("/api/users")
def api_list_users(request: Request):
    require_admin(request)
    return users_for_admin()


@app.post("/api/users")
def api_create_user(body: UserCreateBody, request: Request):
    require_admin(request)
    return create_account(
        username=body.username,
        password=body.password,
        display_name=body.display_name,
        role=body.role,
    )


@app.put("/api/users/{user_id}")
def api_update_user(user_id: str, body: UserUpdateBody, request: Request):
    actor = current_user(request)
    return patch_account(
        user_id,
        actor=actor,
        keep_token=token_from_request(request),
        display_name=body.display_name,
        role=body.role,
        disabled=body.disabled,
        password=body.password,
        old_password=body.old_password,
    )


@app.delete("/api/users/{user_id}")
def api_delete_user(user_id: str, request: Request):
    remove_account(user_id, current_user(request))
    return {"ok": True}


@app.get("/api/config/llm")
def api_get_llm():
    return _mask_config(get_llm_config())


@app.get("/api/config/llm/defaults")
def api_llm_defaults():
    return llm_defaults_public()


@app.put("/api/config/llm")
def api_put_llm(body: LLMConfigUpdate):
    current = get_llm_config()
    data = body.model_dump()
    if not data.get("api_key"):
        data["api_key"] = current.get("api_key", "")
    if not data.get("prompts"):
        data["prompts"] = current.get("prompts") or {}
    saved = save_llm_config(data)
    return _mask_config(saved)


@app.post("/api/config/llm/test")
async def api_test_llm(body: LLMConfigUpdate | None = None):
    cfg = get_llm_config()
    if body:
        tmp = body.model_dump(exclude_none=True)
        if not tmp.get("api_key"):
            tmp.pop("api_key", None)
        cfg = {**cfg, **tmp}
    try:
        msg = await test_connection(cfg)
        return {"ok": True, "message": msg}
    except LLMError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(400, f"连接失败: {e}") from e


@app.post("/api/config/llm/gepa")
async def api_gepa_optimize(body: GepaOptimizeRequest):
    from .services.gepa_optimize import optimize_agent_prompt

    try:
        result = await asyncio.to_thread(
            optimize_agent_prompt,
            body.agent_id,
            max_metric_calls=body.max_metric_calls,
            apply=body.apply,
        )
        return {"ok": True, **result}
    except LLMError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(400, f"GEPA 优化失败: {e}") from e


@app.get("/api/jobs")
async def api_list_jobs(limit: int = 500):
    try:
        n = int(limit or 500)
    except (TypeError, ValueError):
        n = 500
    n = max(1, min(n, 5000))
    jobs = peek_jobs_cache(n)
    if jobs is None:
        jobs = await _run_api(list_jobs_cached, n)
    out = []
    for job in jobs:
        j = dict(job)
        prog = _runtime_progress(j.get("id") or "")
        if prog:
            j["progress"] = prog
        out.append(j)
    return out


@app.get("/api/jobs/events")
async def api_job_events(request: Request):
    async def gen():
        last = ""
        while True:
            if await request.is_disconnected():
                break
            payload = json.dumps(_live_event_payload(), ensure_ascii=False)
            if payload != last:
                yield f"event: jobs\ndata: {payload}\n\n"
                last = payload
            else:
                yield ": ping\n\n"
            await asyncio.sleep(0.8)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _attach_runtime_progress(job: dict, job_id: str) -> dict:
    prog = _runtime_progress(job_id)
    if prog:
        job["progress"] = prog
    if job_id in HUNT_LAB_PROGRESS:
        job["hunt_lab_progress"] = HUNT_LAB_PROGRESS[job_id]
    if job_id in RESEARCH_LAB_PROGRESS:
        job["research_lab_progress"] = RESEARCH_LAB_PROGRESS[job_id]
    return job


def _job_detail_sync(job_id: str, full: bool) -> dict:
    job = get_job(job_id, lite=False)
    if not job:
        raise HTTPException(404, "Job not found")
    _attach_runtime_progress(job, job_id)
    _attach_lab_history(job)
    art = ((job.get("result") or {}).get("artifacts") or {})
    if isinstance(art.get("bypass_pack"), dict):
        art["bypass_pack"] = sanitize_bypass_pack(art["bypass_pack"])
    if isinstance(art.get("residual_pack"), dict):
        art["residual_pack"] = sanitize_residual_pack(art["residual_pack"])
    if isinstance(art.get("alias_pack"), dict):
        art["alias_pack"] = sanitize_residual_pack(art["alias_pack"])
    if isinstance(art.get("feature_off_pack"), dict):
        art["feature_off_pack"] = sanitize_bypass_pack(art["feature_off_pack"])
    notes = art.get("agent_notes") if isinstance(art.get("agent_notes"), dict) else {}
    for nkey, pkey in (
        ("bypass", "bypass_pack"),
        ("residual", "residual_pack"),
        ("alias", "alias_pack"),
        ("feature_off", "feature_off_pack"),
    ):
        pack = art.get(pkey)
        raw = notes.get(nkey) or ""
        if isinstance(pack, dict) and raw:
            cleaned = notes_without_json(raw)
            if cleaned:
                pack["notes"] = cleaned
    is_audit = normalize_kind(job.get("kind")) == KIND_AUDIT or art.get("kind") == KIND_AUDIT
    if not is_audit and heal_artifacts_report(art):
        art["llm_report"] = ensure_func_logic_section(art["llm_report"], art.get("func_logic") or {})
        result = job.get("result") if isinstance(job.get("result"), dict) else {"artifacts": art}
        result["artifacts"] = art
        job["result"] = result
        try:
            update_job(job_id, result_json=json.dumps(result, ensure_ascii=False, default=str))
            (JOBS_DIR / job_id / "report.md").write_text(art["llm_report"], encoding="utf-8")
        except OSError:
            pass
    if not full:
        job = slim_job(job)
    return job


@app.get("/api/jobs/{job_id}")
async def api_get_job(job_id: str, lite: bool = False, full: bool = False):
    if lite:
        job = None
        cached = peek_jobs_cache(5000)
        if cached:
            for row in cached:
                if row.get("id") == job_id:
                    job = dict(row)
                    break
        if job is None:
            job = await _run_api(functools.partial(get_job, job_id, lite=True))
        if not job:
            raise HTTPException(404, "Job not found")
        job["result"] = None
        _attach_runtime_progress(job, job_id)
        if job_id in HUNT_LAB_PROGRESS:
            disk = await _run_api(load_current_hunt_lab, job_id, JOBS_DIR)
            if disk:
                job["result"] = {"artifacts": {"hunt_lab": disk}}
        return job
    return await _run_api(_job_detail_sync, job_id, full)


@app.get("/api/jobs/{job_id}/report.md")
def api_download_report(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    art = ((job.get("result") or {}).get("artifacts") or {})
    report = art.get("llm_report") or ""
    path = JOBS_DIR / job_id / "report.md"
    if not report and path.exists():
        report = path.read_text(encoding="utf-8")
    if not report:
        raise HTTPException(404, "Report not generated")
    if normalize_kind(job.get("kind")) == KIND_AUDIT or art.get("kind") == KIND_AUDIT:
        return Response(
            report,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{job_id}_audit.md"'},
        )
    pack = art.get("ioc_pack") or {}
    if not (pack.get("identity") or pack.get("functions")):
        pack = build_ioc_pack_from_artifacts(art, title=job.get("title") or "")
    text = ensure_ioc_section(report, pack)
    intel = threat_intel_for_artifacts(art, job.get("title") or "")
    text = ensure_threat_section(text, intel)
    bypass = art.get("bypass_pack") if isinstance(art.get("bypass_pack"), dict) else {}
    if not bypass.get("verdict"):
        bypass = build_bypass_pack((art.get("agent_notes") or {}).get("bypass") or "")
    bypass = sanitize_bypass_pack(bypass)
    residual = art.get("residual_pack") if isinstance(art.get("residual_pack"), dict) else {}
    if not residual.get("verdict"):
        residual = build_residual_pack((art.get("agent_notes") or {}).get("residual") or "")
    residual = sanitize_residual_pack(residual)
    text = ensure_bypass_section(text, bypass)
    text = ensure_residual_section(text, residual)
    text = complete_llm_report(text, art)
    return Response(
        text,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{job_id}_report.md"'},
    )


@app.get("/api/jobs/{job_id}/ioc.json")
def api_download_ioc(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    art = ((job.get("result") or {}).get("artifacts") or {})
    pack = art.get("ioc_pack") or {}
    if not (pack.get("identity") or pack.get("functions")):
        pack = build_ioc_pack_from_artifacts(art, title=job.get("title") or "")
    if not pack:
        path = JOBS_DIR / job_id / "ioc.json"
        if path.exists():
            return FileResponse(path, media_type="application/json", filename=f"{job_id}_ioc.json")
        raise HTTPException(404, "IOC pack not generated")
    return Response(
        json.dumps(pack, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{job_id}_ioc.json"'},
    )


@app.get("/api/jobs/{job_id}/threat.json")
def api_download_threat(job_id: str, refresh: bool = False):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    result = job.get("result") or {"artifacts": {}}
    art = result.get("artifacts") or {}
    stored = art.get("threat_intel") if isinstance(art.get("threat_intel"), dict) else {}
    title = job.get("title") or ""
    if refresh:
        pack = lookup_threat_intel(
            resolve_cve_from_artifacts(art, title),
            title=title,
            component=component_from_artifacts(art),
        )
        pack = attach_analyst_notes(pack, stored.get("threat_notes") or "")
    else:
        pack = threat_intel_for_artifacts(art, title)
    should_save = (
        job.get("status") == "completed"
        and pack.get("fetched_at")
        and (refresh or "search_hits" not in stored or not stored.get("fetched_at"))
    )
    if should_save:
        art["threat_intel"] = pack
        result["artifacts"] = art
        if art.get("llm_report"):
            art["llm_report"] = ensure_threat_section(art["llm_report"], pack)
        update_job(job_id, result_json=json.dumps(result, ensure_ascii=False))
        work = JOBS_DIR / job_id
        work.mkdir(parents=True, exist_ok=True)
        (work / "threat_intel.json").write_text(
            json.dumps(pack, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        if art.get("llm_report"):
            (work / "report.md").write_text(art["llm_report"], encoding="utf-8")
    return Response(
        json.dumps(pack, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{job_id}_threat.json"'},
    )


def _review_pack_response(job_id: str, art_key: str, filename: str, builder):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    art = ((job.get("result") or {}).get("artifacts") or {})
    pack = art.get(art_key) if isinstance(art.get(art_key), dict) else {}
    if not pack.get("verdict"):
        notes_key = "bypass" if art_key == "bypass_pack" else "residual"
        pack = builder((art.get("agent_notes") or {}).get(notes_key) or "")
    path = JOBS_DIR / job_id / filename
    if not pack.get("verdict") and path.exists():
        try:
            pack = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pack = pack or {}
    if art_key in {"bypass_pack", "feature_off_pack"}:
        pack = sanitize_bypass_pack(pack)
    elif art_key in {"residual_pack", "alias_pack"}:
        pack = sanitize_residual_pack(pack)
    return Response(
        json.dumps(pack, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{job_id}_{filename}"'},
    )


@app.get("/api/jobs/{job_id}/bypass.json")
def api_download_bypass(job_id: str):
    return _review_pack_response(job_id, "bypass_pack", "bypass_review.json", build_bypass_pack)


@app.get("/api/jobs/{job_id}/residual.json")
def api_download_residual(job_id: str):
    return _review_pack_response(job_id, "residual_pack", "residual_review.json", build_residual_pack)


@app.get("/api/jobs/{job_id}/hunt-lab.json")
def api_download_hunt_lab_json(job_id: str, run_id: str | None = Query(default=None)):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    pack = None
    if run_id:
        pack = load_hunt_run(job_id, JOBS_DIR, run_id)
    else:
        pack = ((job.get("result") or {}).get("artifacts") or {}).get("hunt_lab")
        if not pack:
            pack = load_current_hunt_lab(job_id, JOBS_DIR)
    if not pack:
        raise HTTPException(404, "尚未运行深度狩猎")
    name = f"{job_id}_hunt_lab_{run_id}.json" if run_id else f"{job_id}_hunt_lab.json"
    return Response(
        json.dumps(pack, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@app.get("/api/jobs/{job_id}/hunt-lab.md")
def api_download_hunt_lab_md(job_id: str, run_id: str | None = Query(default=None)):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    report = ""
    if run_id:
        pack = load_hunt_run(job_id, JOBS_DIR, run_id) or {}
        report = pack.get("report") or ""
        md_path = JOBS_DIR / job_id / "hunt_lab" / f"{run_id}.md"
        if not report and md_path.exists():
            report = md_path.read_text(encoding="utf-8")
    else:
        report = (((job.get("result") or {}).get("artifacts") or {}).get("hunt_lab") or {}).get("report") or ""
        path = JOBS_DIR / job_id / "hunt_lab.md"
        if not report and path.exists():
            report = path.read_text(encoding="utf-8")
    if not report:
        raise HTTPException(404, "尚无深度狩猎报告")
    name = f"{job_id}_hunt_lab_{run_id}.md" if run_id else f"{job_id}_hunt_lab.md"
    return Response(
        report,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@app.get("/api/jobs/{job_id}/cfg_diff.html")
def api_cfg_html(job_id: str):
    path = JOBS_DIR / job_id / "cfg_diff.html"
    if not path.exists():
        raise HTTPException(404, "CFG diff not generated")
    return FileResponse(path, media_type="text/html", filename=f"{job_id}_cfg_diff.html")


@app.get("/api/jobs/{job_id}/cfg_diff.json")
def api_cfg_json(job_id: str):
    path = JOBS_DIR / job_id / "cfg_diff.json"
    if not path.exists():
        raise HTTPException(404, "CFG diff JSON not generated")
    return FileResponse(path, media_type="application/json", filename=f"{job_id}_cfg_diff.json")


@app.get("/api/jobs/{job_id}/verify.zip")
def api_verify_zip(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    work = JOBS_DIR / job_id
    art = ((job.get("result") or {}).get("artifacts") or {})
    if art.get("old_pe") or art.get("disassembly") or art.get("feature_trace"):
        write_verify_pack(
            work,
            job.get("title") or "patch-job",
            old_pe=art.get("old_pe") if isinstance(art.get("old_pe"), dict) else {},
            new_pe=art.get("new_pe") if isinstance(art.get("new_pe"), dict) else {},
            feature_trace=art.get("feature_trace") if isinstance(art.get("feature_trace"), dict) else {},
            disassembly=art.get("disassembly") if isinstance(art.get("disassembly"), list) else [],
            hotspot_names=art.get("hotspot_names") if isinstance(art.get("hotspot_names"), list) else [],
        )
    folder = work / "verify"
    if not folder.is_dir():
        raise HTTPException(404, "Verify pack not generated")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in folder.iterdir():
            if p.is_file() and not p.name.lower().startswith("poc_"):
                zf.write(p, p.name)
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{job_id}_verify.zip"'},
    )


class CveJobBody(BaseModel):
    cve: str
    filename: str = ""
    title: str = ""
    run_llm: bool | None = True
    enabled_agents: list[str] | None = None
    routing_mode: str = "auto"


class WatchUpdate(BaseModel):
    enabled: bool | None = None
    auto_kernel: bool | None = None


def enqueue_cve_job(
    cve: str,
    *,
    filename: str = "",
    title: str = "",
    run_llm: bool | None = True,
    enabled_agents: list[str] | None = None,
    routing_mode: str = "auto",
) -> str:
    """Create a CVE-only job (no upload). Starts analysis on the running event loop."""
    cve = (cve or "").strip()
    if not cve:
        raise PatchResolveError("请填写 CVE 编号")
    job_id = uuid.uuid4().hex[:12]
    work = JOBS_DIR / job_id
    work.mkdir(parents=True, exist_ok=True)
    (work / "ingest.json").write_text(
        json.dumps({"cve": cve, "filename": (filename or "").strip()}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    selected = normalize_enabled_agents(
        ",".join(enabled_agents) if enabled_agents else "",
        explicit=enabled_agents is not None,
    )
    use_llm = llm_configured() if run_llm is None else bool(run_llm)
    if selected == []:
        use_llm = False
    create_job(
        job_id,
        (title or "").strip() or cve,
        "漏洞版",
        "修复版",
        "",
        "",
        enabled_agents=selected,
    )
    save_routing_mode(work, routing_mode or "auto")
    spawn_analysis_job(job_id, use_llm, cve)
    return job_id


@app.post("/api/jobs")
async def api_create_job(
    title: str = Form(""),
    cve: str = Form(""),
    filename: str = Form(""),
    old_label: str = Form("漏洞版"),
    new_label: str = Form("修复版"),
    mid_label: str = Form("更早版本"),
    run_llm: bool = Form(True),
    enabled_agents: str = Form(""),
    agents_set: str = Form(""),
    routing_mode: str = Form("auto"),
    old_file: UploadFile | None = File(None),
    new_file: UploadFile | None = File(None),
    mid_file: UploadFile | None = File(None),
):
    has_old = old_file is not None and bool(old_file.filename)
    has_new = new_file is not None and bool(new_file.filename)
    cve = (cve or "").strip()
    if not has_old and not has_new and not cve:
        raise HTTPException(400, "请填写 CVE 编号，或上传漏洞样本")
    if not has_old and not cve:
        raise HTTPException(400, "无样本时必须填写 CVE，将从补丁日/Winbindex 成对下载")

    job_id = uuid.uuid4().hex[:12]
    work = JOBS_DIR / job_id
    work.mkdir(parents=True, exist_ok=True)
    old_name = f"old_{old_file.filename}" if has_old else ""
    new_name = f"new_{new_file.filename}" if has_new else ""
    mid_name = None
    title = (title or "").strip() or cve or "未命名分析"
    try:
        if has_old:
            await asyncio.to_thread(_save_upload_sync, old_file, work / old_name)
        if has_new:
            await asyncio.to_thread(_save_upload_sync, new_file, work / new_name)
        if mid_file is not None and mid_file.filename:
            mid_name = f"mid_{mid_file.filename}"
            await asyncio.to_thread(_save_upload_sync, mid_file, work / mid_name)
    except HTTPException:
        shutil.rmtree(work, ignore_errors=True)
        raise

    if not has_old:
        (work / "ingest.json").write_text(
            json.dumps({"cve": cve, "filename": (filename or "").strip()}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    elif not has_new and not cve:
        shutil.rmtree(work, ignore_errors=True)
        raise HTTPException(400, "请填写 CVE 编号，或同时上传修复版驱动")

    selected = normalize_enabled_agents(
        enabled_agents,
        explicit=(agents_set or "").strip().lower() in ("1", "true", "yes"),
    )
    if selected == []:
        run_llm = False
    create_job(
        job_id,
        title,
        old_label,
        new_label,
        old_name,
        new_name,
        mid_label=mid_label if mid_name else None,
        mid_filename=mid_name,
        enabled_agents=selected,
    )
    save_routing_mode(work, routing_mode)
    spawn_analysis_job(job_id, run_llm, cve)
    return {"job_id": job_id, "status": "pending"}


@app.get("/api/jobs/{job_id}/audit.json")
def api_download_audit_json(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    pack = ((job.get("result") or {}).get("artifacts") or {}).get("kernel_audit")
    path = JOBS_DIR / job_id / "kernel_audit.json"
    if path.exists():
        return FileResponse(path, media_type="application/json", filename=f"{job_id}_audit.json")
    if not pack:
        raise HTTPException(404, "尚未完成内核审计")
    return Response(
        json.dumps(pack, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{job_id}_audit.json"'},
    )


@app.get("/api/jobs/{job_id}/audit.md")
def api_download_audit_md(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    report = (((job.get("result") or {}).get("artifacts") or {}).get("kernel_audit") or {}).get("report") or ""
    path = JOBS_DIR / job_id / "report.md"
    if path.exists() and not report:
        report = path.read_text(encoding="utf-8")
    if not report:
        raise HTTPException(404, "尚未生成审计报告")
    return Response(
        report,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{job_id}_audit.md"'},
    )


@app.post("/api/jobs/from-cve")
async def api_job_from_cve(body: CveJobBody):
    try:
        job_id = enqueue_cve_job(
            body.cve,
            filename=body.filename,
            title=body.title,
            run_llm=body.run_llm,
            enabled_agents=body.enabled_agents,
            routing_mode=body.routing_mode or "auto",
        )
    except PatchResolveError as e:
        raise HTTPException(400, str(e)) from e
    return {"job_id": job_id, "status": "pending"}


@app.get("/api/patch-tuesday")
async def api_patch_tuesday(bulletin: str = "", refresh: bool = False):
    try:
        if not (bulletin or "").strip():
            data = await _run_api(list_patch_days, refresh=refresh)
            return {"watch": get_watch_config(), **data}
        data = await _run_api(list_patch_tuesday, bulletin, refresh=refresh)
    except PatchResolveError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(502, f"读取 MSRC 失败: {e}") from e
    return {"watch": get_watch_config(), **data}


@app.post("/api/patch-tuesday")
def api_patch_tuesday_ingest(bulletin: str = ""):
    try:
        data = refresh_bulletin(bulletin)
        started = auto_ingest(data, force=True)
    except PatchResolveError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(502, f"排队失败: {e}") from e
    return {"started": started, "watch": get_watch_config(), "bulletin": data.get("bulletin")}


@app.get("/api/config/watch")
async def api_get_watch():
    return get_watch_config()


@app.put("/api/config/watch")
def api_put_watch(body: WatchUpdate):
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    return save_watch_config(patch)


@app.post("/api/patch-tuesday/auto")
def api_patch_tuesday_auto(bulletin: str = ""):
    return api_patch_tuesday_ingest(bulletin)


class ExtraHotspotsBody(BaseModel):
    names: list[str] = Field(default_factory=list)
    run_llm: bool = True


@app.post("/api/jobs/{job_id}/cancel")
def api_cancel_job(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.get("status") not in ("running", "pending"):
        raise HTTPException(400, "任务未在运行")
    request_cancel(job_id)
    JOB_PROGRESS[job_id] = {"message": "正在取消…", "percent": JOB_PROGRESS.get(job_id, {}).get("percent") or 0}
    return {"ok": True, "status": "cancelling"}


@app.post("/api/jobs/{job_id}/resume")
async def api_resume_job(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.get("status") not in ("failed", "cancelled"):
        art = ((job.get("result") or {}).get("artifacts") or {})
        pack = art.get("kernel_audit") or {}
        empty_report = not str(art.get("llm_report") or pack.get("report") or "").strip()
        incomplete = bool(pack.get("error") or art.get("llm_error")) or any(
            isinstance(a, dict) and a.get("error") for a in (pack.get("agents") or [])
        )
        if not (job.get("status") == "completed" and (incomplete or empty_report)):
            raise HTTPException(400, "仅失败、已取消，或报告为空/入口未跟完的已完成任务可从断点继续")
    update_job(job_id, status="pending", error=None)
    spawn_analysis_job(job_id, True, "", resume=True)
    return {"ok": True, "status": "pending"}


@app.post("/api/jobs/{job_id}/retry-pdb")
async def api_retry_pdb(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.get("status") in ("running", "pending"):
        raise HTTPException(400, "任务仍在运行")
    update_job(job_id, status="pending", error=None)
    spawn_analysis_job(
        job_id,
        True,
        "",
        resume=True,
        force_nodes=[
            "pdb_symbols",
            "feature",
            "byte_diff",
            "pick_hotspots",
            "timeline",
            "disasm",
            "cfg",
            "verify_pack",
            "join_tools",
            "route_agents",
            "pe_analyst",
            "symbol_analyst",
            "disasm_analyst",
            "feature_analyst",
            "control_analyst",
            "root_cause",
            "hunt_prep",
            "detection_analyst",
            "threat_intel",
            "bypass_analyst",
            "residual_analyst",
            "alias_site_analyst",
            "feature_off_analyst",
            "report_writer",
        ],
    )
    return {"ok": True, "status": "pending"}


def _rerun_hotspots(job_id: str, names: list[str], run_llm: bool) -> None:
    coro = _supervise_job(
        "hotspot",
        {"job_id": job_id, "names": names, "run_llm": run_llm},
    )
    try:
        loop = asyncio.get_running_loop()
        task = loop.create_task(coro)
        _JOB_TASKS.add(task)
        task.add_done_callback(_JOB_TASKS.discard)
    except RuntimeError:
        loop = _MAIN_LOOP
        if not loop or not loop.is_running():
            raise RuntimeError("分析服务尚未就绪")
        asyncio.run_coroutine_threadsafe(coro, loop)


@app.post("/api/jobs/{job_id}/hotspots")
async def api_extra_hotspots(job_id: str, body: ExtraHotspotsBody, background_tasks: BackgroundTasks):
    job = get_job(job_id)
    if not job or job.get("status") != "completed" or not job.get("result"):
        raise HTTPException(400, "任务尚未完成，无法加选热点")
    names = [n.strip() for n in (body.names or []) if str(n).strip()]
    if not names:
        raise HTTPException(400, "请提供至少一个函数名")
    update_job(job_id, status="running")
    _rerun_hotspots(job_id, names, body.run_llm)
    return {"ok": True, "status": "running"}


@app.post("/api/jobs/{job_id}/report")
async def api_regenerate_report(job_id: str):
    job = get_job(job_id)
    if not job or job["status"] != "completed" or not job.get("result"):
        raise HTTPException(400, "Job not ready for LLM report")
    artifacts = job["result"].get("artifacts")
    if not artifacts:
        raise HTTPException(400, "No analysis artifacts")
    selected = artifacts.get("enabled_agents")
    if selected is None:
        selected = job.get("enabled_agents")
    if isinstance(selected, list) and "ReportWriter" not in selected:
        selected = [*selected, "ReportWriter"]
    result = await _supervise_job("llm", {"job_id": job_id, "selected": selected})
    if not result.get("ok"):
        raise HTTPException(400, result.get("error") or "生成报告失败")
    return {"ok": True, "report_preview": result.get("report_preview") or ""}


class HuntLabBody(BaseModel):
    tracks: list[str] = Field(default_factory=lambda: ["bypass", "similar"])


def _persist_hunt_lab(job_id: str, hunt_lab: dict) -> None:
    job = get_job(job_id)
    if not job:
        return
    result = job.get("result") or {}
    art = result.get("artifacts") or {}
    packed = stamp_hunt_pack(hunt_lab, existing=art.get("hunt_lab") if isinstance(art.get("hunt_lab"), dict) else None)
    art["hunt_lab"] = packed
    if packed.get("surface"):
        art["surface_map"] = packed["surface"]
    if packed.get("scores") is not None:
        art["handler_scores"] = packed["scores"]
    result["artifacts"] = art
    update_job(job_id, result_json=json.dumps(result, ensure_ascii=False))
    work = JOBS_DIR / job_id
    work.mkdir(parents=True, exist_ok=True)
    (work / "hunt_lab.json").write_text(json.dumps(packed, ensure_ascii=False, indent=2), encoding="utf-8")
    if packed.get("report"):
        (work / "hunt_lab.md").write_text(str(packed.get("report") or ""), encoding="utf-8")
    if packed.get("status") in {"completed", "failed", "cancelled", "interrupted"}:
        archive_hunt_run(job_id, JOBS_DIR, packed)


def _attach_lab_history(job: dict) -> None:
    job_id = str(job.get("id") or "")
    if not job_id:
        return
    result = job.get("result") or {}
    art = result.get("artifacts") or {}
    if not art.get("hunt_lab"):
        disk = load_current_hunt_lab(job_id, JOBS_DIR)
        if disk:
            art["hunt_lab"] = disk
            result["artifacts"] = art
            job["result"] = result
    job["hunt_lab_history"] = ensure_hunt_index(job_id, JOBS_DIR, art.get("hunt_lab") if isinstance(art.get("hunt_lab"), dict) else None)


def fail_stale_hunt_labs() -> None:
    """Keep interrupted hunt results instead of leaving status=running after a restart."""
    if not JOBS_DIR.exists():
        return
    for path in JOBS_DIR.glob("*/hunt_lab.json"):
        job_id = path.parent.name
        if job_id in HUNT_LAB_PROGRESS:
            continue
        job = get_job(job_id)
        pack = ((job.get("result") or {}).get("artifacts") or {}).get("hunt_lab") if job else None
        if not isinstance(pack, dict):
            pack = load_current_hunt_lab(job_id, JOBS_DIR)
        if not isinstance(pack, dict) or pack.get("status") != "running":
            continue
        pack = stamp_hunt_pack({
            **pack,
            "status": "interrupted",
            "error": pack.get("error") or "服务重启，深度狩猎中断。已保留此前写出的结果。",
        })
        _persist_hunt_lab(job_id, pack)


def _run_hunt_lab_job(job_id: str, tracks: list[str]) -> None:
    job = get_job(job_id)
    if not job:
        return
    artifacts = (job.get("result") or {}).get("artifacts") or {}
    work, old_sys, new_sys, old_pdb, new_pdb = _job_sys_paths(job, artifacts)
    clear_cancel(job_id)

    def cb(msg: str, pct: int):
        HUNT_LAB_PROGRESS[job_id] = {"message": msg, "percent": pct}

    def on_update(pack: dict):
        _persist_hunt_lab(job_id, pack)

    starter = {
        "status": "running",
        "isolated": True,
        "tracks": tracks,
        "bypass": None,
        "similar": None,
        "report": "",
        "error": None,
    }
    _persist_hunt_lab(job_id, starter)
    cb("深度狩猎排队：表面图 → 打分 → 绕过/变体", 2)
    try:
        if not new_sys.exists():
            raise FileNotFoundError(f"找不到修复版样本: {new_sys}")
        hunt_lab = run_hunt_lab(
            artifacts,
            job.get("title") or "",
            old_sys=old_sys if old_sys.exists() else new_sys,
            new_sys=new_sys,
            work=work,
            tracks=tracks,
            job_id=job_id,
            new_pdb=new_pdb,
            old_pdb=old_pdb,
            progress_cb=cb,
            on_update=on_update,
        )
        _persist_hunt_lab(job_id, hunt_lab)
    except LLMError as e:
        _persist_hunt_lab(job_id, {**starter, "status": "failed", "error": str(e)})
    except Exception as e:
        _persist_hunt_lab(job_id, {**starter, "status": "failed", "error": str(e)})
    finally:
        HUNT_LAB_PROGRESS.pop(job_id, None)


@app.post("/api/jobs/{job_id}/hunt-lab")
async def api_start_hunt_lab(job_id: str, body: HuntLabBody, background_tasks: BackgroundTasks):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.get("status") != "completed" or not job.get("result"):
        raise HTTPException(400, "请先完成主分析流水线，再启动深度狩猎")
    if normalize_kind(job.get("kind")) == KIND_AUDIT:
        raise HTTPException(400, "内核审计任务没有补丁对照，请看审计结果页的缺陷类与观察清单")
    existing = ((job.get("result") or {}).get("artifacts") or {}).get("hunt_lab") or {}
    if existing.get("status") == "running" or job_id in HUNT_LAB_PROGRESS:
        raise HTTPException(400, "深度狩猎已在运行")
    if existing and existing.get("status") != "running":
        archive_hunt_run(job_id, JOBS_DIR, existing)
    tracks = [t for t in (body.tracks or []) if t in {"bypass", "similar"}] or ["bypass", "similar"]
    starter = stamp_hunt_pack({
        "status": "running",
        "isolated": True,
        "tracks": tracks,
        "bypass": None,
        "similar": None,
        "report": "",
        "error": None,
    })
    _persist_hunt_lab(job_id, starter)
    HUNT_LAB_PROGRESS[job_id] = {"message": "深度狩猎排队中…", "percent": 1}
    background_tasks.add_task(_run_hunt_lab_job, job_id, tracks)
    return {"ok": True, "status": "running", "tracks": tracks, "isolated": True}


@app.post("/api/jobs/{job_id}/hunt-lab/cancel")
def api_cancel_hunt_lab(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    existing = ((job.get("result") or {}).get("artifacts") or {}).get("hunt_lab") or {}
    if existing.get("status") != "running" and job_id not in HUNT_LAB_PROGRESS:
        raise HTTPException(400, "深度狩猎未在运行")
    request_cancel(job_id)
    HUNT_LAB_PROGRESS[job_id] = {"message": "正在取消深度狩猎…", "percent": (HUNT_LAB_PROGRESS.get(job_id) or {}).get("percent") or 0}
    return {"ok": True, "status": "cancelling"}


class ResearchLabBody(BaseModel):
    run_llm: bool = True


def _job_sys_paths(job: dict, artifacts: dict) -> tuple[Path, Path, Path, Path, Path]:
    work = JOBS_DIR / str(job["id"])
    old_name = job.get("old_filename") or ""
    new_name = job.get("new_filename") or ""
    old_sys = work / old_name if old_name else Path(str((artifacts.get("old_pe") or {}).get("path") or ""))
    new_sys = work / new_name if new_name else Path(str((artifacts.get("new_pe") or {}).get("path") or ""))
    pdb = work / "pdb"
    old_pdb = pdb / "old.pdb"
    new_pdb = pdb / "new.pdb"
    if not new_sys.exists():
        for cand in sorted(work.glob("new_*.sys")) + sorted(work.glob("*patched*.sys")):
            new_sys = cand
            break
    if not old_sys.exists():
        for cand in sorted(work.glob("old_*.sys")):
            old_sys = cand
            break
    return work, old_sys, new_sys, old_pdb, new_pdb


def _persist_research_lab(job_id: str, pack: dict) -> None:
    job = get_job(job_id)
    if not job:
        return
    result = job.get("result") or {}
    art = result.get("artifacts") or {}
    slim = {k: pack.get(k) for k in (
        "status", "isolated", "flow", "surface", "scores", "observations",
        "variant", "report", "error", "llm",
    )}
    art["research_lab"] = slim
    if pack.get("surface"):
        art["surface_map"] = pack["surface"]
    if pack.get("scores") is not None:
        art["handler_scores"] = pack["scores"]
    result["artifacts"] = art
    update_job(job_id, result_json=json.dumps(result, ensure_ascii=False))
    work = JOBS_DIR / job_id
    work.mkdir(parents=True, exist_ok=True)
    (work / "research_lab.json").write_text(json.dumps(slim, ensure_ascii=False, indent=2), encoding="utf-8")
    if pack.get("report"):
        (work / "research_lab.md").write_text(str(pack.get("report") or ""), encoding="utf-8")


def _run_research_lab_job(job_id: str, run_llm: bool) -> None:
    job = get_job(job_id)
    if not job:
        return
    artifacts = (job.get("result") or {}).get("artifacts") or {}
    work, old_sys, new_sys, old_pdb, new_pdb = _job_sys_paths(job, artifacts)
    clear_cancel(job_id)

    def cb(msg: str, pct: int):
        RESEARCH_LAB_PROGRESS[job_id] = {"message": msg, "percent": pct}

    def on_update(pack: dict):
        _persist_research_lab(job_id, pack)

    starter = {
        "status": "running",
        "isolated": True,
        "flow": ["surface", "score", "variant", "observe"],
        "surface": None,
        "scores": [],
        "observations": [],
        "variant": None,
        "report": "",
        "error": None,
        "llm": run_llm,
    }
    _persist_research_lab(job_id, starter)
    cb("研究流程排队中…", 2)
    try:
        if not new_sys.exists():
            raise FileNotFoundError(f"找不到修复版样本: {new_sys}")
        pack = run_research_lab(
            artifacts,
            job.get("title") or "",
            new_sys=new_sys,
            old_sys=old_sys if old_sys.exists() else new_sys,
            work=work,
            new_pdb=new_pdb,
            old_pdb=old_pdb,
            job_id=job_id,
            run_llm=run_llm,
            progress_cb=cb,
            on_update=on_update,
        )
        _persist_research_lab(job_id, pack)
    except LLMError as e:
        _persist_research_lab(job_id, {**starter, "status": "failed", "error": str(e)})
    except Exception as e:
        _persist_research_lab(job_id, {**starter, "status": "failed", "error": str(e)})
    finally:
        RESEARCH_LAB_PROGRESS.pop(job_id, None)


@app.get("/api/jobs/{job_id}/research.json")
def api_download_research_json(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    pack = ((job.get("result") or {}).get("artifacts") or {}).get("research_lab")
    path = JOBS_DIR / job_id / "research_lab.json"
    if path.exists():
        return FileResponse(path, media_type="application/json", filename=f"{job_id}_research.json")
    if not pack:
        raise HTTPException(404, "尚未运行研究流程")
    return Response(
        json.dumps(pack, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{job_id}_research.json"'},
    )


@app.get("/api/jobs/{job_id}/research.md")
def api_download_research_md(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    report = (((job.get("result") or {}).get("artifacts") or {}).get("research_lab") or {}).get("report") or ""
    path = JOBS_DIR / job_id / "research_lab.md"
    if path.exists():
        return FileResponse(path, media_type="text/markdown; charset=utf-8", filename=f"{job_id}_research.md")
    if not report:
        raise HTTPException(404, "尚未生成研究报告")
    return Response(
        report,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{job_id}_research.md"'},
    )


@app.post("/api/jobs/{job_id}/research")
async def api_start_research_lab(job_id: str, body: ResearchLabBody, background_tasks: BackgroundTasks):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if normalize_kind(job.get("kind")) == KIND_AUDIT:
        raise HTTPException(400, "内核审计任务请重新运行审计，不必再开研究流程")
    if job.get("status") != "completed" or not job.get("result"):
        raise HTTPException(400, "请先完成主分析流水线，再启动研究流程")
    existing = ((job.get("result") or {}).get("artifacts") or {}).get("research_lab") or {}
    if existing.get("status") == "running" or job_id in RESEARCH_LAB_PROGRESS:
        raise HTTPException(400, "研究流程已在运行")
    starter = {
        "status": "running",
        "isolated": True,
        "flow": ["surface", "score", "variant", "observe"],
        "surface": None,
        "scores": [],
        "observations": [],
        "variant": None,
        "report": "",
        "error": None,
        "llm": body.run_llm,
    }
    _persist_research_lab(job_id, starter)
    RESEARCH_LAB_PROGRESS[job_id] = {"message": "研究流程排队中…", "percent": 1}
    background_tasks.add_task(_run_research_lab_job, job_id, body.run_llm)
    return {"ok": True, "status": "running", "isolated": True}


@app.post("/api/jobs/{job_id}/research/cancel")
def api_cancel_research_lab(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    existing = ((job.get("result") or {}).get("artifacts") or {}).get("research_lab") or {}
    if existing.get("status") != "running" and job_id not in RESEARCH_LAB_PROGRESS:
        raise HTTPException(400, "研究流程未在运行")
    request_cancel(job_id)
    RESEARCH_LAB_PROGRESS[job_id] = {
        "message": "正在取消研究流程…",
        "percent": (RESEARCH_LAB_PROGRESS.get(job_id) or {}).get("percent") or 0,
    }
    return {"ok": True, "status": "cancelling"}


STATIC_DIR = WEBAPP_ROOT / "ui" / "dist"
LEGACY_DIR = WEBAPP_ROOT / "frontend"


@app.get("/")
async def spa_index():
    for folder in (STATIC_DIR, LEGACY_DIR):
        index = folder / "index.html"
        if index.exists():
            return FileResponse(index)
    raise HTTPException(503, "Frontend missing: build Vue UI with npm run build in webapp/ui")


@app.api_route("/{full_path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
async def spa_or_static(full_path: str, request: Request):
    """Serve static frontend assets. Do not steal /api/* (that caused POST 405)."""
    if full_path.startswith("api/") or full_path == "api":
        raise HTTPException(404, "API endpoint not found")
    if request.method not in ("GET", "HEAD"):
        raise HTTPException(405, "Method Not Allowed")
    for folder in (STATIC_DIR, LEGACY_DIR):
        if not folder.exists():
            continue
        candidate = folder / full_path
        if candidate.is_file():
            return FileResponse(candidate)
        index = folder / "index.html"
        if index.exists() and (STATIC_DIR / "index.html").exists() and folder == STATIC_DIR:
            return FileResponse(index)
        if index.exists() and folder == LEGACY_DIR and not (STATIC_DIR / "index.html").exists():
            return FileResponse(index)
    raise HTTPException(404, "Not found")
