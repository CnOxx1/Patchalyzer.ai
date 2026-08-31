"""Login sessions, password hashing, and request user helpers."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from .config import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USER, SESSION_COOKIE, SESSION_DAYS
from .database import (
    count_admins,
    count_users,
    create_session,
    delete_session,
    delete_user,
    delete_user_sessions,
    get_session_user,
    get_user,
    get_user_by_username,
    insert_user,
    list_users,
    public_user,
    update_user,
)

PBKDF2_ROUNDS = 200_000
USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,31}$")
LOGIN_FAIL_LIMIT = 8
LOGIN_LOCK_SEC = 15 * 60

_login_fails: dict[str, tuple[int, float]] = {}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _algo, rounds, salt_hex, hash_hex = (stored or "").split("$", 3)
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(rounds),
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ensure_default_admin() -> None:
    if count_users() > 0:
        return
    insert_user(
        uuid.uuid4().hex[:12],
        DEFAULT_ADMIN_USER.strip().lower() or "admin",
        hash_password(DEFAULT_ADMIN_PASSWORD),
        display_name="管理员",
        role="admin",
    )


def validate_username(username: str) -> str:
    name = (username or "").strip()
    if not USERNAME_RE.match(name):
        raise HTTPException(400, "用户名为 3–32 位，需以字母开头，只能含字母、数字和下划线")
    return name.lower()


def validate_password(password: str) -> str:
    pw = password or ""
    if len(pw) < 8:
        raise HTTPException(400, "密码至少 8 位")
    if len(pw) > 128:
        raise HTTPException(400, "密码过长")
    return pw


def validate_role(role: str) -> str:
    r = (role or "user").strip().lower()
    if r not in ("admin", "user"):
        raise HTTPException(400, "角色只能是 admin 或 user")
    return r


def _client_ip(request: Request) -> str:
    return (request.client.host if request.client else "") or "local"


def _login_locked(ip: str) -> bool:
    rec = _login_fails.get(ip)
    if not rec:
        return False
    n, until = rec
    if until and time.time() < until:
        return True
    if until and time.time() >= until:
        _login_fails.pop(ip, None)
    return False


def _note_login_fail(ip: str) -> None:
    n, until = _login_fails.get(ip, (0, 0.0))
    n += 1
    lock_until = time.time() + LOGIN_LOCK_SEC if n >= LOGIN_FAIL_LIMIT else until
    _login_fails[ip] = (n, lock_until)


def _clear_login_fail(ip: str) -> None:
    _login_fails.pop(ip, None)


def token_from_request(request: Request) -> str:
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header.split(" ", 1)[1].strip()
    return (request.cookies.get(SESSION_COOKIE) or "").strip()


def resolve_user(request: Request) -> dict[str, Any] | None:
    token = token_from_request(request)
    if not token:
        return None
    user = get_session_user(hash_token(token))
    if not user or user.get("disabled"):
        return None
    return user


def current_user(request: Request) -> dict[str, Any]:
    user = getattr(request.state, "user", None) or resolve_user(request)
    if not user:
        raise HTTPException(401, "未登录")
    request.state.user = user
    return user


def require_admin(request: Request) -> dict[str, Any]:
    user = current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "需要管理员权限")
    return user


def login(username: str, password: str, request: Request) -> tuple[dict[str, Any], str]:
    ip = _client_ip(request)
    if _login_locked(ip):
        raise HTTPException(429, "登录失败次数过多，请稍后再试")
    user = get_user_by_username((username or "").strip())
    if not user or not verify_password(password or "", user.get("password_hash") or ""):
        _note_login_fail(ip)
        raise HTTPException(401, "用户名或密码错误")
    if user.get("disabled"):
        raise HTTPException(403, "账号已停用")
    _clear_login_fail(ip)
    raw = secrets.token_urlsafe(32)
    expires = _utcnow() + timedelta(days=max(1, SESSION_DAYS))
    create_session(hash_token(raw), user["id"], expires.isoformat())
    return public_user(user) or {}, raw


def logout(request: Request) -> None:
    token = token_from_request(request)
    if token:
        delete_session(hash_token(token))


def create_account(
    *,
    username: str,
    password: str,
    display_name: str = "",
    role: str = "user",
) -> dict[str, Any]:
    name = validate_username(username)
    pw = validate_password(password)
    role = validate_role(role)
    if get_user_by_username(name):
        raise HTTPException(400, "用户名已存在")
    return insert_user(
        uuid.uuid4().hex[:12],
        name,
        hash_password(pw),
        display_name=(display_name or name).strip(),
        role=role,
    )


def patch_account(
    user_id: str,
    *,
    actor: dict[str, Any],
    keep_token: str = "",
    display_name: str | None = None,
    role: str | None = None,
    disabled: bool | None = None,
    password: str | None = None,
    old_password: str | None = None,
) -> dict[str, Any]:
    target = get_user(user_id)
    if not target:
        raise HTTPException(404, "用户不存在")
    is_admin = actor.get("role") == "admin"
    is_self = actor.get("id") == user_id
    if not is_admin and not is_self:
        raise HTTPException(403, "只能修改自己的账号")
    fields: dict[str, Any] = {}
    if display_name is not None:
        fields["display_name"] = display_name.strip() or target["username"]
    if role is not None:
        if not is_admin:
            raise HTTPException(403, "不能修改角色")
        role = validate_role(role)
        if target.get("role") == "admin" and role != "admin" and count_admins(exclude_id=user_id) < 1:
            raise HTTPException(400, "不能取消最后一个管理员")
        fields["role"] = role
    if disabled is not None:
        if not is_admin:
            raise HTTPException(403, "不能停用账号")
        if disabled and is_self:
            raise HTTPException(400, "不能停用自己的账号")
        if disabled and target.get("role") == "admin" and count_admins(exclude_id=user_id) < 1:
            raise HTTPException(400, "不能停用最后一个管理员")
        fields["disabled"] = bool(disabled)
        if disabled:
            delete_user_sessions(user_id)
    if password is not None and password != "":
        pw = validate_password(password)
        if not is_admin or is_self:
            if not old_password:
                raise HTTPException(400, "请填写当前密码")
            if not verify_password(old_password, target.get("password_hash") or ""):
                raise HTTPException(400, "当前密码不正确")
        fields["password_hash"] = hash_password(pw)
        keep_hash = hash_token(keep_token) if (is_self and keep_token) else ""
        delete_user_sessions(user_id, keep_hash=keep_hash)
    updated = update_user(user_id, **fields)
    if not updated:
        raise HTTPException(404, "用户不存在")
    return updated


def remove_account(user_id: str, actor: dict[str, Any]) -> None:
    if actor.get("role") != "admin":
        raise HTTPException(403, "需要管理员权限")
    target = get_user(user_id)
    if not target:
        raise HTTPException(404, "用户不存在")
    if target["id"] == actor["id"]:
        raise HTTPException(400, "不能删除自己的账号")
    if target.get("role") == "admin" and count_admins(exclude_id=user_id) < 1:
        raise HTTPException(400, "不能删除最后一个管理员")
    delete_user(user_id)


def users_for_admin() -> list[dict[str, Any]]:
    return list_users()


def auth_error_response(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


PUBLIC_API_EXACT = {
    ("GET", "/api/health"),
    ("POST", "/api/auth/login"),
    ("GET", "/api/auth/me"),
}


def is_public_api(method: str, path: str) -> bool:
    if (method.upper(), path) in PUBLIC_API_EXACT:
        return True
    if method.upper() == "GET" and path.startswith("/api/public/"):
        return True
    return False
