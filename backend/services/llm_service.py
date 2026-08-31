"""Configurable LLM client (OpenAI-compatible API)."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from ..database import get_llm_config


class LLMError(Exception):
    pass


def _with_scheme(url: str) -> str:
    return url if "://" in url else f"http://{url}"


def normalize_base_url(url: str | None) -> str:
    url = _with_scheme((url or "https://api.openai.com/v1").strip()).rstrip("/")
    path = urlparse(url).path
    if path in ("", "/"):
        url = f"{url}/v1"
    return url


def is_local_endpoint(base_url: str | None) -> bool:
    raw = (base_url or "").strip()
    if not raw:
        return False
    host = (urlparse(_with_scheme(raw)).hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "0.0.0.0", "::1"} or host.endswith(".local")


def llm_configured(cfg: dict[str, Any] | None = None) -> bool:
    cfg = cfg or get_llm_config()
    if (cfg.get("api_key") or "").strip():
        return True
    # Local OpenAI-compatible servers (Ollama / LM Studio / vLLM) often need no key
    return is_local_endpoint(cfg.get("base_url"))


async def generate_report(artifacts: dict[str, Any], title: str, config: dict[str, Any] | None = None) -> str:
    """Compatibility wrapper: run LangGraph LLM specialist phase."""
    from ..agents.graph import invoke_llm_phase

    merged = invoke_llm_phase(artifacts, title)
    err = merged.get("llm_error")
    if err and not merged.get("llm_report"):
        raise LLMError(str(err))
    return merged.get("llm_report") or ""


def _preview_choice(data: dict[str, Any]) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        err = data.get("error")
        if err:
            raise LLMError(str(err)[:400])
        raise LLMError(f"响应不是 chat completions 格式: {str(data)[:240]}")
    msg = (choices[0] or {}).get("message") or {}
    content = msg.get("content")
    if isinstance(content, list):
        return "".join(
            str(part.get("text") if isinstance(part, dict) else part) for part in content
        ).strip()
    return str(content or "").strip()


async def test_connection(config: dict[str, Any] | None = None) -> str:
    cfg = config or get_llm_config()
    if not llm_configured(cfg):
        raise LLMError("API key 为空")
    api_key = (cfg.get("api_key") or "").strip() or "sk-local"
    base_url = normalize_base_url(cfg.get("base_url"))
    model = (cfg.get("model") or "gpt-4o-mini").strip()
    payload = {
        "model": model,
        "max_tokens": 16,
        "temperature": 0,
        "messages": [{"role": "user", "content": "Reply with OK only."}],
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    timeout = httpx.Timeout(connect=15.0, read=45.0, write=15.0, pool=10.0)
    url = f"{base_url}/chat/completions"
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.post(url, headers=headers, json=payload)
    except httpx.ConnectError as e:
        raise LLMError(f"无法连接 {base_url}：{e}") from e
    except httpx.TimeoutException as e:
        raise LLMError(
            f"连接超时（{base_url}）。请检查网络 / Base URL，或改用非推理模型再测。"
        ) from e
    except httpx.HTTPError as e:
        raise LLMError(f"HTTP 客户端错误：{e}") from e

    body = (resp.text or "")[:400]
    if resp.status_code >= 400:
        raise LLMError(f"HTTP {resp.status_code}: {body}")

    try:
        data = resp.json()
    except ValueError as e:
        raise LLMError(f"HTTP {resp.status_code} 非 JSON 响应: {body}") from e
    if not isinstance(data, dict):
        raise LLMError(f"响应格式异常: {body}")

    preview = _preview_choice(data)
    used = data.get("model") or model
    if preview:
        return f"连接成功（{used}）：{preview[:80]}"
    return f"连接成功（{used}）"
