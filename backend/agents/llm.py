"""Build ChatOpenAI from saved Patchalyzer LLM config."""
from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from ..config import DEFAULT_AGENT_PROMPTS, DEFAULT_REPORT_STRUCTURE
from ..database import get_llm_config
from ..services.llm_service import LLMError, llm_configured, normalize_base_url


def make_chat(cfg: dict[str, Any] | None = None, *, max_tokens: int | None = None, temperature: float | None = None) -> ChatOpenAI:
    cfg = cfg or get_llm_config()
    if not llm_configured(cfg):
        raise LLMError("LLM API key 未配置，请在设置页填写")
    base_url = normalize_base_url(cfg.get("base_url"))
    api_key = (cfg.get("api_key") or "").strip() or "sk-local"
    tok = max_tokens if max_tokens is not None else int(cfg.get("max_tokens", 16384))
    temp = temperature if temperature is not None else float(cfg.get("temperature", 0.15))
    return ChatOpenAI(
        model=cfg.get("model") or "gpt-4o-mini",
        api_key=api_key,
        base_url=base_url,
        temperature=temp,
        max_tokens=tok,
        timeout=300,
    )


def agent_system_prompt(name: str, cfg: dict[str, Any] | None = None) -> str:
    cfg = cfg or get_llm_config()
    custom = ((cfg.get("prompts") or {}).get(name) or "").strip()
    return custom or DEFAULT_AGENT_PROMPTS.get(name, "")


def report_structure_prompt(cfg: dict[str, Any] | None = None) -> str:
    cfg = cfg or get_llm_config()
    text = (cfg.get("report_structure") or "").strip()
    return text or DEFAULT_REPORT_STRUCTURE


def compose_system(
    name: str,
    system: str,
    cfg: dict[str, Any] | None = None,
    extra_parts: list[str] | None = None,
) -> str:
    cfg = cfg or get_llm_config()
    system = (system or "").strip() or agent_system_prompt(name, cfg)
    extra = (cfg.get("system_prompt") or "").strip()
    focus = (cfg.get("extra_focus") or "").strip()
    language = (cfg.get("language") or "zh").strip().lower()
    parts = [system]
    if extra:
        parts.append(f"全局约束：{extra}")
    if focus:
        parts.append(f"额外关注：{focus}")
    if language.startswith("en"):
        parts.append("Write the entire response in English.")
    else:
        parts.append("全程使用中文回答。")
    if name == "ReportWriter":
        parts.append(
            "禁止输出提纲式短报告；必须按模板写满各节细节与表格。"
            "第一个一级标题必须是 ## 1. 执行摘要。必须写满 §1–§15，禁止只输出 §16 及之后。"
        )
    if extra_parts:
        parts.extend(p for p in extra_parts if p)
    return "\n\n".join(parts)


def run_agent(
    name: str,
    system: str,
    user: str,
    cfg: dict[str, Any] | None = None,
    *,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> str:
    cfg = cfg or get_llm_config()
    # ReportWriter needs more room and lower temperature for longer, stabler prose.
    if name == "ReportWriter":
        if max_tokens is None:
            max_tokens = max(int(cfg.get("max_tokens") or 0), 16384)
        if temperature is None:
            temperature = min(float(cfg.get("temperature", 0.15)), 0.15)
    llm = make_chat(cfg, max_tokens=max_tokens, temperature=temperature)
    resp = llm.invoke([SystemMessage(content=compose_system(name, system, cfg)), HumanMessage(content=user)])
    content = resp.content
    if isinstance(content, list):
        return "".join(str(x) for x in content)
    return str(content or "").strip()
