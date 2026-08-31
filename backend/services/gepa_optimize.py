"""Offline GEPA prompt evolution for specialist agents.

GEPA is NOT part of the live analysis graph. It replays a few completed jobs,
scores outputs with a rubric, and writes a better system prompt back to settings.
"""
from __future__ import annotations

import json
import re
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from ..config import DEFAULT_AGENT_PROMPTS
from ..database import get_job, get_llm_config, list_jobs, save_llm_config
from ..services.llm_service import LLMError, llm_configured
from ..agents.llm import agent_system_prompt, make_chat, run_agent

SAFETY_TAIL = {
    "BypassAnalyst": "禁止 exploit / PoC / payload / 逐步绕过步骤。禁止编造未出现在输入里的 RVA、函数名、Feature ID。",
    "ResidualVulnAnalyst": "禁止 exploit / PoC / 逐步利用。没有嫌疑必须写未发现。禁止编造未提供的 RVA 与函数名。",
    "AliasSiteAnalyst": "禁止 exploit / PoC。没有未改调用点证据必须写未发现。禁止编造未提供的函数名。",
    "FeatureOffAnalyst": "禁止 exploit / PoC / 逐步绕过。无 Feature 证据则 unknown。禁止编造 Feature ID。",
    "DetectionAnalyst": "不要给 PoC 源码，不要逐步 exploit，不要编造未提供的哈希、RVA、Feature ID。",
    "ThreatIntelAnalyst": "组织名必须出现在搜索结果里才可写。不要写 exploit 步骤。",
    "ReportWriter": "禁止编造 SHA256/MD5，禁止写检索结果中未出现的组织名称，禁止写完整 exploit。",
    "RootCauseAnalyst": "区分【已证实】与【推断】；禁止编造 RVA 与指令。",
    "DisasmAnalyst": "只引用给定 RVA 与指令，禁止编造。",
}

_EXPLOIT_NOISE = re.compile(
    r"(PoC\s*如下|完整exploit|shellcode|payload\s*=|逐步绕过步骤)",
    re.I,
)


def _snip(obj: Any, limit: int = 3500) -> str:
    text = json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    if len(text) > limit:
        return text[:limit] + "\n...[truncated]..."
    return text


def _build_eval_user(agent_id: str, art: dict[str, Any], title: str) -> str:
    notes = art.get("agent_notes") or {}
    pe_old = art.get("old_pe") or {}
    pe_new = art.get("new_pe") or {}
    brief_pe = {
        "old": {k: pe_old.get(k) for k in ("original_filename", "file_version", "machine", "size", "sha256")},
        "new": {k: pe_new.get(k) for k in ("original_filename", "file_version", "machine", "size", "sha256")},
    }
    if agent_id == "PEAnalyst":
        return f"任务: {title}\nPE:\n{_snip(brief_pe)}"
    if agent_id == "SymbolAnalyst":
        return f"任务: {title}\n符号差:\n{_snip(art.get('symbol_diff') or {}, 5000)}"
    if agent_id == "DisasmAnalyst":
        return f"任务: {title}\n热点反汇编摘要:\n{_snip((art.get('disassembly') or [])[:4], 6000)}"
    if agent_id == "FeatureAnalyst":
        return f"任务: {title}\nFeature:\n{_snip(art.get('feature_trace') or {}, 5000)}"
    if agent_id == "ControlPathAnalyst":
        return f"任务: {title}\n对照函数: {_snip(art.get('control_names') or [], 2000)}"
    if agent_id == "RootCauseAnalyst":
        return (
            f"任务: {title}\nPE笔记:\n{notes.get('pe') or '（无）'}\n\n"
            f"符号:\n{(notes.get('symbol') or '')[:1500]}\n\n"
            f"反汇编:\n{(notes.get('disasm') or '')[:2000]}\n\n"
            f"Feature:\n{(notes.get('feature') or '')[:1200]}\n\n对照:\n{(notes.get('control') or '')[:800]}"
        )
    if agent_id == "DetectionAnalyst":
        return f"任务: {title}\nIOC:\n{_snip(art.get('ioc_pack') or {}, 5000)}\n根因:\n{(notes.get('root_cause') or '')[:2000]}"
    if agent_id == "ThreatIntelAnalyst":
        intel = art.get("threat_intel") or {}
        return (
            f"任务: {title}\n搜索结果:\n{_snip(intel.get('search_hits') or [], 5000)}\n"
            f"目录: KEV={intel.get('in_kev')} nvd={_snip(intel.get('nvd') or {}, 800)}"
        )
    if agent_id == "BypassAnalyst":
        return (
            f"任务: {title}\n根因:\n{(notes.get('root_cause') or '')[:2500]}\n\n"
            f"Feature:\n{_snip(art.get('feature_trace') or {}, 2500)}\n对照: {_snip(art.get('control_names') or [], 1500)}"
        )
    if agent_id == "ResidualVulnAnalyst":
        return (
            f"任务: {title}\n热点: {_snip(art.get('hotspot_names') or [], 1500)}\n"
            f"根因:\n{(notes.get('root_cause') or '')[:2000]}\n对照: {_snip(art.get('control_names') or [], 2000)}"
        )
    if agent_id == "ReportWriter":
        return (
            f"任务: {title}\nPE:\n{_snip(brief_pe)}\n根因:\n{(notes.get('root_cause') or '')[:1800]}\n"
            f"请按 19 节模板写报告（评测时允许缩短，但必须保留 §6/§16–§19 标题）。"
        )
    return f"任务: {title}\n证据:\n{_snip({k: art.get(k) for k in ('old_pe', 'symbol_diff') if art.get(k)}, 4000)}"


def _synthetic_user(agent_id: str) -> str:
    return (
        "任务: CVE-2026-68820 afd.sys\n"
        "Old: FileVersion 10.0.22621.4317 x64 size 697848 SHA256 5a002ffa927dcbd3ed3e5dc83f12844ffc43814469b9776c537b39cdd6e0505c\n"
        "New: FileVersion 10.0.22621.7517 x64 size 710096 SHA256 b4fe2589989b20c2bde64352fce061516dac312ab683f48d9a8716489fcc05ad\n"
        "热点: AfdBind, AfdCleanupCore, AfdTdiValidateTransportFileObject\n"
        "Feature_1328019771 on_disk_dword=0；对照未改: AfdNotifySock, AfdClose\n"
        "搜索结果: 无 APT 名称。CISA KEV=是 date_added=2026-08-11\n"
        f"请按 {agent_id} 职责输出。"
    )


def collect_trainset(agent_id: str, limit: int = 3) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in list_jobs(24):
        if item.get("status") != "completed":
            continue
        job = get_job(item["id"]) or {}
        art = ((job.get("result") or {}).get("artifacts") or {})
        if not art:
            continue
        user = _build_eval_user(agent_id, art, job.get("title") or "")
        if len(user) < 40:
            continue
        rows.append(
            {
                "input": user[:9000],
                "additional_context": {"job_id": item["id"], "agent": agent_id},
                "answer": agent_id,
            }
        )
        if len(rows) >= limit:
            break
    if not rows:
        rows.append(
            {
                "input": _synthetic_user(agent_id),
                "additional_context": {"job_id": "synthetic", "agent": agent_id},
                "answer": agent_id,
            }
        )
    return rows


def score_output(agent_id: str, response: str) -> tuple[float, str]:
    text = (response or "").strip()
    checks: list[tuple[bool, str]] = []

    def add(ok: bool, msg: str) -> None:
        checks.append((ok, msg))

    add(len(text) > 120, "输出过短，缺少可核对细节")
    add(bool(re.search(r"[\u4e00-\u9fff]", text)), "未使用中文")
    add(not _EXPLOIT_NOISE.search(text), "出现了 exploit/PoC 写法")
    add("编造" not in text[:80], "开头在解释限制而不是做分析")

    if agent_id == "BypassAnalyst":
        add(bool(re.search(r"verdict|闭合|绕过面", text, re.I)), "缺少补丁完整性结论")
        add(bool(re.search(r"findings|Feature|门控|锁", text, re.I)), "未覆盖评审维度")
        add("{" in text and "}" in text, "缺少 JSON 结构")
    elif agent_id == "ResidualVulnAnalyst":
        add(bool(re.search(r"verdict|未发现|嫌疑|残留", text)), "缺少残留结论")
        add("{" in text and "}" in text, "缺少 JSON 结构")
    elif agent_id == "DetectionAnalyst":
        add("哈希" in text or "SHA256" in text or "sha256" in text.lower(), "未使用样本哈希")
        add(bool(re.search(r"清点|hunt|狩猎|核验", text)), "缺少检测方法结构")
    elif agent_id == "ThreatIntelAnalyst":
        add(bool(re.search(r"KEV|在野|优先级|检索", text)), "未对照公开情报")
    elif agent_id == "RootCauseAnalyst":
        add("漏洞链" in text, "缺少漏洞链草稿")
        add(bool(re.search(r"已证实|推断", text)), "未标注证据级别")
    elif agent_id == "ReportWriter":
        add(bool(re.search(r"##\s*6", text)), "缺少 §6 漏洞链标题")
        add(bool(re.search(r"##\s*16", text)), "缺少 §16")
    elif agent_id == "PEAnalyst":
        add(bool(re.search(r"架构|FileVersion|版本", text)), "未做版本归因")
    elif agent_id == "DisasmAnalyst":
        add(bool(re.search(r"锁|Feature|RVA|释放", text, re.I)), "未抓住反汇编要点")
    elif agent_id == "FeatureAnalyst":
        add(bool(re.search(r"Feature|启用|xref", text, re.I)), "未解释 Feature")
    elif agent_id == "SymbolAnalyst":
        add(bool(re.search(r"尺寸|热点|Δ|\+", text)), "未定位补丁热点")
    elif agent_id == "ControlPathAnalyst":
        add(bool(re.search(r"排除|未变|对照", text)), "未做对照排除")

    n = len(checks) or 1
    score = sum(1.0 for ok, _ in checks if ok) / n
    failed = [msg for ok, msg in checks if not ok]
    if score >= 0.99:
        feedback = "输出满足该分析师的结构与安全约束。"
    else:
        feedback = "需要改进：" + "；".join(failed) + "。保留证据级别标注，引用输入中的函数/RVA/哈希，不要写 exploit。"
    return score, feedback


class _RubricEvaluator:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def __call__(self, data: dict[str, Any], response: str):
        from gepa.adapters.default_adapter.default_adapter import EvaluationResult

        score, feedback = score_output(self.agent_id, response)
        return EvaluationResult(score=score, feedback=feedback, objective_scores=None)


class _TaskLM:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def __call__(self, messages: list[dict[str, str]]) -> str:
        system = ""
        user = ""
        for m in messages:
            role = (m.get("role") or "").lower()
            if role == "system":
                system = m.get("content") or ""
            elif role == "user":
                user += m.get("content") or ""
        return run_agent(self.agent_id, system, user, max_tokens=2800, temperature=0.1)


class _ReflectionLM:
    def __call__(self, prompt_or_messages: Any) -> str:
        llm = make_chat(max_tokens=4096, temperature=0.4)
        if isinstance(prompt_or_messages, str):
            msgs = [HumanMessage(content=prompt_or_messages)]
        else:
            msgs = []
            for m in prompt_or_messages or []:
                role = (m.get("role") if isinstance(m, dict) else "") or "user"
                content = m.get("content") if isinstance(m, dict) else str(m)
                if role == "system":
                    msgs.append(SystemMessage(content=content or ""))
                else:
                    msgs.append(HumanMessage(content=content or ""))
            if not msgs:
                msgs = [HumanMessage(content=str(prompt_or_messages))]
        resp = llm.invoke(msgs)
        content = resp.content
        if isinstance(content, list):
            return "".join(str(x) for x in content)
        return str(content or "").strip()


def enforce_safety(agent_id: str, prompt: str) -> str:
    text = (prompt or "").strip()
    tail = SAFETY_TAIL.get(agent_id) or ""
    if tail and tail[:12] not in text:
        text = f"{text}\n{tail}".strip()
    return text


def optimize_agent_prompt(
    agent_id: str,
    *,
    max_metric_calls: int = 16,
    apply: bool = True,
) -> dict[str, Any]:
    if agent_id not in DEFAULT_AGENT_PROMPTS:
        raise LLMError(f"未知分析师: {agent_id}")
    cfg = get_llm_config()
    if not llm_configured(cfg):
        raise LLMError("LLM API key 未配置，请先在设置页填写")
    try:
        import gepa
        from gepa.adapters.default_adapter.default_adapter import DefaultAdapter
    except ImportError as e:
        raise LLMError("未安装 gepa。请在 webapp 目录执行: pip install gepa") from e

    seed = agent_system_prompt(agent_id, cfg)
    trainset = collect_trainset(agent_id)
    adapter = DefaultAdapter(model=_TaskLM(agent_id), evaluator=_RubricEvaluator(agent_id))
    result = gepa.optimize(
        seed_candidate={"system_prompt": seed},
        trainset=trainset,
        valset=trainset,
        adapter=adapter,
        reflection_lm=_ReflectionLM(),
        max_metric_calls=max(8, int(max_metric_calls)),
        display_progress_bar=False,
        track_best_outputs=False,
        raise_on_exception=True,
        seed=0,
    )
    best = (result.best_candidate or {}).get("system_prompt") or seed
    best = enforce_safety(agent_id, best)
    scores = list(result.val_aggregate_scores or [])
    best_score = None
    if scores and result.best_idx is not None and 0 <= result.best_idx < len(scores):
        best_score = float(scores[result.best_idx])
    if apply:
        prompts = dict(cfg.get("prompts") or {})
        prompts[agent_id] = best
        cfg["prompts"] = prompts
        save_llm_config(cfg)
    return {
        "agent_id": agent_id,
        "prompt": best,
        "score": best_score,
        "examples": len(trainset),
        "metric_calls": getattr(result, "total_metric_calls", None),
        "applied": apply,
    }
