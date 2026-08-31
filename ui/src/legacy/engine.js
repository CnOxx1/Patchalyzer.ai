import { ui } from "../lib/store.js";
import { ensureMarkdownLibs } from "../lib/markdown.js";
import { PANEL_GROUP } from "../lib/caseTabs.js";

const API = "/api";

function $(sel) { return document.querySelector(sel); }
function $$(sel) { return [...document.querySelectorAll(sel)]; }

let homeTimer = null;

function activateTab(tab) {
  if (!tab || !$(`#tab-${tab}`)) return;
  $$(".nav-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
  $$(".tab").forEach(t => t.classList.toggle("active", t.id === `tab-${tab}`));
  $(".vt-main")?.classList.toggle("wide", tab !== "analyze");
  try { localStorage.setItem("patchalyzer.tab", tab); } catch { /* ignore */ }
  if (tab !== "home") {
    clearInterval(homeTimer);
    homeTimer = null;
  }
  if (tab === "jobs") loadJobs();
  if (tab === "patch") {
    if (patchView?.mode === "detail" && patchView.bulletin) loadPatchBulletin(patchView.bulletin);
    else loadPatchDays();
  }
  if (tab === "home") loadHome();
}

$$(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => activateTab(btn.dataset.tab));
});
document.addEventListener("click", e => {
  const jump = e.target.closest(".nav-jump");
  if (jump?.dataset.tab) activateTab(jump.dataset.tab);
});

function bindFileLabels() {
  $$(".drop-card input[type=file]").forEach(input => {
    input.addEventListener("change", () => {
      const card = input.closest(".drop-card");
      const nameEl = card.querySelector(".drop-name");
      const file = input.files[0];
      card.classList.toggle("has-file", !!file);
      nameEl.textContent = file ? file.name : "";
    });
  });
}
bindFileLabels();

const AGENT_PICKER = [
  { id: "PEAnalyst", title: "PEAnalyst", hint: "版本归因" },
  { id: "SymbolAnalyst", title: "SymbolAnalyst", hint: "补丁定位" },
  { id: "DisasmAnalyst", title: "DisasmAnalyst", hint: "锁 / 释放" },
  { id: "FeatureAnalyst", title: "FeatureAnalyst", hint: "Feature 启用位" },
  { id: "ControlPathAnalyst", title: "ControlPathAnalyst", hint: "对照路径" },
  { id: "RootCauseAnalyst", title: "RootCauseAnalyst", hint: "根因综合" },
  { id: "DetectionAnalyst", title: "DetectionAnalyst", hint: "IOC / 检测" },
  { id: "ThreatIntelAnalyst", title: "ThreatIntelAnalyst", hint: "在野利用" },
  { id: "BypassAnalyst", title: "BypassAnalyst", hint: "补丁完整性狩猎" },
  { id: "FeatureOffAnalyst", title: "FeatureOffAnalyst", hint: "Feature 关闭路径" },
  { id: "ResidualVulnAnalyst", title: "ResidualVulnAnalyst", hint: "同类残留发现" },
  { id: "AliasSiteAnalyst", title: "AliasSiteAnalyst", hint: "调用点覆盖" },
  { id: "ReportWriter", title: "ReportWriter", hint: "报告执笔" },
];
const AGENT_PRESETS = {
  all: AGENT_PICKER.map(a => a.id),
  core: ["PEAnalyst", "SymbolAnalyst", "DisasmAnalyst", "FeatureAnalyst", "ControlPathAnalyst", "RootCauseAnalyst"],
  soc: ["DetectionAnalyst", "ThreatIntelAnalyst", "BypassAnalyst", "FeatureOffAnalyst", "ResidualVulnAnalyst", "AliasSiteAnalyst", "ReportWriter"],
  report: ["ReportWriter"],
  none: [],
};
const AGENT_STORE_KEY = "patchalyzer.enabled_agents";
const ROUTING_STORE_KEY = "patchalyzer.routing_mode";

function selectedAgentIds() {
  return $$("#agent-checks input[name=agent]").filter(el => el.checked).map(el => el.value);
}

function persistAgentSelection(ids) {
  try { localStorage.setItem(AGENT_STORE_KEY, JSON.stringify(ids)); } catch { /* ignore */ }
}

function loadSavedAgentSelection() {
  try {
    const raw = JSON.parse(localStorage.getItem(AGENT_STORE_KEY) || "null");
    if (Array.isArray(raw)) return raw.filter(id => AGENT_PICKER.some(a => a.id === id));
  } catch { /* ignore */ }
  return AGENT_PRESETS.all;
}

function setAgentChecks(ids) {
  const want = new Set(ids);
  $$("#agent-checks input[name=agent]").forEach(el => { el.checked = want.has(el.value); });
}

function syncAgentPickerEnabled() {
  const on = $("#run-llm")?.checked !== false;
  $("#agent-picker")?.classList.toggle("is-off", !on);
}

function renderAgentPicker() {
  const box = $("#agent-checks");
  if (!box) return;
  const saved = loadSavedAgentSelection();
  box.innerHTML = AGENT_PICKER.map(a => `
    <label>
      <input type="checkbox" name="agent" value="${a.id}" ${saved.includes(a.id) ? "checked" : ""} />
      <span>${a.title}<small>${a.hint}</small></span>
    </label>`).join("");
  syncAgentPickerEnabled();
}

function loadSavedRoutingMode() {
  try {
    const v = localStorage.getItem(ROUTING_STORE_KEY);
    if (v === "manual" || v === "auto") return v;
  } catch { /* ignore */ }
  return "auto";
}
function persistRoutingMode(mode) {
  try { localStorage.setItem(ROUTING_STORE_KEY, mode === "manual" ? "manual" : "auto"); } catch { /* ignore */ }
}
function selectedRoutingMode() {
  const el = document.querySelector("input[name=routing_mode]:checked");
  return el && el.value === "manual" ? "manual" : "auto";
}
function applyRoutingMode(mode) {
  const want = mode === "manual" ? "manual" : "auto";
  document.querySelectorAll("input[name=routing_mode]").forEach(el => { el.checked = el.value === want; });
}

renderAgentPicker();
applyRoutingMode(loadSavedRoutingMode());
document.querySelectorAll("input[name=routing_mode]").forEach(el => {
  el.addEventListener("change", () => persistRoutingMode(selectedRoutingMode()));
});
$("#run-llm")?.addEventListener("change", syncAgentPickerEnabled);
$$(".agent-presets [data-agents]").forEach(btn => {
  btn.addEventListener("click", () => {
    const key = btn.dataset.agents;
    setAgentChecks(AGENT_PRESETS[key] || AGENT_PRESETS.all);
    persistAgentSelection(selectedAgentIds());
  });
});
$("#agent-checks")?.addEventListener("change", () => persistAgentSelection(selectedAgentIds()));

let settingsDefaults = null;
let agentPromptState = {};
let currentPromptAgent = "PEAnalyst";

function openSettings() {
  window.__paOpenSettings?.();
  loadSettings();
}
function closeSettings() {
  window.__paCloseSettings?.();
}

function flushAgentPrompt() {
  const ta = $("#agent-prompt-text");
  if (ta && currentPromptAgent) agentPromptState[currentPromptAgent] = ta.value;
}

function showAgentPrompt(id, { flush = true } = {}) {
  if (flush) flushAgentPrompt();
  currentPromptAgent = id;
  const ta = $("#agent-prompt-text");
  if (ta) ta.value = agentPromptState[id] || "";
  const sel = $("#prompt-agent");
  if (sel) sel.value = id;
}

function llmSettingsPayload() {
  const f = $("#settings-form");
  if (!f) return {};
  flushAgentPrompt();
  const body = {
    provider: f.provider.value.trim(),
    base_url: f.base_url.value.trim(),
    model: f.model.value.trim(),
    language: f.language.value,
    extra_focus: f.extra_focus.value.trim(),
    system_prompt: f.system_prompt.value,
    report_structure: f.report_structure.value,
    prompts: { ...agentPromptState },
  };
  const temp = parseFloat(f.temperature.value);
  if (Number.isFinite(temp)) body.temperature = temp;
  const mt = parseInt(f.max_tokens.value, 10);
  if (Number.isFinite(mt)) body.max_tokens = mt;
  const key = f.api_key.value.trim();
  if (key) body.api_key = key;
  return body;
}

function apiErrorMessage(data, fallback) {
  const d = data && data.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map(x => x.msg || JSON.stringify(x)).join("; ");
  if (d && typeof d === "object") return d.msg || JSON.stringify(d);
  if (data && data.message) return data.message;
  return fallback || "请求失败";
}

async function readApiJson(res) {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(text.replace(/<[^>]+>/g, " ").trim().slice(0, 300) || `HTTP ${res.status}`);
  }
}

async function loadSettings() {
  const form = $("#settings-form");
  if (!form) return;
  const [cfgRes, defRes] = await Promise.all([
    fetch(`${API}/config/llm`),
    settingsDefaults ? Promise.resolve(null) : fetch(`${API}/config/llm/defaults`),
  ]);
  const cfg = await cfgRes.json();
  if (defRes) settingsDefaults = await defRes.json();
  form.provider.value = cfg.provider || "openai";
  form.base_url.value = cfg.base_url || "";
  form.model.value = cfg.model || "";
  form.temperature.value = cfg.temperature ?? 0.2;
  form.max_tokens.value = cfg.max_tokens ?? 8192;
  form.language.value = cfg.language || "zh";
  form.extra_focus.value = cfg.extra_focus || "";
  form.system_prompt.value = cfg.system_prompt || "";
  form.report_structure.value = cfg.report_structure || "";
  form.api_key.value = "";
  $("#key-preview").textContent = cfg.api_key_set
    ? `已保存 Key：${cfg.api_key_preview}（留空则不修改）`
    : "尚未配置 API Key";

  const agents = (settingsDefaults && settingsDefaults.agents) || [];
  const sel = $("#prompt-agent");
  if (sel && !sel.options.length) {
    sel.innerHTML = agents.map(a => `<option value="${a.id}">${a.title} · ${a.hint}</option>`).join("");
    sel.addEventListener("change", () => showAgentPrompt(sel.value));
  }
  agentPromptState = { ...(settingsDefaults?.prompts || {}), ...(cfg.prompts || {}) };
  showAgentPrompt(sel?.value || currentPromptAgent, { flush: false });
}

document.addEventListener("submit", async e => {
  if (e.target?.id !== "settings-form") return;
  e.preventDefault();
  const msg = $("#settings-msg");
  const res = await fetch(`${API}/config/llm`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(llmSettingsPayload()),
  });
  if (!msg) return;
  if (res.ok) {
    msg.textContent = "配置已保存";
    msg.className = "msg ok";
    loadSettings();
  } else {
    try {
      const data = await readApiJson(res);
      msg.textContent = apiErrorMessage(data, `HTTP ${res.status}`);
    } catch (err) {
      msg.textContent = err.message;
    }
    msg.className = "msg err";
  }
});

document.addEventListener("click", async e => {
  const preset = e.target.closest?.(".presets .preset");
  if (preset && $("#settings-form")) {
    $("#settings-form").base_url.value = preset.dataset.url;
    $("#settings-form").model.value = preset.dataset.model;
    return;
  }
  if (e.target.closest?.("#reset-agent-prompt")) {
    const id = $("#prompt-agent")?.value || currentPromptAgent;
    const def = settingsDefaults?.prompts?.[id] || "";
    agentPromptState[id] = def;
    const ta = $("#agent-prompt-text");
    if (ta) ta.value = def;
    return;
  }
  if (e.target.closest?.("#reset-prompts")) {
    if (!settingsDefaults) return;
    const f = $("#settings-form");
    if (!f) return;
    f.system_prompt.value = settingsDefaults.system_prompt || "";
    f.report_structure.value = settingsDefaults.report_structure || "";
    f.extra_focus.value = settingsDefaults.extra_focus || "";
    f.language.value = settingsDefaults.language || "zh";
    agentPromptState = { ...(settingsDefaults.prompts || {}) };
    const ta = $("#agent-prompt-text");
    if (ta) ta.value = agentPromptState[currentPromptAgent] || "";
    const msg = $("#settings-msg");
    if (msg) {
      msg.textContent = "已填入默认提示词，点击保存后生效";
      msg.className = "msg";
    }
    return;
  }
  const testBtn = e.target.closest?.("#test-llm");
  if (testBtn) {
    const msg = $("#settings-msg");
    testBtn.disabled = true;
    if (msg) {
      msg.textContent = "测试中…";
      msg.className = "msg";
    }
    try {
      const res = await fetch(`${API}/config/llm/test`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(llmSettingsPayload()),
      });
      const data = await readApiJson(res);
      if (!res.ok) throw new Error(apiErrorMessage(data, `HTTP ${res.status}`));
      if (msg) {
        msg.textContent = data.message || "OK";
        msg.className = "msg ok";
      }
    } catch (err) {
      if (msg) {
        msg.textContent = err.message;
        msg.className = "msg err";
      }
    } finally {
      testBtn.disabled = false;
    }
    return;
  }
  const gepaBtn = e.target.closest?.("#gepa-optimize");
  if (gepaBtn) {
    flushAgentPrompt();
    const id = $("#prompt-agent")?.value || currentPromptAgent;
    const msg = $("#settings-msg");
    if (!id) return;
    gepaBtn.disabled = true;
    if (msg) {
      msg.textContent = `GEPA 正在优化 ${id}，可能需要几分钟…`;
      msg.className = "msg";
    }
    try {
      const res = await fetch(`${API}/config/llm/gepa`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_id: id, max_metric_calls: 16, apply: true }),
      });
      const data = await readApiJson(res);
      if (!res.ok) throw new Error(apiErrorMessage(data, `HTTP ${res.status}`));
      if (data.prompt) {
        agentPromptState[id] = data.prompt;
        const ta = $("#agent-prompt-text");
        if (ta) ta.value = data.prompt;
      }
      const score = data.score != null ? ` · 评分 ${(Number(data.score) * 100).toFixed(0)}%` : "";
      if (msg) {
        msg.textContent = `已写入 ${id} 提示词${score}。重新生成报告后生效。`;
        msg.className = "msg ok";
      }
    } catch (err) {
      if (msg) {
        msg.textContent = err.message || "GEPA 优化失败";
        msg.className = "msg err";
      }
    } finally {
      gepaBtn.disabled = false;
    }
  }
});

let pollTimer = null;
let huntLabTimer = null;
let researchLabTimer = null;
let unsubLive = null;

$("#analyze-form")?.addEventListener("submit", async e => {
  e.preventDefault();
  const f = e.target;
  const fd = new FormData();
  fd.append("title", f.title.value);
  fd.append("cve", f.cve.value);
  if (f.filename?.value) fd.append("filename", f.filename.value);
  fd.append("old_label", f.old_label.value);
  fd.append("new_label", f.new_label.value);
  fd.append("mid_label", f.mid_label.value);
  const runLlm = f.run_llm.checked;
  fd.append("run_llm", runLlm ? "true" : "false");
  fd.append("agents_set", "1");
  const picked = selectedAgentIds();
  fd.append("enabled_agents", runLlm ? picked.join(",") : "");
  fd.append("routing_mode", selectedRoutingMode());
  persistRoutingMode(selectedRoutingMode());
  persistAgentSelection(picked);
  if (f.old_file.files[0]) fd.append("old_file", f.old_file.files[0]);
  if (f.new_file.files[0]) fd.append("new_file", f.new_file.files[0]);
  if (f.mid_file.files[0]) fd.append("mid_file", f.mid_file.files[0]);

  const statusBox = $("#analyze-status");
  statusBox.classList.remove("hidden");
  $("#progress-fill").style.width = "0%";
  $("#progress-text").textContent = f.old_file.files[0] ? "上传中…" : "正在从微软补丁定位样本…";

  const res = await fetch(`${API}/jobs`, { method: "POST", body: fd });
  if (!res.ok) {
    $("#progress-text").textContent = "失败: " + (await res.text());
    return;
  }
  const { job_id } = await res.json();
  currentJobId = job_id;
  pollJob(job_id, true);
});

$("#cancel-job")?.addEventListener("click", async () => {
  const id = currentJobId;
  if (!id) return;
  try {
    await fetch(`${API}/jobs/${id}/cancel`, { method: "POST" });
    $("#progress-text").textContent = "正在取消…";
  } catch (e) {
    $("#progress-text").textContent = "取消失败: " + e.message;
  }
});

async function postJobAction(path, body) {
  const id = currentJobId;
  if (!id) return;
  const opts = { method: "POST" };
  if (body) {
    opts.headers = { "Content-Type": "application/json" };
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(`${API}/jobs/${id}${path}`, opts);
  const data = await readApiJson(res);
  if (!res.ok) {
    const msg = apiErrorMessage(data, `HTTP ${res.status}`);
    if (path === "/resume" && /仅失败/.test(msg)) {
      pollJob(id);
      return;
    }
    throw new Error(msg);
  }
  pollJob(id);
}

document.addEventListener("click", async e => {
  if (e.target.closest("#rerun-hotspots")) {
    const names = $$("input[name=extra-hot]:checked").map(el => el.value);
    const typed = ($("#extra-hot-input")?.value || "").split(/[\s,;，]+/).map(s => s.trim()).filter(Boolean);
    const all = [...new Set([...names, ...typed])];
    if (!all.length) {
      alert("请勾选或输入至少一个函数名");
      return;
    }
    e.target.closest("#rerun-hotspots").disabled = true;
    try {
      await postJobAction("/hotspots", { names: all, run_llm: true });
    } catch (err) {
      alert(err.message);
    }
    return;
  }
  if (e.target.closest("#retry-pdb")) {
    try { await postJobAction("/retry-pdb"); } catch (err) { alert(err.message); }
    return;
  }
  if (e.target.closest("#resume-job")) {
    const btn = e.target.closest("#resume-job");
    btn.disabled = true;
    try { await postJobAction("/resume"); } catch (err) {
      btn.disabled = false;
      alert(err.message);
    }
  }
});

let currentJobId = null;

function pollJob(jobId, switchToJobs = false) {
  currentJobId = jobId;
  watchLiveJob(jobId, { switchToJobs, analyze: true });
}

function applyWatchToggles(watch) {
  const en = $("#watch-enabled");
  const au = $("#watch-auto");
  if (en) en.checked = watch?.enabled !== false;
  if (au) au.checked = !!watch?.auto_kernel;
}

async function saveWatchToggles() {
  const res = await fetch(`${API}/config/watch`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      enabled: $("#watch-enabled")?.checked !== false,
      auto_kernel: !!$("#watch-auto")?.checked,
    }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function startCveJob(cve, filename) {
  const runLlm = $("#run-llm")?.checked !== false;
  const res = await fetch(`${API}/jobs/from-cve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      cve,
      filename: filename || "",
      run_llm: runLlm,
      enabled_agents: runLlm ? selectedAgentIds() : [],
      routing_mode: selectedRoutingMode(),
    }),
  });
  const data = await readApiJson(res);
  if (!res.ok) throw new Error(apiErrorMessage(data, `HTTP ${res.status}`));
  return data.job_id;
}

function fmtPatchDate(iso) {
  const d = String(iso || "").slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return "";
  const [y, m, day] = d.split("-");
  return `${y} 年 ${Number(m)} 月 ${Number(day)} 日`;
}

let patchView = { mode: "days", bulletin: "" };
let patchDaysCache = null;
const patchBulletinCache = {};
let patchImpactFilter = localStorage.getItem("patchImpactFilter") || "weaponizable";
let patchKernelOnly = localStorage.getItem("patchKernelOnly") === "1";
let selectedPatchCve = "";

const EXPLOIT_LIKELY_LABEL = {
  more: "较可能被利用",
  less: "较不可能",
  unlikely: "不太可能",
  detected: "已发现在野利用",
};

function setPatchChrome() {
  const detail = patchView.mode === "detail";
  $("#patch-back")?.classList.toggle("hidden", !detail);
  $("#auto-patch-now")?.classList.toggle("hidden", !detail);
  $("#patch-filters")?.classList.toggle("hidden", !detail);
  $("#patch-detail")?.classList.toggle("hidden", !detail);
  if (!detail) selectedPatchCve = "";
  if (detail) {
    $$(".patch-filter").forEach(btn => btn.classList.toggle("active", btn.dataset.impact === patchImpactFilter));
    const ker = $("#patch-kernel-only");
    if (ker) ker.checked = patchKernelOnly;
  }
}

function filterPatchRows(rows) {
  return (rows || []).filter(r => {
    if (patchKernelOnly && !r.kernelish) return false;
    if (patchImpactFilter === "all") return true;
    if (patchImpactFilter === "weaponizable") return !!r.weaponizable;
    return (r.impact || "") === patchImpactFilter;
  });
}

function patchCacheHint(data) {
  if (!data) return "";
  const when = (data.fetched_at || "").replace("T", " ").slice(0, 16);
  if (data.cached) return when ? ` · 本地缓存 ${when}` : " · 本地缓存";
  return when ? ` · 已保存 ${when}` : "";
}

function renderPatchDays(data) {
  const meta = $("#patch-meta");
  const list = $("#patch-list");
  const months = data.months || [];
  applyWatchToggles(data.watch);
  meta.textContent = months.length
    ? `共 ${months.length} 个补丁日，点进去查看 CVE${patchCacheHint(data)}`
    : "未获取到补丁日";
  if (!months.length) {
    list.innerHTML = `<p class="empty">MSRC 没有返回月度公告。</p>`;
    return;
  }
  list.innerHTML = months.map(m => {
    const day = String(m.date || "").slice(8, 10).replace(/^0/, "") || "·";
    return `
      <div class="patch-day" data-bulletin="${esc(m.id)}" role="button" tabindex="0">
        <div class="job-avatar">${esc(day)}</div>
        <div>
          <strong>${esc(m.title || m.id)}</strong>
          <div class="hint">${esc(fmtPatchDate(m.date) || m.id)}</div>
        </div>
        <span class="status pending">进入</span>
      </div>`;
  }).join("");
}

function renderPatchDetail(row) {
  const el = $("#patch-detail");
  if (!el) return;
  if (!row) {
    el.innerHTML = `<p class="hint">点一条 CVE 查看 MSRC 公告描述，再决定要不要点「分析」。</p>`;
    return;
  }
  const faqs = (row.faq || []).map(f => `<p class="msrc-faq">${esc(f)}</p>`).join("");
  const link = `https://msrc.microsoft.com/update-guide/vulnerability/${encodeURIComponent(row.cve)}`;
  const likely = EXPLOIT_LIKELY_LABEL[row.exploit_likely] || row.exploit_likely || "利用可能性未标注";
  el.innerHTML = `
    <h4>${esc(row.cve)}</h4>
    <p class="hint">${esc(row.title || "")}</p>
    <p class="hint">${esc(row.impact_label || "影响类型未标注")} · ${esc(likely)}</p>
    <p class="msrc-body">${esc(row.description || "这条公告没有独立描述，标题即摘要。")}</p>
    ${faqs ? `<h4>MSRC FAQ</h4>${faqs}` : ""}
    <p><a href="${link}" target="_blank" rel="noopener">打开 MSRC 公告</a></p>
    <p class="hint">描述来自当月 CVRF，用来判断值不值得分析，不是本工具的结论。</p>`;
}

function selectPatchCve(cve) {
  selectedPatchCve = cve || "";
  $$(".patch-row").forEach(el => el.classList.toggle("selected", el.dataset.cve === selectedPatchCve));
  const id = patchView.bulletin;
  const all = (id && patchBulletinCache[id]?.cves) || [];
  renderPatchDetail(all.find(r => r.cve === selectedPatchCve) || null);
}

function renderPatchBulletin(id, data) {
  const meta = $("#patch-meta");
  const list = $("#patch-list");
  applyWatchToggles(data.watch);
  const date = fmtPatchDate(data.release_date) || (data.release_date || "").slice(0, 10);
  const all = data.cves || [];
  const rows = filterPatchRows(all);
  const w = data.weaponizable_count ?? all.filter(r => r.weaponizable).length;
  meta.textContent = `${data.bulletin || id} · ${date || "日期未知"} · 列出 ${rows.length}/${all.length} · 可利用向 ${w} · 内核/驱动 ${data.kernel_count || 0}${patchCacheHint(data)}`;
  if (selectedPatchCve && !rows.some(r => r.cve === selectedPatchCve)) selectedPatchCve = "";
  if (!all.length) {
    list.innerHTML = `<p class="empty">这一期没有可列的 Windows CVE（已过滤 Edge/Office 等）。</p>`;
    renderPatchDetail(null);
    return;
  }
  if (!rows.length) {
    list.innerHTML = `<p class="empty">当前筛选下没有 CVE。可改选「全部」或取消「仅内核/驱动」。</p>`;
    renderPatchDetail(null);
    return;
  }
  list.innerHTML = rows.map(r => {
    const impact = r.impact_label || "";
    const cls = r.weaponizable ? "is-weapon" : (r.impact === "dos" || r.impact === "info" ? `is-${r.impact}` : "");
    const sel = selectedPatchCve === r.cve ? " selected" : "";
    return `
      <div class="patch-row${r.kernelish ? " is-kernel" : ""}${sel}" data-cve="${esc(r.cve)}" data-file="${esc(r.filename_guess || "")}">
        <div>
          <strong>${esc(r.cve)}${impact ? `<span class="patch-impact ${cls}">${esc(impact)}</span>` : ""}</strong>
          <div class="hint">${esc(r.title || "")}</div>
        </div>
        <div class="patch-file">${esc(r.filename_guess || "需手填文件名")}</div>
        <button type="button" class="btn ghost patch-run">分析</button>
      </div>`;
  }).join("");
  renderPatchDetail(rows.find(r => r.cve === selectedPatchCve) || null);
}

async function loadPatchDays(force = false) {
  const meta = $("#patch-meta");
  const list = $("#patch-list");
  if (!list) return;
  patchView = { mode: "days", bulletin: "" };
  setPatchChrome();
  if (!force && patchDaysCache?.months?.length) {
    renderPatchDays(patchDaysCache);
    return;
  }
  meta.textContent = force ? "正在向微软刷新补丁日…" : "正在读取补丁日目录…";
  if (!patchDaysCache) list.innerHTML = `<p class="empty">${force ? "刷新 MSRC…" : "读取本地缓存…"}</p>`;
  try {
    const res = await fetch(`${API}/patch-tuesday${force ? "?refresh=1" : ""}`);
    const data = await readApiJson(res);
    if (res.status === 404 || res.status === 405) {
      throw new Error("后端进程过旧，没有补丁日接口。请关掉旧的 python run.py 后重新启动，再强制刷新页面。");
    }
    if (!res.ok) throw new Error(apiErrorMessage(data, `HTTP ${res.status}`));
    patchDaysCache = data;
    renderPatchDays(data);
  } catch (err) {
    meta.textContent = "读取补丁日失败";
    list.innerHTML = `<p class="empty">${esc(err.message || String(err))}</p>`;
  }
}

async function loadPatchBulletin(id, force = false) {
  const meta = $("#patch-meta");
  const list = $("#patch-list");
  if (!list || !id) return;
  if (patchView.bulletin !== id) selectedPatchCve = "";
  patchView = { mode: "detail", bulletin: id };
  setPatchChrome();
  if (!force && patchBulletinCache[id]) {
    renderPatchBulletin(id, patchBulletinCache[id]);
    return;
  }
  meta.textContent = force ? `正在向微软刷新 ${id}…` : `正在读取 ${id}…`;
  if (!patchBulletinCache[id]) list.innerHTML = `<p class="empty">${force ? "刷新该期 CVE…" : "读取本地缓存…"}</p>`;
  try {
    const q = new URLSearchParams({ bulletin: id });
    if (force) q.set("refresh", "1");
    const res = await fetch(`${API}/patch-tuesday?${q}`);
    const data = await readApiJson(res);
    if (res.status === 404 || res.status === 405) {
      throw new Error("后端进程过旧，没有补丁日接口。请关掉旧的 python run.py 后重新启动，再强制刷新页面。");
    }
    if (!res.ok) throw new Error(apiErrorMessage(data, `HTTP ${res.status}`));
    patchBulletinCache[id] = data;
    renderPatchBulletin(id, data);
  } catch (err) {
    meta.textContent = "读取公告失败";
    list.innerHTML = `<p class="empty">${esc(err.message || String(err))}</p>`;
  }
}

function jobRowHtml(j) {
  const initial = (j.title || "P").replace(/^CVE-/i, "").slice(0, 2).toUpperCase() || "PA";
  const pills = [];
  if (j.in_kev === 1 || j.in_kev === true) pills.push(`<span class="tag-pill err">KEV</span>`);
  const bv = String(j.bypass_verdict || "");
  if (bv === "bypassable") pills.push(`<span class="tag-pill err">有绕过面</span>`);
  else if (bv === "partial") pills.push(`<span class="tag-pill warn">部分闭合</span>`);
  else if (bv === "closed") pills.push(`<span class="tag-pill ok">已闭合</span>`);
  const rv = String(j.residual_verdict || "");
  if (rv === "likely") pills.push(`<span class="tag-pill err">残留</span>`);
  else if (rv === "suspects") pills.push(`<span class="tag-pill warn">同类嫌疑</span>`);
  return `
    <div class="job-item" data-id="${j.id}">
      <div class="job-avatar ${esc(j.status)}">${esc(initial)}</div>
      <div>
        <strong>${esc(j.title)}</strong>
        <div class="hint">${esc(j.old_label || "")}${j.mid_label ? " / " + esc(j.mid_label) : ""}${j.new_label ? " → " + esc(j.new_label) : ""} · ${fmtDate(j.created_at)}</div>
        <div class="job-id">${esc(j.id)}</div>
      </div>
      <div class="job-end">
        <span class="status ${j.status}">${statusLabel(j.status)}</span>
        ${pills.length ? `<div class="job-pills">${pills.join("")}</div>` : ""}
      </div>
    </div>`;
}

function bindJobRows(root) {
  root?.querySelectorAll(".job-item").forEach(item => {
    item.addEventListener("click", () => {
      if (window.__paOpenJob) window.__paOpenJob(item.dataset.id);
      else openJobModal(item.dataset.id);
    });
  });
}

function setNavLive(on) {
  $("#nav-live")?.classList.toggle("hidden", !on);
}

async function loadHome() {
  if (loadHome.busy) return;
  loadHome.busy = true;
  const statsEl = $("#home-stats");
  const liveEl = $("#home-live");
  const svcEl = $("#home-service");
  const recentEl = $("#home-jobs");
  if (!statsEl) {
    loadHome.busy = false;
    return;
  }

  try {
  const daysPromise = patchDaysCache
    ? Promise.resolve(patchDaysCache)
    : fetch(`${API}/patch-tuesday`).then(r => r.json()).then(d => {
        if (d?.months) patchDaysCache = d;
        return d;
      });
  const [jobsRes, healthRes, llmRes, watchRes, daysRes] = await Promise.allSettled([
    fetch(`${API}/jobs`).then(r => r.json()),
    fetch(`${API}/health`).then(r => r.json()),
    fetch(`${API}/config/llm`).then(r => r.json()),
    fetch(`${API}/config/watch`).then(r => r.json()),
    daysPromise,
  ]);
  const jobs = jobsRes.status === "fulfilled" && Array.isArray(jobsRes.value) ? jobsRes.value : [];
  const running = jobs.filter(j => j.status === "running").length;
  const pending = jobs.filter(j => j.status === "pending").length;
  const completed = jobs.filter(j => j.status === "completed").length;
  const failed = jobs.filter(j => j.status === "failed" || j.status === "cancelled").length;
  setNavLive(running + pending > 0);
  statsEl.innerHTML = `
    <div class="home-stat"><b>${running}</b><span>运行中</span></div>
    <div class="home-stat${pending ? " is-warn" : ""}"><b>${pending}</b><span>排队</span></div>
    <div class="home-stat is-ok"><b>${completed}</b><span>已完成</span></div>
    <div class="home-stat${failed ? " is-err" : ""}"><b>${failed}</b><span>失败 / 取消</span></div>`;

  const live = jobs.filter(j => j.status === "running" || j.status === "pending");
  await Promise.all(live.map(async j => {
    if (j.progress) return;
    try {
      const full = await fetch(`${API}/jobs/${j.id}`).then(r => r.json());
      if (full?.progress) j.progress = full.progress;
    } catch { /* ignore */ }
  }));
  if (liveEl) {
    if (!live.length) {
      liveEl.innerHTML = `<p class="hint">当前没有正在分析的任务。</p>
        <div class="home-links">
          <button type="button" class="btn ghost nav-jump" data-tab="analyze">去上传分析</button>
          <button type="button" class="btn ghost nav-jump" data-tab="patch">去补丁列表</button>
        </div>`;
    } else {
      liveEl.innerHTML = live.map(j => {
        const pct = j.progress?.percent ?? (j.status === "pending" ? 0 : 10);
        const msg = j.progress?.message || statusLabel(j.status);
        return `<div class="home-live-item" data-id="${esc(j.id)}" role="button">
          <strong>${esc(j.title)}</strong>
          <div class="progress-bar"><div style="width:${pct}%;height:100%;background:var(--accent-strong)"></div></div>
          <p class="hint">${esc(msg)}</p>
        </div>`;
      }).join("");
      liveEl.querySelectorAll(".home-live-item").forEach(el => {
        el.addEventListener("click", () => {
          if (window.__paOpenJob) window.__paOpenJob(el.dataset.id);
          else openJobModal(el.dataset.id);
        });
      });
    }
  }

  const health = healthRes.status === "fulfilled" ? healthRes.value : null;
  const llm = llmRes.status === "fulfilled" ? llmRes.value : null;
  const watch = watchRes.status === "fulfilled" ? watchRes.value : null;
  const days = daysRes.status === "fulfilled" ? daysRes.value : null;
  const month = (days?.months || [])[0];
  if (svcEl) {
    svcEl.innerHTML = `<dl class="home-kv">
      <div><dt>服务</dt><dd>${health?.status === "ok" ? "运行中" : "未连接"}</dd></div>
      <div><dt>LLM</dt><dd>${llm?.api_key_set ? "已配置 API Key" : "未填写 Key"}</dd></div>
      <div><dt>补丁监控</dt><dd>${watch?.enabled === false ? "关闭" : "开启"}${watch?.auto_kernel ? " · 自动分析内核" : ""}</dd></div>
      <div><dt>最近补丁日</dt><dd>${month ? esc(month.title || month.id) : "未拉取"}</dd></div>
      <div><dt>任务总数</dt><dd>${jobs.length}</dd></div>
    </dl>
    <div class="home-links">
      <button type="button" class="btn ghost" id="home-open-settings">打开设置</button>
    </div>`;
    $("#home-open-settings")?.addEventListener("click", openSettings);
  }

  if (recentEl) {
    const recent = jobs.slice(0, 8);
    recentEl.innerHTML = recent.length
      ? recent.map(jobRowHtml).join("")
      : `<p class="empty">暂无任务。可从「上传分析」或「补丁列表」开始。</p>`;
    bindJobRows(recentEl);
  }

  const lead = $("#home-lead");
  if (lead) {
    lead.textContent = live.length
      ? `有 ${live.length} 个任务在队列中`
      : `共 ${jobs.length} 个任务`;
  }

  clearInterval(homeTimer);
  if ($("#tab-home")?.classList.contains("active") && live.length) {
    homeTimer = setInterval(() => {
      if ($("#tab-home")?.classList.contains("active")) loadHome();
      else {
        clearInterval(homeTimer);
        homeTimer = null;
      }
    }, 4000);
  }
  } catch (err) {
    if (liveEl && !liveEl.innerHTML) {
      liveEl.innerHTML = `<p class="empty">${esc(err.message || String(err))}</p>`;
    }
  } finally {
    loadHome.busy = false;
  }
}

async function loadJobs() {
  const res = await fetch(`${API}/jobs`);
  const jobs = await res.json();
  const el = $("#jobs-list");
  if (!el) return;
  setNavLive(jobs.some(j => j.status === "running" || j.status === "pending"));
  if (!jobs.length) {
    el.innerHTML = '<p class="empty">暂无任务。可从「上传分析」填 CVE，或在「补丁列表」从本月公告开始。</p>';
    return;
  }
  el.innerHTML = jobs.map(jobRowHtml).join("");
  bindJobRows(el);
}

$("#refresh-jobs")?.addEventListener("click", loadJobs);
$("#refresh-home")?.addEventListener("click", loadHome);
$("#refresh-patch")?.addEventListener("click", () => {
  if (patchView.mode === "detail" && patchView.bulletin) loadPatchBulletin(patchView.bulletin, true);
  else loadPatchDays(true);
});
$("#patch-back")?.addEventListener("click", loadPatchDays);
$("#watch-enabled")?.addEventListener("change", () => saveWatchToggles().catch(err => {
  $("#patch-meta").textContent = "保存监控设置失败: " + err.message;
}));
$("#watch-auto")?.addEventListener("change", () => saveWatchToggles().catch(err => {
  $("#patch-meta").textContent = "保存监控设置失败: " + err.message;
}));
$$(".patch-filter").forEach(btn => {
  btn.addEventListener("click", () => {
    patchImpactFilter = btn.dataset.impact || "weaponizable";
    localStorage.setItem("patchImpactFilter", patchImpactFilter);
    const id = patchView.bulletin;
    if (id && patchBulletinCache[id]) renderPatchBulletin(id, patchBulletinCache[id]);
    setPatchChrome();
  });
});
$("#patch-kernel-only")?.addEventListener("change", e => {
  patchKernelOnly = !!e.target.checked;
  localStorage.setItem("patchKernelOnly", patchKernelOnly ? "1" : "0");
  const id = patchView.bulletin;
  if (id && patchBulletinCache[id]) renderPatchBulletin(id, patchBulletinCache[id]);
});
$("#auto-patch-now")?.addEventListener("click", async () => {
  const meta = $("#patch-meta");
  const bulletin = patchView.bulletin || "";
  meta.textContent = "正在排队本期内核/驱动 CVE（每轮最多 6 个）…";
  try {
    const q = bulletin ? `?bulletin=${encodeURIComponent(bulletin)}` : "";
    const res = await fetch(`${API}/patch-tuesday${q}`, { method: "POST" });
    const data = await readApiJson(res);
    if (res.status === 404 || res.status === 405) {
      throw new Error("后端进程过旧。请关掉旧的 python run.py 后重新启动，再强制刷新页面。");
    }
    if (!res.ok) throw new Error(apiErrorMessage(data, `HTTP ${res.status}`));
    const n = (data.started || []).filter(x => x.job_id).length;
    meta.textContent = n ? `已启动 ${n} 个任务` : "没有新的可自动分析项（可能已做过或无法推断文件名）";
    loadJobs();
  } catch (err) {
    meta.textContent = "自动分析失败: " + err.message;
  }
});
document.addEventListener("click", async e => {
  const day = e.target.closest(".patch-day");
  if (day?.dataset.bulletin) {
    loadPatchBulletin(day.dataset.bulletin);
    return;
  }
  const rowClick = e.target.closest(".patch-row");
  const btn = e.target.closest(".patch-run");
  if (rowClick && !btn) {
    selectPatchCve(rowClick.dataset.cve);
    return;
  }
  if (!btn) return;
  const row = btn.closest(".patch-row");
  if (!row) return;
  selectPatchCve(row.dataset.cve);
  btn.disabled = true;
  const prev = btn.textContent;
  btn.textContent = "排队…";
  try {
    const jobId = await startCveJob(row.dataset.cve, row.dataset.file);
    btn.textContent = "已开始";
    currentJobId = jobId;
    const statusBox = $("#analyze-status");
    statusBox?.classList.remove("hidden");
    $("#progress-text").textContent = "正在从微软补丁定位样本…";
    pollJob(jobId, true);
  } catch (err) {
    btn.disabled = false;
    btn.textContent = prev;
    $("#patch-meta").textContent = err.message;
  }
});

const PRODUCT_NAME = "Patchalyzer.ai";
const PRODUCT_MARK = "Patchalyzer.ai";

let lastJobData = null;

function table(headers, body) {
  return `<div class="table-wrap"><table><thead><tr>${headers.map(h => `<th>${h}</th>`).join("")}</tr></thead><tbody>${body}</tbody></table></div>`;
}

const ROLE_LABEL = { vulnerable: "漏洞版", patched: "修复版", earlier: "更早版本" };

const BYPASS_DIMS = [
  { id: "feature", label: "Feature 门控", re: /feature|门控|开关/i },
  { id: "coverage", label: "检查覆盖", re: /覆盖|校验|检查/i },
  { id: "sidestep", label: "旁路路径", re: /旁路|未改|旧逻辑/i },
  { id: "lock", label: "锁 / 时序窗口", re: /锁|时序|toctou|窗口/i },
  { id: "error", label: "错误 / 提前返回", re: /错误|失败|提前返回|返回路径/i },
  { id: "kill", label: "可关闭开关", re: /关闭|关掉|可关/i },
];

function fnLink(name) {
  if (!name) return "—";
  return `<button type="button" class="fn-link" data-goto-fn="${esc(name)}"><code>${esc(name)}</code></button>`;
}

function chips(list, cls) {
  return (list || []).slice(0, 8).map(c => `<span class="chip ${cls || ""}">${esc(c)}</span>`).join("");
}

function pdbGuid(pe) {
  for (const d of pe?.debug || []) {
    if (d.guid_compact) return `${d.guid_compact}${d.age ?? ""}`;
    if (d.guid) return String(d.guid);
  }
  return "";
}

function importDiff(oldPe, newPe) {
  const a = oldPe?.imports || {};
  const b = newPe?.imports || {};
  const names = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  return names
    .map(dll => ({ dll, old: a[dll] || 0, neu: b[dll] || 0, delta: (b[dll] || 0) - (a[dll] || 0) }))
    .filter(r => r.delta);
}

function hashLine(label, value) {
  if (!value) return "";
  return `<div class="ident-line"><dt>${esc(label)}</dt><dd><code class="ioc-hash" title="${esc(value)}">${esc(value)}</code></dd>
    <button type="button" class="copy-btn" data-copy="${esc(value)}">复制</button></div>`;
}

function huntClipboard(pack) {
  const lines = [];
  if (pack.cve) lines.push(pack.cve);
  if (pack.component) lines.push(pack.component);
  for (const item of pack.identity || []) {
    const role = ROLE_LABEL[item.role] || item.role || "";
    lines.push(`${role} ${item.filename || ""} ${item.file_version || ""}`.trim());
    if (item.sha256) lines.push(`SHA256 ${item.sha256}`);
    if (item.md5) lines.push(`MD5 ${item.md5}`);
  }
  const apis = [...(pack.apis?.user_mode || []), ...(pack.apis?.kernel || [])];
  if (apis.length) lines.push(`API ${apis.join(", ")}`);
  return lines.join("\n");
}

function gotoFn(name) {
  if (!name) return;
  const block = $$("details.block[data-fn]").find(el => el.dataset.fn === name);
  if (block) {
    activatePanel("disasm");
    block.open = true;
    block.classList.add("fn-flash");
    block.scrollIntoView({ block: "center", behavior: "smooth" });
    setTimeout(() => block.classList.remove("fn-flash"), 1600);
    return;
  }
  const row = $$("#panel-control tr[data-fn]").find(el => el.dataset.fn === name);
  if (row) {
    activatePanel("control");
    row.classList.add("fn-flash");
    row.scrollIntoView({ block: "center", behavior: "smooth" });
    setTimeout(() => row.classList.remove("fn-flash"), 1600);
  }
}

function configureMarked() {
  const marked = globalThis.marked;
  if (typeof marked === "undefined") return;
  const opts = { gfm: true, breaks: true, pedantic: false };
  try { if (typeof marked.setOptions === "function") marked.setOptions(opts); } catch { /* ignore */ }
  try { if (typeof marked.use === "function") marked.use(opts); } catch { /* ignore */ }
}

function sliceJsonObject(text) {
  const s = String(text || "").replace(/\r\n/g, "\n");
  const lead = s.trimStart();
  const fenceLead = lead.match(/^```(?:json)?\s*/i);
  const hay = fenceLead ? lead.slice(fenceLead[0].length) : lead;
  let start = -1;
  if (hay.startsWith("{")) start = s.indexOf("{");
  else {
    const m = s.match(/```(?:json)?\s*\{/i);
    if (m) start = s.indexOf("{", m.index);
  }
  if (start < 0) return { blob: null, rest: s.trim() };
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === "\"") inStr = false;
      continue;
    }
    if (c === "\"") inStr = true;
    else if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) {
        let rest = s.slice(i + 1).replace(/^\s*```[ \t]*/, "").trim();
        let prefix = s.slice(0, start).trim().replace(/```(?:json)?\s*$/i, "").trim();
        if (/json/i.test(prefix) && prefix.length < 160) prefix = "";
        if (prefix) rest = `${prefix}\n\n${rest}`.trim();
        return { blob: s.slice(start, i + 1), rest };
      }
    }
  }
  return { blob: null, rest: s.trim() };
}

const JSON_COPY = new Map();
let JSON_COPY_N = 0;

function coerceJson(input) {
  if (input != null && (typeof input === "object")) return { ok: true, value: input };
  const s = String(input ?? "").trim();
  if (!s) return { ok: false, error: "空内容", raw: s };
  try {
    return { ok: true, value: JSON.parse(s), raw: s };
  } catch (err) {
    const sliced = sliceJsonObject(s);
    if (sliced.blob) {
      try {
        return { ok: true, value: JSON.parse(sliced.blob), raw: sliced.blob };
      } catch (err2) {
        return { ok: false, error: err2.message || String(err2), raw: s };
      }
    }
    return { ok: false, error: err.message || String(err), raw: s };
  }
}

function looksLikeJson(text) {
  const t = String(text || "").trim();
  if (!t) return false;
  if (/^```(?:json)?/i.test(t)) return true;
  if (!/^[{\[]/.test(t)) return false;
  try {
    JSON.parse(t);
    return true;
  } catch {
    return /"[^"]+"\s*:/.test(t.slice(0, 600));
  }
}

function jsonNodeHtml(value, key, depth, ctx) {
  ctx.count = (ctx.count || 0) + 1;
  if (ctx.count > 5000) return `<div class="jleaf jmuted">…节点过多，已停止展开</div>`;
  const k = key != null ? `<span class="jk">${esc(JSON.stringify(String(key)))}</span><span class="jp">: </span>` : "";
  if (value === null) return `<div class="jleaf">${k}<span class="jn">null</span></div>`;
  const t = typeof value;
  if (t === "boolean") return `<div class="jleaf">${k}<span class="jb">${value}</span></div>`;
  if (t === "number") return `<div class="jleaf">${k}<span class="jn">${esc(String(value))}</span></div>`;
  if (t === "string") {
    if (value.length <= 220) {
      return `<div class="jleaf">${k}<span class="js">${esc(JSON.stringify(value))}</span></div>`;
    }
    return `<details class="json-node"><summary>${k}<span class="js">${esc(JSON.stringify(`${value.slice(0, 64)}…`))}</span> <span class="jhint">${value.length} 字</span></summary><pre class="jstr">${esc(value)}</pre></details>`;
  }
  if (Array.isArray(value)) {
    if (!value.length) return `<div class="jleaf">${k}<span class="jp">[]</span></div>`;
    const cap = 80;
    const kids = value.slice(0, cap).map((v, i) => jsonNodeHtml(v, i, depth + 1, ctx)).join("");
    const more = value.length > cap ? `<div class="jhint">其余 ${value.length - cap} 项未展开</div>` : "";
    return `<details class="json-node"${depth < 2 ? " open" : ""}><summary>${k}<span class="jp">[</span> <span class="jhint">${value.length}</span></summary><div class="jchildren">${kids}${more}</div></details>`;
  }
  if (t === "object") {
    const keys = Object.keys(value);
    if (!keys.length) return `<div class="jleaf">${k}<span class="jp">{}</span></div>`;
    const cap = 80;
    const kids = keys.slice(0, cap).map(kk => jsonNodeHtml(value[kk], kk, depth + 1, ctx)).join("");
    const more = keys.length > cap ? `<div class="jhint">其余 ${keys.length - cap} 键未展开</div>` : "";
    return `<details class="json-node"${depth < 2 ? " open" : ""}><summary>${k}<span class="jp">{</span> <span class="jhint">${keys.length}</span></summary><div class="jchildren">${kids}${more}</div></details>`;
  }
  return `<div class="jleaf">${k}<span class="js">${esc(String(value))}</span></div>`;
}

function jsonViewHtml(input) {
  const parsed = coerceJson(input);
  JSON_COPY_N += 1;
  const id = `j${JSON_COPY_N}`;
  const pretty = parsed.ok
    ? JSON.stringify(parsed.value, null, 2)
    : String(parsed.raw || input || "");
  JSON_COPY.set(id, pretty);
  if (JSON_COPY.size > 80) JSON_COPY.delete(JSON_COPY.keys().next().value);
  if (!parsed.ok) {
    return `<div class="json-view is-bad" data-json-view>
      <div class="json-view-bar"><span>无法解析为 JSON</span><span class="jhint">${esc(parsed.error || "")}</span>
        <button type="button" class="btn ghost json-copy" data-copy-json="${id}">复制原文</button></div>
      <pre class="note-pre">${esc(pretty)}</pre>
    </div>`;
  }
  return `<div class="json-view" data-json-view>
    <div class="json-view-bar"><span>JSON</span>
      <button type="button" class="btn ghost json-copy" data-copy-json="${id}">复制</button></div>
    <div class="json-tree">${jsonNodeHtml(parsed.value, null, 0, { count: 0 })}</div>
  </div>`;
}

function extractJsonFences(text) {
  const s = String(text || "");
  const re = /```(?:json)?[ \t]*\n?([\s\S]*?)```/gi;
  const blocks = [];
  let m;
  while ((m = re.exec(s))) {
    const inner = (m[1] || "").trim();
    const parsed = coerceJson(inner);
    if (parsed.ok) blocks.push({ value: parsed.value, start: m.index, end: m.index + m[0].length });
  }
  return blocks;
}

function mixedJsonMarkdownHtml(raw) {
  const s = String(raw || "").replace(/\r\n/g, "\n");
  if (!s.trim()) return "";
  const fences = extractJsonFences(s);
  const parts = [];
  if (fences.length) {
    let cursor = 0;
    for (const b of fences) {
      const before = s.slice(cursor, b.start).trim();
      if (before && !(/json/i.test(before) && before.length < 160)) {
        parts.push(`<div class="report-md md-compact">${mdHtml(before)}</div>`);
      }
      parts.push(jsonViewHtml(b.value));
      cursor = b.end;
    }
    const after = s.slice(cursor).trim();
    if (after) parts.push(`<div class="report-md md-compact">${mdHtml(after)}</div>`);
    return parts.join("");
  }
  const sliced = sliceJsonObject(s);
  if (sliced.blob) {
    const parsed = coerceJson(sliced.blob);
    if (parsed.ok) {
      parts.push(jsonViewHtml(parsed.value));
      if (sliced.rest) parts.push(`<div class="report-md md-compact">${mdHtml(sliced.rest)}</div>`);
      return parts.join("");
    }
  }
  if (looksLikeJson(s)) return jsonViewHtml(s);
  return `<div class="report-md md-compact">${mdHtml(s)}</div>`;
}

function replaceJsonCodeBlocks(root) {
  if (!root) return;
  root.querySelectorAll("pre > code").forEach(code => {
    const pre = code.parentElement;
    if (!pre || pre.closest("[data-json-view]")) return;
    const text = code.textContent || "";
    const lang = `${code.className || ""} ${pre.className || ""}`;
    if (!/json/i.test(lang) && !looksLikeJson(text)) return;
    const wrap = document.createElement("div");
    wrap.innerHTML = jsonViewHtml(text);
    const view = wrap.firstElementChild;
    if (view) pre.replaceWith(view);
  });
}

function stripJsonPrefix(text) {
  let rest = sliceJsonObject(text).rest;
  rest = rest.replace(/```(?:json)?\s*[\s\S]*?```/gi, "").trim();
  rest = rest.replace(/```(?:json)?[ \t]*\n(?!\s*\{)/gi, "\n").trim();
  rest = rest.replace(/^```(?:json)?\s*/i, "").trim();
  rest = rest.replace(/^(?:#+\s*)?(?:中文\s*)?(?:Markdown\s*)?(?:技术)?解读\s*$/im, "").trim();
  if (/^\s*\{/.test(rest) && /"(?:verdict|findings|confidence)"\s*:/.test(rest.slice(0, 500))) {
    return "";
  }
  return rest;
}

function repairMarkdownTables(src) {
  const lines = String(src || "").split("\n");
  const out = [];
  const isRow = ln => /^\s*\|/.test(ln);
  let i = 0;
  while (i < lines.length) {
    if (!isRow(lines[i])) {
      out.push(lines[i]);
      i += 1;
      continue;
    }
    while (i < lines.length) {
      let row = lines[i];
      if (isRow(row)) {
        while (i + 1 < lines.length && !row.trim().endsWith("|")) {
          i += 1;
          row = `${row.replace(/\s+$/, "")} ${lines[i].trim()}`;
        }
        out.push(row);
        i += 1;
        continue;
      }
      const cont = (lines[i] || "").trim();
      if (!cont || /^#{1,6}\s/.test(cont) || /^```/.test(cont)) break;
      const last = out[out.length - 1];
      const isCont = /^\|/.test(cont) || /\|$/.test(cont) || /^[0-9a-fA-F]{16,}/.test(cont);
      if (isCont && last && last.trim().startsWith("|")) {
        const glue = cont.startsWith("|") ? cont : `${cont}${cont.endsWith("|") ? "" : " |"}`;
        out[out.length - 1] = last.replace(/\|\s*$/, ` ${glue}`);
        i += 1;
        continue;
      }
      break;
    }
  }
  return out.join("\n");
}

function normalizeMdLine(line) {
  return String(line || "")
    .replace(/\r/g, "")
    .replace(/[\u200b\u200c\u200d\ufeff]/g, "")
    .replace(/[–—－﹣]/g, "-")
    .replace(/｜/g, "|");
}

function isGfmTableSep(line) {
  const s = normalizeMdLine(line).trim();
  if (!s.includes("-")) return false;
  return /^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$/.test(s);
}

function isGfmTableRow(line) {
  const s = normalizeMdLine(line).trim();
  if (!s || isGfmTableSep(s)) return false;
  if (/^#{1,6}\s/.test(s) || /^\s*[-*+]\s/.test(s) || /^\s*>/.test(s)) return false;
  return splitGfmTableRow(s).length >= 2 && (s.match(/\|/g) || []).length >= 1;
}

function splitGfmTableRow(line) {
  let s = normalizeMdLine(line).trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  return s.split("|").map(c => c.trim());
}

function mdInline(text) {
  const s = String(text || "");
  if (!s) return "";
  const marked = globalThis.marked;
  if (typeof marked !== "undefined" && typeof marked.parseInline === "function") {
    try { return marked.parseInline(s, { async: false, gfm: true, breaks: false }); } catch { /* ignore */ }
  }
  return esc(s);
}

function cellText(v) {
  const s = String(v == null ? "" : v).trim();
  return s && s !== "—" ? s : "";
}

function colRole(h) {
  const s = String(h || "");
  if (/步骤|序号|^n$|^#$/i.test(s)) return "step";
  if (/位置|阶段|location/i.test(s)) return "loc";
  if (/动作|行为|action/i.test(s)) return "act";
  if (/函数|api/i.test(s) && !/门控/.test(s)) return "fn";
  if (/对象|偏移/i.test(s)) return "obj";
  if (/结果|outcome|result/i.test(s)) return "res";
  if (/证据|级别|确信度|置信/i.test(s)) return "ev";
  if (/旧版|漏洞版|^old$/i.test(s)) return "old";
  if (/新版|修复版|^new$/i.test(s)) return "new";
  if (/^(项目|字段|项)$/.test(s)) return "field";
  return "other";
}

function isChainHeaders(heads) {
  const roles = heads.map(colRole);
  return roles.includes("act") && (roles.includes("step") || roles.includes("loc") || roles.includes("fn"));
}

function isCompareHeaders(heads) {
  const roles = heads.map(colRole);
  return roles.includes("old") && roles.includes("new");
}

function finishSentence(s) {
  const t = String(s || "").replace(/[；，、]+$/g, "").trim();
  if (!t) return "";
  return /[。！？…]$/.test(t) ? t : `${t}。`;
}

function narrativeFromRow(heads, row) {
  const get = role => {
    const i = heads.findIndex(h => colRole(h) === role);
    return i >= 0 ? cellText(row[i]) : "";
  };
  const step = get("step");
  if (isChainHeaders(heads)) {
    const loc = get("loc");
    const act = get("act");
    const fn = get("fn");
    const obj = get("obj");
    const res = get("res");
    const ev = get("ev");
    let text = loc ? `在${loc}，` : "";
    text += act || "";
    const extras = [];
    if (fn) extras.push(`涉及 ${fn}`);
    if (obj) extras.push(`对象/偏移为 ${obj}`);
    if (extras.length) text = finishSentence(text) + extras.join("；");
    text = finishSentence(text);
    if (res) text += `结果：${res.replace(/[。；]+$/g, "")}。`;
    if (ev) text += `【${ev}】`;
    return { step, text: text.replace(/。。+/g, "。") };
  }
  if (isCompareHeaders(heads)) {
    const field = get("field") || cellText(row[0]) || "项";
    const old = get("old") || "—";
    const neu = get("new") || "—";
    const extra = heads.map((h, i) => {
      const role = colRole(h);
      if (role === "field" || role === "old" || role === "new" || role === "step" || i === 0) return "";
      const v = cellText(row[i]);
      return v ? `${h}：${v}` : "";
    }).filter(Boolean);
    let text = `${field}：旧版 ${old}，新版 ${neu}`;
    if (extra.length) text += `；${extra.join("；")}`;
    return { step: "", text: finishSentence(text) };
  }
  const subj = cellText(row[0]);
  const parts = [];
  let ev = "";
  heads.forEach((h, i) => {
    const v = cellText(row[i]);
    if (!v) return;
    const role = colRole(h);
    if (role === "step" || i === 0) return;
    if (role === "ev") { ev = v; return; }
    parts.push(`${h}：${v}`);
  });
  let text = parts.length ? (subj ? `${subj}：${parts.join("，")}` : parts.join("；")) : subj;
  text = finishSentence(text);
  if (ev) text += `【${ev}】`;
  return { step: "", text };
}

function htmlProseFromGfm(headers, rows) {
  const cols = Math.max(headers.length, ...rows.map(r => r.length), 1);
  const pad = cells => {
    const next = cells.slice(0, cols);
    while (next.length < cols) next.push("");
    return next;
  };
  const heads = pad(headers);
  const data = rows.map(pad).filter(r => r.some(c => cellText(c)));
  if (!data.length) return `<p class="report-empty">无</p>`;
  if (cols <= 2) {
    return `<div class="report-prose">${data.map(r => {
      const k = cellText(r[0]) || "项";
      const v = cellText(r[1]) || "—";
      return `<p><strong>${mdInline(k)}</strong>：${mdInline(v)}</p>`;
    }).join("")}</div>`;
  }
  return `<div class="report-prose">${data.map(row => {
    const { step, text } = narrativeFromRow(heads, row);
    return step
      ? `<p>${esc(step)}. ${mdInline(text)}</p>`
      : `<p>${mdInline(text)}</p>`;
  }).join("")}</div>`;
}

function htmlTableFromGfm(headers, rows) {
  return htmlProseFromGfm(headers, rows);
}

function consumeGfmTable(lines, start) {
  if (!isGfmTableRow(lines[start]) || start + 1 >= lines.length) return null;
  const second = lines[start + 1];
  const hasSep = isGfmTableSep(second);
  if (!hasSep && !isGfmTableRow(second)) return null;
  const headers = splitGfmTableRow(lines[start]);
  if (headers.length < 2) return null;
  let i = start + (hasSep ? 2 : 1);
  const rows = [];
  if (!hasSep && isGfmTableRow(second)) {
    rows.push(splitGfmTableRow(second));
    i = start + 2;
  }
  while (i < lines.length && isGfmTableRow(lines[i])) {
    rows.push(splitGfmTableRow(lines[i]));
    i += 1;
  }
  if (!hasSep && !rows.length) return null;
  return { html: htmlTableFromGfm(headers, rows), end: i };
}

function tablePlaceholder(i) {
  return `%%PTBL${i}%%`;
}

function extractGfmTables(src) {
  const lines = String(src || "").split("\n");
  const tables = [];
  const out = [];
  let i = 0;
  let inFence = false;
  while (i < lines.length) {
    const line = lines[i];
    if (/^\s*```/.test(line)) {
      inFence = !inFence;
      out.push(line);
      i += 1;
      continue;
    }
    if (!inFence) {
      const block = consumeGfmTable(lines, i);
      if (block) {
        const id = tables.length;
        tables.push(block.html);
        out.push("", tablePlaceholder(id), "");
        i = block.end;
        continue;
      }
    }
    out.push(line);
    i += 1;
  }
  return { markdown: out.join("\n"), tables };
}

function restoreExtractedTables(html, tables) {
  let out = String(html || "");
  tables.forEach((table, i) => {
    const token = tablePlaceholder(i);
    const escaped = esc(token);
    out = out.replace(new RegExp(`<p>\\s*${token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*</p>`, "g"), table);
    out = out.replace(new RegExp(`<p>\\s*${escaped.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*</p>`, "g"), table);
    out = out.split(token).join(table);
    out = out.split(escaped).join(table);
  });
  return out;
}

function htmlToMdish(inner) {
  return String(inner || "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(?:p|div|h[1-6]|tr)>/gi, "\n")
    .replace(/<code>([\s\S]*?)<\/code>/gi, "`$1`")
    .replace(/<strong>([\s\S]*?)<\/strong>/gi, "**$1**")
    .replace(/<em>([\s\S]*?)<\/em>/gi, "*$1*")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"");
}

function proseFromLoosePipes(text) {
  const lines = String(text || "").split("\n").map(l => l.trim()).filter(Boolean);
  const rows = [];
  for (const line of lines) {
    if (isGfmTableSep(line)) continue;
    if (!line.includes("|")) continue;
    const cells = splitGfmTableRow(line);
    if (cells.length >= 2) rows.push(cells);
  }
  if (rows.length < 2) return "";
  return htmlProseFromGfm(rows[0], rows.slice(1));
}

function salvagePipeTablesInHtml(html) {
  return String(html || "").replace(/<p\b[^>]*>([\s\S]*?)<\/p>/gi, (full, inner) => {
    if (!inner.includes("|")) return full;
    const md = htmlToMdish(inner);
    const { markdown, tables } = extractGfmTables(prepMarkdown(md));
    if (tables.length) {
      const leftover = markdown.replace(/%%PTBL\d+%%/g, "").trim();
      if (!leftover) return tables.join("\n");
      if ((leftover.match(/\|/g) || []).length < 2) {
        return `<p>${mdInline(leftover)}</p>\n${tables.join("\n")}`;
      }
    }
    return proseFromLoosePipes(md) || full;
  });
}

function looksLikePipePara(el) {
  if (!el || el.tagName !== "P" || el.querySelector("table")) return false;
  const t = el.textContent || "";
  return t.includes("|") && (t.match(/\|/g) || []).length >= 1;
}

function salvageTablesInDom(root) {
  if (!root) return;
  const groups = [];
  let cur = [];
  [...root.children].forEach(el => {
    if (looksLikePipePara(el)) cur.push(el);
    else {
      if (cur.length >= 2) groups.push(cur);
      cur = [];
    }
  });
  if (cur.length >= 2) groups.push(cur);
  for (const group of groups) {
    const md = group.map(p => htmlToMdish(p.innerHTML)).join("\n");
    const extracted = extractGfmTables(prepMarkdown(md));
    const html = extracted.tables.length ? extracted.tables.join("") : proseFromLoosePipes(md);
    if (!html) continue;
    const tmp = document.createElement("div");
    tmp.innerHTML = html;
    group[0].replaceWith(...tmp.childNodes);
    group.slice(1).forEach(n => n.remove());
  }
  root.querySelectorAll("p").forEach(p => {
    if (!looksLikePipePara(p) || p.querySelector("table, .report-prose, .report-kv, .report-record")) return;
    const fixed = salvagePipeTablesInHtml(p.outerHTML);
    if (fixed === p.outerHTML) return;
    const tmp = document.createElement("div");
    tmp.innerHTML = fixed;
    p.replaceWith(...tmp.childNodes);
  });
}

function tableElToProse(table) {
  const rows = [...table.querySelectorAll("tr")].map(tr =>
    [...tr.querySelectorAll("th,td")].map(c => (c.textContent || "").trim())
  ).filter(r => r.length);
  if (rows.length < 2) return "";
  const hasHead = table.querySelector("th") || table.querySelector("thead");
  const headers = hasHead ? rows[0] : rows[0].map((_, i) => `字段${i + 1}`);
  const body = hasHead ? rows.slice(1) : rows;
  return body.length ? htmlProseFromGfm(headers, body) : "";
}

function convertTablesToProse(root) {
  if (!root) return;
  root.querySelectorAll("table").forEach(table => {
    const html = tableElToProse(table);
    if (!html) return;
    const tmp = document.createElement("div");
    tmp.innerHTML = html;
    const target = table.closest(".md-scroll, .table-wrap") || table;
    target.replaceWith(...tmp.childNodes);
  });
  const groups = [];
  let cur = [];
  [...root.children].forEach(el => {
    if (looksLikePipePara(el)) cur.push(el);
    else {
      if (cur.length) groups.push(cur);
      cur = [];
    }
  });
  if (cur.length) groups.push(cur);
  for (const group of groups) {
    const md = group.map(p => htmlToMdish(p.innerHTML)).join("\n");
    const html = proseFromLoosePipes(md);
    if (!html) continue;
    const tmp = document.createElement("div");
    tmp.innerHTML = html;
    group[0].replaceWith(...tmp.childNodes);
    group.slice(1).forEach(n => n.remove());
  }
  root.querySelectorAll("pre").forEach(pre => {
    if (pre.closest(".mermaid, .report-mermaid")) return;
    const text = pre.textContent || "";
    if ((text.match(/\|/g) || []).length < 4) return;
    const html = proseFromLoosePipes(text);
    if (!html) return;
    const tmp = document.createElement("div");
    tmp.innerHTML = html;
    pre.replaceWith(...tmp.childNodes);
  });
}

function unwrapTableWraps(root) {
  if (!root) return;
  root.querySelectorAll(".md-scroll, .table-wrap").forEach(wrap => {
    wrap.replaceWith(...wrap.childNodes);
  });
}

function unwrapMarkdownFence(text) {
  let s = String(text || "").replace(/^\uFEFF/, "").trim();
  const open = s.match(/^```(?:markdown|md|gfm)?[ \t]*\n/i);
  if (!open) return s;
  s = s.slice(open[0].length);
  s = s.replace(/\n```[ \t]*\s*$/, "");
  return s.trim();
}

function prepMarkdown(text) {
  let s = unwrapMarkdownFence(stripJsonPrefix(text));
  s = s.replace(/\r/g, "").replace(/\u00a0/g, " ").replace(/｜/g, "|");
  s = s.replace(/^(#{1,6}[^\n]+)\n(?=\s*\|)/gm, "$1\n\n");
  s = s.replace(/([^\n])\n(?=\|[^|\n]+\|)/g, "$1\n\n");
  s = repairMarkdownTables(s);
  return s.trim();
}

function mdHtml(text) {
  const src = prepMarkdown(text);
  if (!src) return "";
  const { markdown, tables } = extractGfmTables(src);
  const marked = globalThis.marked;
  if (typeof marked === "undefined") {
    return restoreExtractedTables(`<pre>${esc(markdown)}</pre>`, tables);
  }
  try {
    const out = marked.parse(markdown, { async: false, gfm: true, breaks: true });
    let html = typeof out === "string" ? out : `<pre>${esc(src)}</pre>`;
    html = restoreExtractedTables(html, tables);
    html = salvagePipeTablesInHtml(html);
    return html;
  } catch {
    return `<pre>${esc(src)}</pre>`;
  }
}

function wrapMdTables(root) {
  if (!root) return;
  root.querySelectorAll("table").forEach(t => {
    const parent = t.parentElement;
    if (!parent || parent.classList.contains("md-scroll") || parent.classList.contains("table-wrap")) return;
    const wrap = document.createElement("div");
    wrap.className = "md-scroll table-wrap";
    parent.insertBefore(wrap, t);
    wrap.appendChild(t);
  });
}

async function hydrateMarkdown(root) {
  if (!root) return;
  await ensureMarkdownLibs();
  configureMarked();
  wrapMdTables(root);
  replaceJsonCodeBlocks(root);
  root.querySelectorAll("pre.mermaid[data-m], pre.mermaid[data-m], pre.mermaid[data-src], pre.mermaid[data-src]").forEach(el => {
    if (el.textContent.trim()) return;
    const packed = el.getAttribute("data-src") || el.getAttribute("data-src") || el.getAttribute("data-m") || el.getAttribute("data-m") || "";
    try { el.textContent = decodeURIComponent(packed); } catch { el.textContent = packed; }
  });
  liftMermaidBlocks(root);
  const detached = !root.isConnected;
  if (detached) {
    root.setAttribute("data-export-scratch", "1");
    root.style.cssText = "position:fixed;left:-9999px;top:0;width:880px;visibility:hidden;";
    document.body.appendChild(root);
  }
  const hiddenPanel = !detached && root.classList.contains("modal-panel") && !root.classList.contains("active");
  try {
    if (!hiddenPanel) {
      await renderMermaidIn(root);
      typesetMath(root);
    }
  } finally {
    if (detached && root.parentNode) {
      root.remove();
      root.removeAttribute("data-export-scratch");
      root.style.cssText = "";
    }
  }
}

function setRing(job) {
  const ring = $("#detect-ring");
  const fg = $("#ring-fg");
  if (!ring || !fg) return;
  const circ = 2 * Math.PI * 40;
  const v = caseVerdict(job);
  ring.classList.remove("ok", "err", "run", "warn");
  ring.classList.add(v.cls);
  let offset = circ;
  if (v.cls === "ok") offset = 0;
  else if (v.cls === "err") offset = circ * 0.22;
  else if (v.cls === "warn") offset = circ * 0.4;
  else offset = circ * 0.55;
  $("#ring-value").textContent = v.value;
  $("#ring-sub").textContent = v.sub;
  fg.style.strokeDasharray = String(circ);
  fg.style.strokeDashoffset = String(offset);
}

let graphSelectedId = null;
let lastCommunityJob = null;

const GRAPH_NODES = [
  { id: "PEExtractor", name: "PE 提取", label: "PEExtractor", kind: "tool" },
  { id: "SymbolDiffer", name: "符号 Diff", label: "SymbolDiffer", kind: "tool" },
  { id: "FeatureTracer", name: "Feature 跟踪", label: "FeatureTracer", kind: "tool" },
  { id: "SizeTimeline", name: "尺寸时间线", label: "SizeTimeline", kind: "tool" },
  { id: "ByteDiffer", name: "字节 Diff", label: "ByteDiffer", kind: "tool" },
  { id: "DisasmWorker", name: "热点反汇编", label: "DisasmWorker", kind: "tool" },
  { id: "CfgDiffer", name: "CFG Diff", label: "CfgDiffer", kind: "tool" },
  { id: "VerifyPack", name: "验证包", label: "VerifyPack", kind: "tool" },
  { id: "AgentRouter", name: "专家编制", label: "AgentRouter", kind: "tool" },
  { id: "PEAnalyst", name: "版本归因", label: "PEAnalyst", kind: "agent" },
  { id: "SymbolAnalyst", name: "补丁定位", label: "SymbolAnalyst", kind: "agent" },
  { id: "DisasmAnalyst", name: "锁 / 释放", label: "DisasmAnalyst", kind: "agent" },
  { id: "FeatureAnalyst", name: "启用位", label: "FeatureAnalyst", kind: "agent" },
  { id: "ControlPathAnalyst", name: "对照排除", label: "ControlPathAnalyst", kind: "agent" },
  { id: "RootCauseAnalyst", name: "根因综合", label: "RootCauseAnalyst", kind: "agent" },
  { id: "HuntPrep", name: "狩猎准备", label: "HuntPrep", kind: "tool" },
  { id: "DetectionAnalyst", name: "IOC / 检测", label: "DetectionAnalyst", kind: "agent" },
  { id: "ThreatIntelAnalyst", name: "在野利用", label: "ThreatIntelAnalyst", kind: "agent" },
  { id: "BypassAnalyst", name: "完整性狩猎", label: "BypassAnalyst", kind: "agent" },
  { id: "FeatureOffAnalyst", name: "Feature 关闭", label: "FeatureOffAnalyst", kind: "agent" },
  { id: "ResidualVulnAnalyst", name: "同类残留", label: "ResidualVulnAnalyst", kind: "agent" },
  { id: "AliasSiteAnalyst", name: "调用点覆盖", label: "AliasSiteAnalyst", kind: "agent" },
  { id: "ReportWriter", name: "生成报告", label: "ReportWriter", kind: "agent" },
];

const GRAPH_LANES = [
  {
    id: "collect",
    title: "证据采集",
    tag: "Tool · 并行采集",
    rows: [
      ["PEExtractor", "SymbolDiffer"],
      ["FeatureTracer", "ByteDiffer"],
      ["SizeTimeline", "DisasmWorker", "CfgDiffer"],
    ],
  },
  {
    id: "expert",
    title: "专家解读",
    tag: "Agent · 4 并行",
    rows: [["AgentRouter"], ["PEAnalyst", "SymbolAnalyst", "DisasmAnalyst", "FeatureAnalyst"]],
  },
  {
    id: "synth",
    title: "综合输出",
    tag: "Hunt · 独立流水线",
    rows: [
      ["ControlPathAnalyst", "RootCauseAnalyst"],
      ["HuntPrep"],
      ["DetectionAnalyst", "ThreatIntelAnalyst"],
      ["BypassAnalyst", "FeatureOffAnalyst"],
      ["ResidualVulnAnalyst", "AliasSiteAnalyst"],
      ["ReportWriter"],
    ],
  },
];

const GRAPH_NOTE_KEY = {
  PEAnalyst: "pe",
  SymbolAnalyst: "symbol",
  DisasmAnalyst: "disasm",
  FeatureAnalyst: "feature",
  ControlPathAnalyst: "control",
  RootCauseAnalyst: "root_cause",
  DetectionAnalyst: "detection",
  ThreatIntelAnalyst: "threat",
  BypassAnalyst: "bypass",
  ResidualVulnAnalyst: "residual",
  AliasSiteAnalyst: "alias",
  FeatureOffAnalyst: "feature_off",
};

const GRAPH_PANEL = {
  PEExtractor: "summary",
  SymbolDiffer: "symbols",
  SizeTimeline: "timeline",
  ByteDiffer: "bytediff",
  DisasmWorker: "disasm",
  CfgDiffer: "cfg",
  FeatureTracer: "feature",
  VerifyPack: "verify",
  ControlPathAnalyst: "control",
  DetectionAnalyst: "ioc",
  ThreatIntelAnalyst: "threat",
  BypassAnalyst: "bypass",
  ResidualVulnAnalyst: "residual",
  AliasSiteAnalyst: "residual",
  FeatureOffAnalyst: "bypass",
  HuntPrep: "residual",
  ReportWriter: "summary",
  RootCauseAnalyst: "chain",
};

const GRAPH_STATUS_TEXT = { done: "完成", run: "运行", skip: "跳过", err: "失败", wait: "等待" };

function graphNode(id) {
  return GRAPH_NODES.find(n => n.id === id);
}

function tracesByAgent(traces) {
  const map = new Map();
  for (const t of traces || []) {
    const id = t.agent;
    if (!id) continue;
    const list = map.get(id) || [];
    list.push(t);
    map.set(id, list);
  }
  return map;
}

function nodeStatus(id, job, byAgent) {
  const traces = byAgent.get(id) || [];
  const last = traces[traces.length - 1];
  const msg = last?.message || "";
  if (last?.role === "error" || /失败/.test(msg)) return "err";
  if (/跳过|未启用|缺少 API/.test(msg)) return "skip";
  if (last) return "done";
  const running = job.status === "running" || job.status === "pending";
  if (!running) return "wait";
  const doneIds = new Set([...byAgent.keys()]);
  const firstPending = GRAPH_NODES.find(n => !doneIds.has(n.id));
  return firstPending?.id === id ? "run" : "wait";
}

function fmtBytes(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v <= 0) return "";
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${Math.round(v / 1024)} KB`;
  return `${(v / 1024 / 1024).toFixed(1)} MB`;
}

function nodeBlurb(id, job) {
  const art = job.result?.artifacts || {};
  switch (id) {
    case "PEExtractor": {
      const o = art.old_pe || {};
      const n = art.new_pe || {};
      return [o.machine, fmtBytes(o.size), n.size && `→ ${fmtBytes(n.size)}`].filter(Boolean).join(" · ");
    }
    case "SymbolDiffer": {
      const s = art.symbol_diff || {};
      return `Δ${(s.functions_resized || []).length} · +${(s.symbols_added || []).length}/−${(s.symbols_removed || []).length}`;
    }
    case "SizeTimeline": {
      const tl = art.size_timeline || {};
      return `${(tl.labels || []).length} 构建 · ${(tl.rows || []).length} 函数`;
    }
    case "ByteDiffer": {
      const bd = art.byte_diff || {};
      return `${bd.total_bytes ?? "—"} B · ${bd.functions_with_byte_changes ?? "—"} 函数`;
    }
    case "DisasmWorker":
      return `${(art.disassembly || []).length} 个热点`;
    case "CfgDiffer":
      return `${((art.cfg_diff || {}).functions || []).length} 个函数`;
    case "FeatureTracer":
      return `${((art.feature_trace || {}).features || []).length} 组 Feature`;
    case "VerifyPack": {
      const vp = art.verify_pack || {};
      return vp.driver ? `${vp.driver} · Verifier / WinDbg` : `${(vp.files || []).length || 4} 个文件`;
    }
    case "DetectionAnalyst": {
      const pack = art.ioc_pack || {};
      const n = (pack.identity || []).filter(x => x.sha256).length;
      return pack.has_detection ? `检测方法 · ${n} 哈希` : (n ? `${n} 个样本哈希` : "");
    }
    case "ThreatIntelAnalyst": {
      const t = art.threat_intel || {};
      const n = (t.search_hits || []).length;
      if (n) return `检索 ${n} 条`;
      if (t.in_kev) return "CISA KEV · 已知在野";
      if (t.status === "not_in_kev") return "未列入 KEV";
      if (t.status === "no_cve") return "无 CVE";
      if (t.status === "lookup_failed") return "查询失败";
      return t.cve || "";
    }
    case "HuntPrep": {
      const h = art.hunt_brief || {};
      const n = (h.candidates || []).length;
      const hi = (h.high_priority || []).length;
      const clone = (h.clone_sites || []).length;
      const gaps = (h.cfg_gaps || []).length;
      return n ? `未改函数 ${n}${hi ? ` · 高优先级 ${hi}` : ""}${clone ? ` · 克隆 ${clone}` : ""}${gaps ? ` · CFG缺口 ${gaps}` : ""}` : "";
    }
    case "BypassAnalyst": {
      const p = art.bypass_pack || {};
      const labels = { closed: "已闭合", partial: "部分闭合", bypassable: "有绕过面", unknown: "待评估" };
      const n = (p.findings || []).length;
      return p.verdict ? `${labels[p.verdict] || p.verdict}${n ? ` · ${n} 条` : ""}` : "";
    }
    case "ResidualVulnAnalyst": {
      const p = art.residual_pack || {};
      const labels = { none: "未发现", suspects: "有嫌疑", likely: "可能残留", unknown: "待评估" };
      const n = (p.findings || []).length;
      return p.verdict ? `${labels[p.verdict] || p.verdict}${n ? ` · ${n} 条` : ""}` : "";
    }
    case "AliasSiteAnalyst": {
      const p = art.alias_pack || {};
      const labels = { none: "已打全", suspects: "有未改调用点", likely: "覆盖不全", unknown: "待评估" };
      const n = (p.findings || []).length;
      return p.verdict ? `${labels[p.verdict] || p.verdict}${n ? ` · ${n} 条` : ""}` : "";
    }
    case "FeatureOffAnalyst": {
      const p = art.feature_off_pack || {};
      const labels = { closed: "关闭亦防护", partial: "部分门控", bypassable: "关闭回旧路径", unknown: "待评估" };
      const n = (p.findings || []).length;
      return p.verdict ? `${labels[p.verdict] || p.verdict}${n ? ` · ${n} 条` : ""}` : "";
    }
    case "ReportWriter":
      return art.llm_report ? `${art.llm_report.length} 字` : (art.llm_error ? "生成失败" : "");
    case "AgentRouter": {
      const mode = art.routing_mode === "manual" ? "手动" : "自动";
      const n = Array.isArray(art.routed_agents) ? art.routed_agents.length : 0;
      const skipped = Object.keys(art.skip_reasons || {}).length;
      if (art.routing_mode === "manual") return `${mode} · 按勾选`;
      return skipped ? `${mode} · ${n} 个专家 · 跳过 ${skipped}` : `${mode} · ${n} 个专家`;
    }
    default: {
      const why = (art.skip_reasons || {})[id];
      return why || "";
    }
  }
}

function packSummaryHtml(title, pack, extraRows) {
  if (!pack || typeof pack !== "object") return "";
  const rows = [
    pack.verdict ? ["结论", pack.verdict] : null,
    pack.confidence ? ["置信度", pack.confidence] : null,
    pack.summary ? ["摘要", pack.summary] : null,
    Array.isArray(pack.findings) && pack.findings.length ? ["条目", `${pack.findings.length} 条`] : null,
    ...(extraRows || []),
  ].filter(Boolean);
  if (!rows.length) return "";
  const notes = pack.notes || "";
  return `<p class="card-title">${esc(title)}</p>
    <dl class="review-kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join("")}</dl>
    ${notes ? mixedJsonMarkdownHtml(notes) : ""}
    <details class="json-raw"><summary>原始 JSON</summary>${jsonViewHtml(pack)}</details>`;
}

function specialistNoteHtml(id, job) {
  const art = job.result?.artifacts || {};
  const raw = (art.agent_notes || {})[GRAPH_NOTE_KEY[id]] || "";
  if (raw && !/^（/.test(String(raw).trim())) {
    return `<p class="card-title">专家输出</p>${mixedJsonMarkdownHtml(raw)}`;
  }
  if (id === "ReportWriter" && art.llm_report) {
    return `<p class="card-title">报告预览</p><div class="report-md md-compact">${mdHtml(String(art.llm_report).slice(0, 4000))}</div>`;
  }
  if (id === "DetectionAnalyst" && art.ioc_pack) {
    const p = art.ioc_pack;
    return packSummaryHtml("IOC 摘要", {
      summary: [p.cve, p.component].filter(Boolean).join(" · "),
      findings: p.identity || [],
      notes: p.detection_notes || "",
    }, p.cve ? [["CVE", p.cve]] : []);
  }
  if (id === "ThreatIntelAnalyst" && art.threat_intel) {
    const p = art.threat_intel;
    return packSummaryHtml("公开情报", {
      verdict: p.status,
      summary: p.summary,
      notes: p.threat_notes || "",
    }, [
      p.cve ? ["CVE", p.cve] : null,
      p.in_kev != null ? ["CISA KEV", p.in_kev ? "是" : "否"] : null,
    ].filter(Boolean));
  }
  if (id === "BypassAnalyst") return packSummaryHtml("绕过面", art.bypass_pack);
  if (id === "ResidualVulnAnalyst") return packSummaryHtml("残留", art.residual_pack);
  if (id === "AliasSiteAnalyst") return packSummaryHtml("调用点覆盖", art.alias_pack);
  if (id === "FeatureOffAnalyst") return packSummaryHtml("Feature 关闭路径", art.feature_off_pack);
  if (id === "HuntPrep" && art.hunt_brief) {
    const h = art.hunt_brief;
    const n = (h.candidates || []).length;
    return packSummaryHtml("狩猎简报", {
      summary: h.goal || "",
      findings: h.candidates || [],
    }, [
      h.high_priority != null ? ["高优先级", String(h.high_priority)] : null,
      n ? ["候选", `${n} 个`] : null,
    ].filter(Boolean));
  }
  return "";
}

function nodeDetailHtml(id, job) {
  const def = graphNode(id);
  if (!def) return "";
  const art = job.result?.artifacts || {};
  const traces = (art.agent_traces || []).filter(t => t.agent === id);
  const last = traces[traces.length - 1];
  const blurb = nodeBlurb(id, job);
  const status = nodeStatus(id, job, tracesByAgent(art.agent_traces));
  const statusText = { done: "已完成", run: "进行中", skip: "已跳过", err: "失败", wait: "等待" }[status] || status;
  const why = (art.skip_reasons || {})[id];
  const body = last?.message || why || (status === "wait" ? "该节点尚未执行。" : "");
  const toolLines = traces.filter(t => t.role === "tool").map(t => t.message).filter(Boolean);
  const toolsBlock = toolLines.length
    ? `<p class="card-title">工具调用</p><pre class="note-pre">${esc(toolLines.join("\n"))}</pre>`
    : "";
  const noteBlock = specialistNoteHtml(id, job);
  const pr = art.patch_resolve;
  const extra = id === "PEExtractor" && pr
    ? `<p class="hint">自动匹配：${esc(pr.old_file)} ${esc(pr.old_version)} → ${esc(pr.new_version)}</p>`
    : "";
  return `
    <header>
      <div>
        <p class="eyebrow">${def.kind === "agent" ? "LLM Agent" : "Tool"}</p>
        <h4>${esc(def.name)}</h4>
        <p class="hint" style="margin:0.25rem 0 0">${esc(def.label)}</p>
      </div>
      <button type="button" class="icon-btn" data-close-pop aria-label="关闭">×</button>
    </header>
    <div class="pop-meta">
      <span class="tag-pill ${status === "done" ? "ok" : status === "err" ? "err" : "warn"}">${esc(statusText)}</span>
      ${last?.at ? `<span class="tag-pill">${esc(fmtRel(last.at))}</span>` : ""}
    </div>
    ${extra}
    ${blurb ? `<p class="hint">${esc(blurb)}</p>` : ""}
    <p class="pop-body">${esc(body)}</p>
    ${GRAPH_PANEL[id] ? `<p><button type="button" class="btn ghost" data-goto-panel="${GRAPH_PANEL[id]}">打开页签</button></p>` : ""}
    ${toolsBlock}
    ${noteBlock}
  `;
}

function graphEmptyDetail() {
  return `<p class="pipe-detail-empty"><strong>点击节点查看输出</strong><span>HuntPrep 用调用图扩候选后，Bypass / FeatureOff / Residual / AliasSite 四路独立狩猎，发现汇入 §18 / §19。</span></p>`;
}

function closeGraphPop() {
  graphSelectedId = null;
  $$(".gnode.selected").forEach(n => n.classList.remove("selected"));
  const pop = $("#graph-pop");
  if (pop) pop.innerHTML = graphEmptyDetail();
}

function openGraphPop(id, { toggle = false } = {}) {
  const job = lastCommunityJob;
  if (!job) return;
  if (toggle && graphSelectedId === id) {
    closeGraphPop();
    return;
  }
  graphSelectedId = id;
  $$(".gnode").forEach(n => n.classList.toggle("selected", n.dataset.node === id));
  const pop = $("#graph-pop");
  if (pop) pop.innerHTML = nodeDetailHtml(id, job);
}

function paintCommunity(job) {
  lastCommunityJob = job;
  const keep = graphSelectedId;
  $("#panel-community").innerHTML = renderCommunity(job);
  if (keep) openGraphPop(keep);
}

function renderNodeButton(id, job, byAgent) {
  const n = graphNode(id);
  const st = nodeStatus(id, job, byAgent);
  const metric = nodeBlurb(id, job);
  return `<button type="button" class="gnode ${n.kind} ${st}" data-node="${n.id}" title="${esc(n.label)}">
    <span class="gst">${esc(GRAPH_STATUS_TEXT[st])}</span>
    <span class="gname">${esc(n.name)}</span>
    <span class="gsub">${esc(n.label)}</span>
    ${metric ? `<span class="gmetric">${esc(metric)}</span>` : ""}
  </button>`;
}

function renderLane(lane, job, byAgent) {
  const rows = lane.rows.map((ids, i) => {
    const parts = [];
    ids.forEach((id, j) => {
      if (j) parts.push('<span class="pipe-arrow" aria-hidden="true"></span>');
      parts.push(renderNodeButton(id, job, byAgent));
    });
    const join = i < lane.rows.length - 1 ? '<div class="pipe-join"><span>↓</span></div>' : "";
    return `<div class="pipe-row">${parts.join("")}</div>${join}`;
  }).join("");
  return `<section class="pipe-lane">
    <div class="pipe-lane-head">
      <h4>${esc(lane.title)}</h4>
      <span class="lane-tag">${esc(lane.tag)}</span>
    </div>
    ${rows}
  </section>`;
}

function fileBase(p) {
  return String(p || "").split(/[/\\]/).pop() || "";
}

function mdLite(text) {
  return esc(text).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
}

function firstProse(text, maxChars = 620) {
  const paras = String(text || "").split(/\n\s*\n/).map(p => p.trim()).filter(p => {
    if (!p) return false;
    if (/^[-*|]>/.test(p) && p.includes("|")) return false;
    if (p.startsWith("|") || p.startsWith("#") || p.startsWith("##")) return false;
    if (/^[-*]{3,}$/.test(p)) return false;
    if (/^目录/.test(p)) return false;
    return true;
  });
  const out = [];
  let n = 0;
  for (const p of paras) {
    const clean = p.replace(/^>\s*/gm, "").trim();
    if (!clean) continue;
    if (n + clean.length > maxChars && out.length) break;
    out.push(clean);
    n += clean.length;
    if (out.length >= 3 && n > 360) break;
  }
  return out.join("\n\n");
}

function extractRootOneLiner(art) {
  const ready = (art.conclusions || {}).root_one_liner || (art.conclusions || {}).root_cause_line;
  if (ready) return String(ready).trim();
  const blob = `${(art.agent_notes || {}).root_cause || ""}\n${art.llm_report || ""}`;
  const m = blob.match(/根因一句话[^\n]*[：:]\s*(.+)/);
  if (m) return m[1].replace(/[*`]/g, "").trim().slice(0, 240);
  return firstProse(blob, 180);
}

function extractPatchCut(art) {
  const ready = (art.conclusions || {}).patch_cut;
  if (ready) return String(ready).trim();
  const blob = `${(art.agent_notes || {}).root_cause || ""}\n${art.llm_report || ""}`;
  const m = blob.match(/补丁切断点[^\n]*[：:]\s*(.+)/) || blob.match(/切断步骤[^\n]*[：:]\s*(.+)/);
  if (m) return m[1].replace(/[*`]/g, "").trim().slice(0, 240);
  return "";
}

function qualityBanner(art) {
  const q = art.evidence_quality || art.quality || {};
  const level = q.level || "";
  if (!level || level === "ok") return "";
  const cls = level === "unreliable" ? "bad" : "";
  const flags = q.flags || [];
  const retryPdb = flags.includes("no_pdb")
    ? `<button type="button" class="btn ghost" id="retry-pdb">重试 PDB</button>`
    : "";
  return `<div class="quality-banner ${cls}"><strong>${esc(q.label || "结论不可靠")}</strong>${esc(q.detail || "符号或热点覆盖不完整，请谨慎采信。")}${retryPdb}</div>`;
}

function hotspotPickerHtml(art, job) {
  const plan = art.hotspot_plan || {};
  const uncovered = plan.uncovered || [];
  const selected = art.hotspot_names || plan.selected || [];
  if (!selected.length && !uncovered.length) return "";
  const done = selected.slice(0, 16).map(n => `<li>${fnLink(n)}</li>`).join("");
  const miss = uncovered.slice(0, 24).map(n =>
    `<li><label><input type="checkbox" name="extra-hot" value="${esc(n)}"/> ${fnLink(n)}</label></li>`
  ).join("");
  const running = job.status === "running" || job.status === "pending";
  const resume = (job.status === "failed" || job.status === "cancelled")
    ? `<button type="button" class="btn ghost" id="resume-job">从断点继续</button>` : "";
  return `<div class="hotspot-box">
    <p class="card-title">热点覆盖</p>
    <p class="hint">已反汇编 ${selected.length} 个${uncovered.length ? `，未覆盖 ${uncovered.length} 个` : ""}。可勾选或输入函数名后只重跑反汇编 / CFG / 专家。</p>
    ${done ? `<ul>${done}</ul>` : ""}
    ${miss ? `<ul>${miss}</ul>` : ""}
    <p><input type="text" id="extra-hot-input" placeholder="额外函数名，逗号分隔" style="width:min(28rem,100%)" ${running ? "disabled" : ""}/></p>
    <button type="button" class="btn ghost" id="rerun-hotspots" ${running ? "disabled" : ""}>加选并重跑尾部</button>
    ${resume}
  </div>`;
}

function extractExecSummary(art) {
  const report = art.llm_report || "";
  const root = (art.agent_notes || {}).root_cause || "";
  const sources = [report, root];
  for (const src of sources) {
    const m = src.match(/^#{1,3}\s*(?:\d+\.\s*)?执行摘要[^\n]*\n([\s\S]*?)(?=^#{1,3}\s|\s*$)/m);
    if (m && m[1].trim()) return firstProse(m[1].trim());
  }
  const oneLiner = report.match(/漏洞链一句话[^\n]*[：:]\s*(.+)/);
  if (oneLiner) return oneLiner[1].trim();
  if (root) return firstProse(root, 480);
  return "";
}

function extractVulnType(art) {
  const blob = `${art.llm_report || ""}\n${(art.agent_notes || {}).root_cause || ""}`;
  const m = blob.match(/\*\*漏洞类型\*\*[：:]\s*([^\n*]+)/)
    || blob.match(/漏洞类型[：:*|\s]+([^\n|]+)/);
  if (m) return m[1].replace(/[*`]/g, "").trim().slice(0, 80);
  const hit = blob.match(/(竞态[^\n。]{0,24}(?:UAF|TOCTOU|释放后使用)?|Use-After-Free|UAF|TOCTOU|整数溢出|缓冲区溢出)/i);
  return hit ? hit[0].replace(/[*`]/g, "").trim().slice(0, 80) : "";
}

function caseVerdict(job) {
  const art = job?.result?.artifacts || {};
  const st = job?.status || "";
  if (st === "failed" || st === "cancelled") {
    return { cls: "err", value: "失败", sub: "待继续" };
  }
  if (st === "running" || st === "pending") {
    return { cls: "run", value: "分析", sub: statusLabel(st) };
  }
  const kev = !!(art.threat_intel?.in_kev || job?.in_kev);
  const bypass = String(art.bypass_pack?.verdict || job?.bypass_verdict || "");
  const residual = String(art.residual_pack?.verdict || job?.residual_verdict || "");
  if (kev) return { cls: "err", value: "在野", sub: "CISA KEV" };
  if (bypass === "bypassable") return { cls: "err", value: "绕过", sub: "补丁未闭合" };
  if (residual === "likely") return { cls: "err", value: "残留", sub: "同类缺陷" };
  if (bypass === "partial" || residual === "suspects") {
    return { cls: "warn", value: "部分", sub: bypass === "partial" ? "部分闭合" : "有嫌疑" };
  }
  if (bypass === "closed") return { cls: "ok", value: "闭合", sub: "主路径已切断" };
  if (st === "completed") return { cls: "ok", value: "完成", sub: "待评估绕过" };
  return { cls: "run", value: "—", sub: "状态" };
}

function caseAction(job, art) {
  const st = job?.status || "";
  if (st === "running" || st === "pending") {
    return { tone: "run", title: "等待分析完成", detail: "工具与专家跑完后，这里会给出检测与加急建议。" };
  }
  if (st === "failed" || st === "cancelled") {
    return { tone: "err", title: "从断点继续", detail: job.error || "分析中断，可继续以补全结论。" };
  }
  const kev = !!(art.threat_intel?.in_kev || job.in_kev);
  const bypass = String(art.bypass_pack?.verdict || job.bypass_verdict || "");
  const residual = String(art.residual_pack?.verdict || job.residual_verdict || "");
  if (kev) {
    return { tone: "err", title: "紧急：下发检测", detail: "已列入 CISA KEV。优先资产清点、狩猎线索和补丁部署核验。" };
  }
  if (bypass === "bypassable") {
    return { tone: "err", title: "紧急：补检测并复核补丁", detail: "主修复路径可绕过。不要只依赖版本号，按 IOC 页的行为线索狩猎。" };
  }
  if (residual === "likely") {
    return { tone: "err", title: "复查残留函数", detail: "同类缺陷可能仍在未改函数中。对照残留页签决定是否加规则。" };
  }
  if (bypass === "partial" || residual === "suspects") {
    return { tone: "warn", title: "观察并补检测", detail: "补丁未完全闭合或有同类嫌疑。建议下发狩猎，不必按 KEV 加急。" };
  }
  if (bypass === "closed") {
    return { tone: "ok", title: "可按常规跟踪", detail: "主路径已切断。仍应用哈希做资产清点，确认修复版已落地。" };
  }
  return { tone: "", title: "阅读检测要点", detail: "先看 IOC / 检测方法，再决定是否展开取证。" };
}

function renderBriefing(job) {
  const art = job.result?.artifacts || {};
  const peOld = art.old_pe || {};
  const peNew = art.new_pe || {};
  const pr = art.patch_resolve || {};
  const sym = art.symbol_diff || {};
  const resized = [...(sym.functions_resized || [])].sort((a, b) => Math.abs(b.delta || 0) - Math.abs(a.delta || 0));
  const features = (art.feature_trace || {}).features || [];
  const chain = extractChainClient(art);
  const summary = extractExecSummary(art);
  const vulnType = extractVulnType(art);
  const component = pr.old_file || fileBase(peOld.path) || job.title || "驱动样本";
  const verOld = pr.old_version || peOld.file_version || job.old_label || "漏洞版";
  const verNew = pr.new_version || peNew.file_version || job.new_label || "修复版";
  const running = job.status === "running" || job.status === "pending";

  const facts = [
    ["组件", component],
    ["版本", `${verOld} → ${verNew}`],
    ["架构", peOld.machine || peNew.machine || "—"],
    ["尺寸变化", String(resized.length)],
    ["Feature", String(features.length || (sym.feature_symbols_added || []).length || 0)],
  ];
  if (vulnType) facts.splice(3, 0, ["类型", vulnType]);
  if (chain.present) facts.push(["漏洞链", `${(chain.steps || []).length} 步`]);
  const ioc = art.ioc_pack || {};
  const hashN = (ioc.identity || []).filter(x => x.sha256).length;
  if (hashN) facts.push(["IOC", `${hashN} 哈希`]);
  const threat = art.threat_intel || {};
  if (threat.in_kev) facts.push(["在野利用", "CISA KEV 已确认"]);
  else if ((threat.search_hits || []).length) facts.push(["在野利用", `检索 ${(threat.search_hits || []).length} 条`]);
  else if (threat.status === "not_in_kev") facts.push(["在野利用", "未发现公开报道"]);
  else if (threat.status === "no_cve") facts.push(["在野利用", "无 CVE"]);
  const bypass = art.bypass_pack || {};
  if (bypass.verdict && bypass.verdict !== "unknown") {
    const residualN = (bypass.findings || []).filter(f => f.status === "residual").length;
    const label = { closed: "已闭合", partial: "部分闭合", bypassable: "有绕过面" }[bypass.verdict] || bypass.verdict;
    facts.push(["绕过面", residualN ? `${label}（残留 ${residualN}）` : label]);
  }
  const residual = art.residual_pack || {};
  if (residual.verdict && residual.verdict !== "unknown") {
    facts.push(["残留漏洞", (RESIDUAL_META[residual.verdict] || {}).mark || residual.verdict]);
  }

  const hot = resized.slice(0, 5).map(f => {
    const d = f.delta || 0;
    const cls = d >= 0 ? "delta-pos" : "delta-neg";
    return `<li>${fnLink(f.name)} <span class="${cls}">${d >= 0 ? "+" : ""}${d}</span></li>`;
  }).join("");

  let body = "";
  if (summary) body = mdLite(summary).replace(/\n\n/g, "</p><p>");
  else if (running) body = "分析进行中。工具节点完成后会出现函数尺寸与热点；LLM 报告生成后会补上根因总结。";
  else if (art.llm_error) body = `尚未生成可读总结：${art.llm_error}`;
  else if (job.error) body = job.error;
  else body = "工具阶段已完成。配置 LLM 并重新生成报告后，这里会显示执行摘要与根因一句话。";

  return `<section class="brief-card">
    <div class="brief-head">
      <div>
        <h3>分析总结</h3>
        <p class="brief-kicker">${running ? "进行中 · 以下为已确认事实" : "不读长报告也可先看结论"}</p>
      </div>
      <div class="brief-actions">
        ${chain.present ? `<button type="button" class="btn ghost" data-goto-panel="chain">漏洞链</button>` : ""}
        <button type="button" class="btn ghost" data-goto-panel="ioc">IOC / 检测</button>
        <button type="button" class="btn ghost" data-goto-panel="threat">在野利用</button>
        <button type="button" class="btn ghost" data-goto-panel="bypass">绕过面</button>
        <button type="button" class="btn ghost" data-goto-panel="residual">残留漏洞</button>
        <button type="button" class="btn ghost" data-goto-panel="control">对照</button>
        <button type="button" class="btn ghost" data-open-export="1">导出报告</button>
      </div>
    </div>
    <div class="brief-facts">
      ${facts.map(([k, v]) => `<div class="brief-fact"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join("")}
    </div>
    ${qualityBanner(art)}
    <div class="conclude-grid">
      <div class="conclude-card"><span>根因一句话</span><p>${esc(extractRootOneLiner(art) || "尚无根因总结")}</p></div>
      <div class="conclude-card"><span>补丁切断点</span><p>${esc(extractPatchCut(art) || "尚无切断点")}</p></div>
    </div>
    <div class="brief-body"><p>${body}</p></div>
    ${hot ? `<div class="brief-hot"><p class="card-title">尺寸变化最大</p><ul>${hot}</ul></div>` : ""}
    ${hotspotPickerHtml(art, job)}
  </section>`;
}

function iocFromJob(job) {
  const art = job?.result?.artifacts || {};
  const peOld = art.old_pe || {};
  const peNew = art.new_pe || {};
  const pr = art.patch_resolve || {};
  const chain = extractChainClient(art);
  const user = [];
  const kernel = [];
  for (const st of chain.steps || []) {
    for (const a of st.apis || []) {
      if (/^(socket|bind|listen|accept|connect|closesocket|WSA|DeviceIoControl|CreateFile)/i.test(a)) user.push(a);
      else kernel.push(a);
    }
  }
  const synthesized = {
    cve: (job.title || "").match(/CVE-\d{4}-\d+/i)?.[0] || pr.cve || "",
    component: pr.old_file || peOld.original_filename || "",
    kbs: pr.matched_kbs || pr.kbs || [],
    identity: [
      { role: "vulnerable", filename: peOld.original_filename, file_version: pr.old_version || peOld.file_version, machine: peOld.machine, size: peOld.size, timestamp_utc: peOld.timestamp_utc, sha256: peOld.sha256, md5: peOld.md5, sha1: peOld.sha1, pdb_guid: pdbGuid(peOld) },
      { role: "patched", filename: peNew.original_filename, file_version: pr.new_version || peNew.file_version, machine: peNew.machine, size: peNew.size, timestamp_utc: peNew.timestamp_utc, sha256: peNew.sha256, md5: peNew.md5, sha1: peNew.sha1, pdb_guid: pdbGuid(peNew) },
      ...(art.mid_pe && (art.mid_pe.sha256 || art.mid_pe.original_filename)
        ? [{ role: "earlier", filename: art.mid_pe.original_filename, file_version: art.mid_pe.file_version, machine: art.mid_pe.machine, size: art.mid_pe.size, timestamp_utc: art.mid_pe.timestamp_utc, sha256: art.mid_pe.sha256, md5: art.mid_pe.md5, sha1: art.mid_pe.sha1, pdb_guid: pdbGuid(art.mid_pe) }]
        : []),
    ],
    functions: (art.symbol_diff?.functions_resized || []).slice(0, 12),
    features: (art.feature_trace?.features || []).map(f => ({
      feature_id: f.feature_id,
      featureState_rva: f.featureState_rva,
      on_disk_dword: f.on_disk_dword,
      gated_functions: (f.xrefs || []).map(x => x.in_function).filter(Boolean),
    })),
    apis: { user_mode: [...new Set(user)], kernel: [...new Set(kernel)] },
    hunts: (chain.steps || []).map(st => ({ n: st.n, location: st.location, apis: st.apis, action: st.action || st.detail })),
    detection_notes: (art.agent_notes || {}).detection || "",
    has_detection: !!(art.agent_notes || {}).detection && !/^（/.test((art.agent_notes || {}).detection || ""),
  };
  const pack = art.ioc_pack;
  if (!pack || !(pack.identity || pack.functions || pack.apis)) return synthesized;
  const ident = (pack.identity || []).map((item, i) => {
    const fb = synthesized.identity[i] || {};
    return {
      ...fb,
      ...item,
      sha256: item.sha256 || fb.sha256,
      md5: item.md5 || fb.md5,
      sha1: item.sha1 || fb.sha1,
      pdb_guid: item.pdb_guid || fb.pdb_guid,
      timestamp_utc: item.timestamp_utc || fb.timestamp_utc,
      size: item.size || fb.size,
      file_version: item.file_version || fb.file_version,
      filename: item.filename || fb.filename,
    };
  });
  const notes = (pack.detection_notes || synthesized.detection_notes || "").trim();
  return {
    ...synthesized,
    ...pack,
    identity: ident.length ? ident : synthesized.identity,
    functions: (pack.functions || []).length ? pack.functions : synthesized.functions,
    features: (pack.features || []).length ? pack.features : synthesized.features,
    apis: {
      user_mode: (pack.apis?.user_mode || []).length ? pack.apis.user_mode : synthesized.apis.user_mode,
      kernel: (pack.apis?.kernel || []).length ? pack.apis.kernel : synthesized.apis.kernel,
    },
    hunts: (pack.hunts || []).length ? pack.hunts : synthesized.hunts,
    detection_notes: notes.startsWith("（") ? synthesized.detection_notes : notes,
    cve: pack.cve || synthesized.cve,
    component: pack.component || synthesized.component,
  };
}

function renderIocPanel(job) {
  const pack = iocFromJob(job);
  const ident = (pack.identity || []).filter(x => x.filename || x.sha256 || x.file_version);
  const identCards = ident.map(item => {
    const meta = [item.machine, item.size ? fmtBytes(item.size) : "", item.timestamp_utc].filter(Boolean).join(" · ");
    return `<article class="ident-card">
      <p class="ident-role">${esc(ROLE_LABEL[item.role] || item.role || "")}</p>
      <h4>${esc(item.filename || "—")} <span>${esc(item.file_version || "")}</span></h4>
      ${meta ? `<p class="hint">${esc(meta)}</p>` : ""}
      <div class="ident-dl">
        ${hashLine("SHA256", item.sha256)}
        ${hashLine("SHA1", item.sha1)}
        ${hashLine("MD5", item.md5)}
        ${hashLine("PDB", item.pdb_guid)}
      </div>
    </article>`;
  }).join("");
  const huntText = huntClipboard(pack);
  const apiU = pack.apis?.user_mode || [];
  const apiK = pack.apis?.kernel || [];
  const huntRows = (pack.hunts || []).map(h => `<tr>
    <td>${esc(h.n ?? "")}</td>
    <td>${esc(h.location || "")}</td>
    <td>${(h.apis || []).map(a => `<code>${esc(a)}</code>`).join(" ") || "—"}</td>
    <td>${esc((h.action || "").slice(0, 120))}</td>
    <td>${esc(h.evidence || "—")}</td>
  </tr>`).join("");
  const featRows = (pack.features || []).map(f => `<tr>
    <td><code>${esc(f.feature_id || "")}</code></td>
    <td><code>${esc(f.featureState_rva || "")}</code></td>
    <td>${esc(f.on_disk_dword ?? "—")}</td>
    <td>${(f.gated_functions || []).map(fnLink).join(" ") || "—"}</td>
  </tr>`).join("");
  const fnRows = (pack.functions || []).slice(0, 12).map(f => `<tr>
    <td>${fnLink(f.name)}</td>
    <td>${esc(f.old_rva || "")}</td>
    <td>${esc(f.new_rva || "")}</td>
    <td>${f.old_size ?? f.old ?? "—"}</td>
    <td>${f.new_size ?? f.new ?? "—"}</td>
    <td class="${(f.delta || 0) >= 0 ? "delta-pos" : "delta-neg"}">${(f.delta || 0) >= 0 ? "+" : ""}${f.delta ?? ""}</td>
  </tr>`).join("");
  const notes = demoteSpecialistHeadings((pack.detection_notes || "").trim());
  const notesHtml = notes && !notes.startsWith("（")
    ? mdHtml(notes)
    : `<p class="hint">尚无检测方法说明。重新生成报告后会补充狩猎、补丁核验与误报说明。</p>`;
  const meta = [
    pack.cve ? `<span class="tag-pill ok">${esc(pack.cve)}</span>` : "",
    pack.component ? `<span class="tag-pill">${esc(pack.component)}</span>` : "",
    ...(pack.kbs || []).map(k => `<span class="tag-pill">#KB${esc(k)}</span>`),
  ].filter(Boolean).join("");

  return `<section class="ioc-page">
    <div class="brief-head">
      <div>
        <h3>IOC / 检测方法</h3>
        <p class="brief-kicker">哈希用于资产清点，行为线索用于威胁狩猎。</p>
      </div>
      <div class="brief-actions">
        ${huntText ? `<button type="button" class="btn ghost" data-copy-hunt="1">复制狩猎块</button>` : ""}
        <a class="btn ghost" id="ioc-json-link" target="_blank">下载 ioc.json</a>
      </div>
    </div>
    <div class="tag-row" style="margin:0 0 1rem">${meta || `<span class="hint">完成分析后会出现 CVE / 组件标签</span>`}</div>
    <p class="card-title">样本身份</p>
    ${identCards || '<p class="hint">尚无样本哈希。重新跑分析后会写入 SHA256。</p>'}
    <p class="card-title" style="margin-top:1.2rem">行为检测线索</p>
    <p class="hint">用户态 ${apiU.length ? apiU.map(a => `<code>${esc(a)}</code>`).join(" ") : "—"}
      · 内核 ${apiK.length ? apiK.map(a => `<code>${esc(a)}</code>`).join(" ") : "—"}</p>
    ${huntRows ? table(["步骤","位置","API/函数","动作","证据"], huntRows) : '<p class="hint">漏洞链生成后会列出逐步 hunt 线索。</p>'}
    ${featRows ? `<p class="card-title" style="margin-top:1.2rem">Feature</p>${table(["Feature","featureState RVA","on-disk","门控函数"], featRows)}` : ""}
    ${fnRows ? `<p class="card-title" style="margin-top:1.2rem">热点函数</p>${table(["函数","Old RVA","New RVA","Old","New","Δ"], fnRows)}` : ""}
    <p class="card-title" style="margin-top:1.2rem">运营检测方法</p>
    <div class="ioc-notes report-md md-compact">${notesHtml}</div>
  </section>`;
}

function threatStatusMeta(pack) {
  const st = pack?.status || "";
  const n = (pack?.search_hits || []).length;
  if (pack?.in_kev || st === "confirmed_exploited") {
    return { cls: "hot", mark: "已知在野", title: "已确认在野利用", sub: n ? `已列入 CISA KEV，另有 ${n} 条公开报道` : "已列入 CISA KEV" };
  }
  if (n || st === "searched") {
    return { cls: "mid", mark: "有报道", title: n ? `${n} 条公开报道` : "已完成检索", sub: pack.summary || "见下方分析与来源" };
  }
  if (st === "not_in_kev") {
    return { cls: "ok", mark: "未列入", title: "未发现相关公开报道", sub: "也未列入 CISA KEV" };
  }
  if (st === "lookup_failed") {
    return { cls: "mid", mark: "失败", title: "检索失败", sub: (pack.errors || []).join("；") || "网络暂时不可用" };
  }
  if (st === "kev_unavailable") {
    return { cls: "mid", mark: "不完整", title: "检索无结果", sub: "公开目录也暂不可用" };
  }
  if (st === "no_cve") {
    return { cls: "muted", mark: "待补", title: "缺少 CVE", sub: "在标题中带上 CVE 后再生成报告" };
  }
  return { cls: "muted", mark: "待查", title: "尚未检索", sub: "重新生成报告或点击联网检索" };
}

function threatHost(url) {
  try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return ""; }
}

function fmtEpss(epss) {
  const v = Number(epss?.epss);
  if (!Number.isFinite(v)) return "";
  const pct = v <= 1 ? `${(v * 100).toFixed(1)}%` : String(v);
  const rank = Number(epss.percentile);
  if (Number.isFinite(rank) && rank <= 1) return `${pct} · ${Math.round(rank * 100)} 分位`;
  return pct;
}

function fmtRansom(val) {
  const s = String(val || "").trim();
  if (!s) return "";
  if (/^known$/i.test(s)) return "已知";
  if (/^unknown$/i.test(s)) return "未知";
  return s;
}

function renderThreatPanel(job) {
  const pack = job?.result?.artifacts?.threat_intel || {};
  const meta = threatStatusMeta(pack);
  const kev = pack.kev || {};
  const nvd = pack.nvd || {};
  const epss = pack.epss || {};
  const hits = pack.search_hits || [];
  const rans = fmtRansom(kev.ransomware || pack.ransomware_campaign);
  const epssLabel = fmtEpss(epss);
  const kevLabel = pack.in_kev
    ? (kev.date_added ? `是 · ${kev.date_added}` : "是")
    : (pack.status === "not_in_kev" ? "否" : "");

  const facts = [
    pack.cve && ["CVE", pack.cve],
    kevLabel && ["CISA KEV", kevLabel],
    rans && ["勒索活动", rans],
    (nvd.cvss || nvd.severity) && ["NVD CVSS", [nvd.cvss, nvd.severity].filter(Boolean).join(" ")],
    (nvd.cwe || []).length && ["CWE", (nvd.cwe || []).slice(0, 4).join(" ")],
    epssLabel && ["EPSS", epssLabel],
    hits.length ? ["公开报道", `${hits.length} 条`] : null,
    pack.fetched_at && ["更新", fmtDate(pack.fetched_at)],
  ].filter(Boolean);

  const hitList = hits.map((h, i) => {
    const title = h.title || h.url || "未命名来源";
    const url = h.url || "";
    const host = threatHost(url);
    const snippet = (h.snippet || "").trim();
    const heading = url
      ? `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(title)}</a>`
      : `<strong>${esc(title)}</strong>`;
    return `<li class="threat-hit">
      <div class="threat-hit-top">
        <span class="threat-hit-n">${String(i + 1).padStart(2, "0")}</span>
        ${heading}
        ${host ? `<span class="threat-hit-host">${esc(host)}</span>` : ""}
      </div>
      ${snippet ? `<p>${esc(snippet)}</p>` : ""}
    </li>`;
  }).join("");

  const notes = demoteSpecialistHeadings((pack.threat_notes || (job?.result?.artifacts?.agent_notes || {}).threat || "").trim());
  const notesHtml = notes && !notes.startsWith("（")
    ? mdHtml(notes)
    : `<p class="hint">尚无分析师解读。重新生成报告后会根据检索结果写出总结。</p>`;
  const needSearch = !("search_hits" in pack);

  return `<section class="ioc-page">
    <div class="brief-head">
      <div>
        <h3>在野利用 / 威胁情报</h3>
        <p class="brief-kicker">公开报道与目录对照，用于判断补丁优先级。</p>
      </div>
      <div class="brief-actions">
        <a class="btn ghost" id="threat-json-link" target="_blank">下载 JSON</a>
        ${needSearch || !hits.length
          ? `<button type="button" class="btn primary" id="threat-refresh">联网检索</button>`
          : `<button type="button" class="btn ghost" id="threat-refresh">重新检索</button>`}
      </div>
    </div>
    <div class="threat-banner ${meta.cls}">
      <span class="threat-mark">${esc(meta.mark)}</span>
      <div>
        <strong>${esc(meta.title)}</strong>
        <span>${esc(pack.summary || meta.sub)}</span>
      </div>
    </div>
    ${facts.length ? `<div class="brief-facts">${facts.map(([k, v]) => `<div class="brief-fact"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join("")}</div>` : ""}
    <p class="card-title">分析师解读</p>
    <div class="ioc-notes report-md md-compact threat-notes">${notesHtml}</div>
    <p class="card-title" style="margin-top:1.2rem">公开报道</p>
    ${hitList
      ? `<ol class="threat-hits">${hitList}</ol>`
      : `<p class="hint">尚未检索到相关报道。</p>`}
    ${(pack.errors || []).length ? `<p class="hint" style="margin-top:0.8rem">${esc((pack.errors || []).join("；"))}</p>` : ""}
  </section>`;
}

const BYPASS_META = {
  closed: { cls: "ok", mark: "已闭合", title: "补丁已闭合已知窗口" },
  partial: { cls: "mid", mark: "部分闭合", title: "补丁部分闭合" },
  bypassable: { cls: "hot", mark: "有绕过面", title: "仍存在绕过面" },
  unknown: { cls: "muted", mark: "待评估", title: "尚未评估补丁完整性" },
};

const RESIDUAL_META = {
  none: { cls: "ok", mark: "未发现", title: "未发现同类未修复缺陷" },
  suspects: { cls: "mid", mark: "有嫌疑", title: "有待核实的同类嫌疑" },
  likely: { cls: "hot", mark: "可能残留", title: "可能仍有同类漏洞" },
  unknown: { cls: "muted", mark: "待评估", title: "尚未审查残留漏洞" },
};

const FINDING_STATUS = {
  closed: { cls: "ok", label: "已闭合" },
  residual: { cls: "err", label: "残留" },
  confirmed: { cls: "err", label: "成立" },
  refuted: { cls: "ok", label: "排除" },
  unknown: { cls: "warn", label: "未知" },
  suspect: { cls: "warn", label: "嫌疑" },
  similar: { cls: "warn", label: "同类" },
  cleared: { cls: "ok", label: "排除" },
};

function reviewNotesHtml(notes, emptyHint) {
  const t = String(notes || "").trim();
  if (!t || t.startsWith("（")) return `<p class="hint">${emptyHint}</p>`;
  return mixedJsonMarkdownHtml(t) || `<p class="hint">${emptyHint}</p>`;
}

function countByStatus(findings) {
  const n = { closed: 0, residual: 0, unknown: 0 };
  for (const f of findings || []) {
    const k = f.status === "closed" || f.status === "residual" ? f.status : "unknown";
    n[k] += 1;
  }
  return n;
}

function renderBypassPanel(job) {
  const art = job?.result?.artifacts || {};
  const pack = art.bypass_pack || {};
  const meta = BYPASS_META[pack.verdict] || BYPASS_META.unknown;
  const findings = [...(pack.findings || [])];
  const used = new Set();
  const ordered = [];
  for (const dim of BYPASS_DIMS) {
    const hit = findings.find((f, i) => !used.has(i) && dim.re.test(`${f.method || ""} ${f.target || ""}`));
    if (hit) {
      used.add(findings.indexOf(hit));
      ordered.push({ ...hit, method: hit.method || dim.label, _dim: dim.label });
    } else {
      ordered.push({ method: dim.label, status: "unknown", _empty: true });
    }
  }
  findings.forEach((f, i) => {
    if (!used.has(i)) ordered.push(f);
  });
  const notes = demoteSpecialistHeadings(pack.notes || (art.agent_notes || {}).bypass || "");
  const counts = countByStatus(findings);
  const cve = (job?.title || "").match(/CVE-\d{4}-\d+/i)?.[0] || art.ioc_pack?.cve || art.threat_intel?.cve || "";
  const confLabel = { high: "高", medium: "中", low: "低" }[pack.confidence] || "";
  const facts = [
    counts.residual ? ["残留", `${counts.residual} 条`] : null,
    counts.closed ? ["已闭合", `${counts.closed} 条`] : null,
    counts.unknown ? ["未判定", `${counts.unknown} 条`] : null,
    confLabel && pack.has_analyst ? ["置信度", confLabel] : null,
  ].filter(Boolean);
  const tags = [
    cve ? `<span class="tag-pill ok">${esc(cve)}</span>` : "",
    pack.verdict && pack.verdict !== "unknown" ? `<span class="tag-pill ${meta.cls === "hot" ? "err" : meta.cls === "ok" ? "ok" : "warn"}">${esc(meta.mark)}</span>` : "",
    counts.residual ? `<span class="tag-pill err">残留 ${counts.residual}</span>` : "",
  ].filter(Boolean).join("");
  const cards = ordered.map((f, i) => {
    const st = FINDING_STATUS[f.status] || FINDING_STATUS.unknown;
    const like = { high: "高", medium: "中", low: "低" }[f.likelihood] || f.likelihood || "";
    const kvs = [
      f.evidence ? ["证据", esc(f.evidence)] : null,
      f.hardening ? ["加固", esc(f.hardening)] : null,
    ].filter(Boolean);
    const target = f.target ? fnLink(f.target) : "";
    return `<li class="review-hit st-${esc(f.status === "closed" || f.status === "residual" ? f.status : "unknown")}${f._empty ? " st-empty" : ""}">
      <div class="review-hit-top">
        <span class="review-hit-n">${String(i + 1).padStart(2, "0")}</span>
        <strong>${esc(f.method || "未命名维度")}</strong>
        ${target ? `<span class="review-target">${target}</span>` : ""}
        <span class="tag-pill ${st.cls}">${esc(f._empty ? "未评" : st.label)}</span>
        ${f.demoted ? `<span class="tag-pill warn">已降级·无汇编</span>` : ""}
        ${like && !f._empty ? `<span class="tag-pill">${esc(like)}</span>` : ""}
      </div>
      ${kvs.length ? `<dl class="review-kv">${kvs.map(([k, v]) => `<dt>${k}</dt><dd${k === "加固" ? ' class="fix"' : ""}>${v}</dd>`).join("")}</dl>` : (f._empty ? `<p class="hint" style="margin:0.4rem 0 0">该维度本次未单独给出结论。</p>` : "")}
    </li>`;
  }).join("");
  return `<section class="ioc-page">
    <div class="brief-head">
      <div>
        <h3>补丁完整性 / 绕过面</h3>
        <p class="brief-kicker">评估补丁是否闭合已知窗口，并标出加固点。</p>
      </div>
      <div class="brief-actions">
        <a class="btn ghost" id="bypass-json-link" target="_blank">下载 JSON</a>
        <button type="button" class="btn ghost" data-goto-panel="residual">残留漏洞</button>
      </div>
    </div>
    ${tags ? `<div class="tag-row" style="margin:0.7rem 0 0">${tags}</div>` : ""}
    <div class="threat-banner ${meta.cls}">
      <span class="threat-mark">${esc(meta.mark)}</span>
      <div>
        <strong>${esc(meta.title)}</strong>
        <span>${esc(pack.summary || (pack.has_analyst ? "见下方绕过面清单" : "重新生成报告后会出现评估"))}</span>
      </div>
    </div>
    ${facts.length ? `<div class="brief-facts">${facts.map(([k, v]) => `<div class="brief-fact"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join("")}</div>` : ""}
    <p class="card-title">${findings.length ? `绕过面 · ${findings.length} 条评估 / 6 个维度` : "绕过面 · 6 个维度"}</p>
    ${cards ? `<ol class="review-hits">${cards}</ol>` : `<p class="hint">尚未列出可核对的绕过面。重新生成报告后会按门控、旁路路径、锁窗口等维度给出结论。</p>`}
    <p class="card-title" style="margin-top:1.2rem">分析师解读</p>
    <div class="ioc-notes report-md md-compact threat-notes">${reviewNotesHtml(notes, "尚无解读。配置 LLM 后重新生成报告。")}</div>
  </section>`;
}

function renderResidualPanel(job) {
  const art = job?.result?.artifacts || {};
  const pack = art.residual_pack || {};
  const meta = RESIDUAL_META[pack.verdict] || RESIDUAL_META.unknown;
  const findings = pack.findings || [];
  const notes = demoteSpecialistHeadings(pack.notes || (art.agent_notes || {}).residual || "");
  const facts = [
    pack.verdict && ["结论", meta.mark],
    pack.confidence && ["置信度", { high: "高", medium: "中", low: "低" }[pack.confidence] || pack.confidence],
    findings.length ? ["嫌疑函数", `${findings.length} 个`] : null,
  ].filter(Boolean);
  const cards = findings.map((f, i) => {
    const st = FINDING_STATUS[f.status] || FINDING_STATUS.suspect;
    const sev = { high: "高", medium: "中", low: "低" }[f.severity] || f.severity || "";
    return `<li class="review-hit">
      <div class="review-hit-top">
        <span class="review-hit-n">${String(i + 1).padStart(2, "0")}</span>
        <strong>${fnLink(f.function || "未命名函数")}</strong>
        ${f.pattern ? `<span class="review-target">${esc(f.pattern)}</span>` : ""}
        <span class="tag-pill ${st.cls}">${esc(st.label)}</span>
        ${sev ? `<span class="tag-pill">${esc(sev)}</span>` : ""}
      </div>
      ${f.evidence ? `<p>${esc(f.evidence)}</p>` : ""}
    </li>`;
  }).join("");
  return `<section class="ioc-page">
    <div class="brief-head">
      <div>
        <h3>残留漏洞 / 同类缺陷</h3>
        <p class="brief-kicker">审查同组件未改函数是否存在与本次根因同类的问题。</p>
      </div>
      <div class="brief-actions">
        <a class="btn ghost" id="residual-json-link" target="_blank">下载 JSON</a>
        <button type="button" class="btn ghost" data-goto-panel="control">对照路径</button>
      </div>
    </div>
    <div class="threat-banner ${meta.cls}">
      <span class="threat-mark">${esc(meta.mark)}</span>
      <div>
        <strong>${esc(meta.title)}</strong>
        <span>${esc(pack.summary || (pack.has_analyst ? "见下方分析师解读" : "重新生成报告后会出现审查结果"))}</span>
      </div>
    </div>
    ${facts.length ? `<div class="brief-facts">${facts.map(([k, v]) => `<div class="brief-fact"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join("")}</div>` : ""}
    <p class="card-title">分析师解读</p>
    <div class="ioc-notes report-md md-compact threat-notes">${reviewNotesHtml(notes, "尚无解读。配置 LLM 后重新生成报告。")}</div>
    <p class="card-title" style="margin-top:1.2rem">嫌疑函数</p>
    ${cards ? `<ol class="review-hits">${cards}</ol>` : `<p class="hint">未发现与本次根因同类的未修复函数。</p>`}
  </section>`;
}

function huntLabOf(job) {
  if (job?._huntView) return job._huntView;
  return (job?.result?.artifacts || {}).hunt_lab || {};
}

function huntLabCurrent(job) {
  return (job?.result?.artifacts || {}).hunt_lab || {};
}

function huntSurfacePack(job, lab) {
  const art = job?.result?.artifacts || {};
  const research = art.research_lab || {};
  const src = lab || {};
  return {
    surface: src.surface || research.surface || art.surface_map || {},
    scores: (src.scores && src.scores.length) ? src.scores : (research.scores || art.handler_scores || []),
    observations: src.observations || research.observations || [],
    variant: src.similar || src.variant || research.variant,
  };
}

function huntLabHistoryRows(job) {
  const rows = [...(job?.hunt_lab_history || [])];
  const cur = huntLabCurrent(job);
  if (cur.status && cur.run_id && !rows.some(r => r.run_id === cur.run_id)) {
    rows.unshift({
      run_id: cur.run_id,
      status: cur.status,
      started_at: cur.started_at,
      finished_at: cur.finished_at,
      bypass_verdict: cur.bypass?.verdict,
      similar_verdict: cur.similar?.verdict,
      has_report: Boolean(cur.report),
    });
  } else if (cur.status && !cur.run_id && !rows.length) {
    rows.unshift({
      run_id: "current",
      status: cur.status,
      started_at: cur.started_at,
      finished_at: cur.finished_at,
      bypass_verdict: cur.bypass?.verdict,
      similar_verdict: cur.similar?.verdict,
      has_report: Boolean(cur.report),
    });
  }
  return rows;
}

function renderHuntLabHistory(job) {
  const rows = huntLabHistoryRows(job);
  if (!rows.length) {
    return `<p class="hint">尚无历史。跑完一轮后会留在本任务下，关闭页面也能再打开。</p>`;
  }
  const viewing = job?._huntView?.run_id || "current";
  const currentId = huntLabCurrent(job).run_id || "current";
  const items = rows.map(row => {
    const id = row.run_id || "current";
    const when = row.finished_at || row.started_at;
    const st = ({ running: "运行中", completed: "已完成", failed: "失败", cancelled: "已取消", interrupted: "已中断" })[row.status] || row.status || "—";
    const bits = [
      row.bypass_verdict ? `绕过 ${row.bypass_verdict}` : null,
      row.similar_verdict ? `变体 ${row.similar_verdict}` : null,
    ].filter(Boolean).join(" · ");
    const on = viewing === id || (!job?._huntView && id === currentId);
    return `<li>
      <button type="button" class="huntlab-hist-item${on ? " on" : ""}" data-hunt-run="${esc(id)}">
        <strong>${esc(when ? fmtDate(when) : "本轮")}</strong>
        <span>${esc(st)}${bits ? " · " + bits : ""}</span>
      </button>
    </li>`;
  }).join("");
  return `<ol class="huntlab-history">${items}</ol>`;
}

function renderHuntLabTrack(title, pack, metaMap) {
  if (!pack) return `<p class="hint">${esc(title)}尚未运行。</p>`;
  const meta = metaMap[pack.verdict] || metaMap.unknown || { cls: "muted", mark: pack.verdict || "—", title: "" };
  const findings = pack.findings || [];
  const hyps = pack.hypotheses || [];
  const cards = findings.map((f, i) => {
    const st = FINDING_STATUS[f.status] || FINDING_STATUS.unknown;
    const name = f.target || f.function || f.method || "未命名";
    return `<li class="review-hit">
      <div class="review-hit-top">
        <span class="review-hit-n">${String(i + 1).padStart(2, "0")}</span>
        <strong>${fnLink(name)}</strong>
        ${f.pattern || f.method ? `<span class="review-target">${esc(f.pattern || f.method)}</span>` : ""}
        <span class="tag-pill ${st.cls}">${esc(st.label)}</span>
      </div>
      ${f.evidence ? `<p>${esc(f.evidence)}</p>` : ""}
      ${f.hardening ? `<p class="hint">加固：${esc(f.hardening)}</p>` : ""}
    </li>`;
  }).join("");
  const hypLine = hyps.map(h => `${h.id || ""} ${h.status || ""}`).filter(Boolean).join(" · ");
  return `
    <div class="threat-banner ${meta.cls}">
      <span class="threat-mark">${esc(meta.mark)}</span>
      <div>
        <strong>${esc(title)}</strong>
        <span>${esc(pack.summary || "尚无摘要")}</span>
        ${hypLine ? `<span class="hint">${esc(hypLine)}</span>` : ""}
      </div>
    </div>
    ${cards ? `<ol class="review-hits">${cards}</ol>` : `<p class="hint">本线暂无 findings。</p>`}
    <p class="hint">工具 ${pack.tool_call_count || (pack.tool_calls || []).length} 次 · ${pack.rounds || 0} 轮</p>`;
}

function renderHuntLabPanel(job) {
  const lab = huntLabOf(job);
  const current = huntLabCurrent(job);
  const prog = job?.hunt_lab_progress || {};
  const status = lab.status || "";
  const running = huntLabRunning(job);
  const jobReady = job?.status === "completed";
  const viewingPast = Boolean(job?._huntView && job._huntView.run_id && job._huntView.run_id !== current.run_id);
  const runQ = viewingPast && lab.run_id ? `?run_id=${encodeURIComponent(lab.run_id)}` : "";
  const logs = [
    ...(lab.bypass?.tool_calls || []).map(x => ({ ...x, track: "绕过" })),
    ...(lab.similar?.tool_calls || []).map(x => ({ ...x, track: "变体" })),
  ];
  const logHtml = logs.map(item => `<li><span class="huntlab-track">${esc(item.track)}</span> <code>${esc(item.tool || "")}</code>
    ${jsonViewHtml(item.args || {})}
    ${item.result_preview ? jsonViewHtml(item.result_preview) : ""}</li>`).join("");
  const report = lab.report || "";
  const pct = prog.percent != null ? prog.percent : (status === "completed" ? 100 : 0);
  const actions = running
    ? `<button type="button" class="btn ghost" data-cancel-huntlab>取消</button>`
    : `<button type="button" class="btn primary" data-start-huntlab ${jobReady ? "" : "disabled"}>启动深度狩猎</button>`;
  const when = lab.finished_at || lab.started_at;
  return `<section class="ioc-page huntlab-page">
    <div class="brief-head">
      <div>
        <h3>深度狩猎</h3>
        <p class="brief-kicker">一次启动：表面图 → 处理函数打分 → 绕过面 / 变体。结果写入本任务，关闭页面后可再打开。</p>
      </div>
      <div class="brief-actions">
        ${actions}
        <a class="btn ghost" href="${API}/jobs/${job.id}/hunt-lab.json${runQ}" target="_blank">JSON</a>
        <a class="btn ghost" href="${API}/jobs/${job.id}/hunt-lab.md${runQ}" target="_blank">报告 MD</a>
      </div>
    </div>
    ${!jobReady ? `<p class="hint">请先等主分析完成，再启动本功能。</p>` : ""}
    ${running || prog.message ? `<div class="huntlab-progress"><span>${esc(prog.message || "深度狩猎运行中…")}</span><strong>${pct}%</strong></div>` : ""}
    ${lab.error ? `<p class="err">${esc(lab.error)}</p>` : ""}
    ${viewingPast ? `<p class="hint">正在查看历史轮次。点左侧「本轮」或再启动可回到最新结果。</p>` : ""}
    <p class="card-title">历史记录</p>
    ${renderHuntLabHistory(job)}
    <div class="brief-facts">
      <div class="brief-fact"><span>状态</span><strong>${esc({ running: "运行中", completed: "已完成", failed: "失败", cancelled: "已取消", interrupted: "已中断" }[status] || "未运行")}</strong></div>
      <div class="brief-fact"><span>时间</span><strong>${esc(when ? fmtDate(when) : "—")}</strong></div>
      <div class="brief-fact"><span>补反汇编</span><strong>${lab.disasm_used ?? "—"}</strong></div>
    </div>
    ${renderSurfaceTables(huntSurfacePack(job, lab))}
    <p class="card-title">绕过面（方法测试）</p>
    ${renderHuntLabTrack("绕过面", lab.bypass, BYPASS_META)}
    <p class="card-title" style="margin-top:1.2rem">同类残留（变体狩猎）</p>
    ${renderHuntLabTrack("变体狩猎", lab.similar || huntSurfacePack(job, lab).variant, RESIDUAL_META)}
    <p class="card-title" style="margin-top:1.2rem">工具调用</p>
    ${logHtml ? `<ol class="huntlab-log">${logHtml}</ol>` : `<p class="hint">启动后将在此列出 Agent 实际调用的工具（反汇编 / CFG / 符号 / Feature）。</p>`}
    <p class="card-title" style="margin-top:1.2rem">狩猎报告</p>
    <div class="ioc-notes report-md md-compact threat-notes">${report ? mdHtml(report) : `<p class="hint">完成后在此显示独立五节报告，不会写入主报告 19 节。</p>`}</div>
  </section>`;
}

const SCORE_META = {
  high: { cls: "err", label: "high" },
  medium: { cls: "warn", label: "medium" },
  low: { cls: "muted", label: "low" },
  buffered: { cls: "ok", label: "buffered" },
  hardened: { cls: "ok", label: "hardened" },
  wrapper: { cls: "muted", label: "wrapper" },
};

function researchLabOf(job) {
  return (job?.result?.artifacts || {}).research_lab || {};
}

function researchLabRunning(job) {
  const st = researchLabOf(job).status;
  return st === "running" || (Boolean(job?.research_lab_progress) && st !== "completed" && st !== "failed" && st !== "cancelled");
}

function renderScoreTable(scores, cap = 40) {
  const rows = (scores || []).slice(0, cap).map(r => {
    const meta = SCORE_META[r.risk] || SCORE_META.low;
    return `<tr>
      <td>${fnLink(r.name || "")}</td>
      <td><span class="tag-pill ${meta.cls}">${esc(meta.label)}</span></td>
      <td>${esc(r.method || "—")}</td>
      <td>${r.size ?? "—"}</td>
      <td>${esc((r.why || []).join("；"))}</td>
    </tr>`;
  }).join("");
  return rows
    ? table(["处理函数", "打分", "METHOD", "size", "依据"], rows)
    : '<p class="hint">尚无打分。启动后会列出 IOCTL / FastIo 处理函数。</p>';
}

function renderSurfaceTables(pack) {
  const surface = pack.surface || {};
  const scores = pack.scores || [];
  const dispatch = surface.dispatch || {};
  const ioctl = dispatch.ioctl || [];
  const imm = (surface.immediate || {}).entries || [];
  const fast = (surface.fastio || {}).callees || [];
  const ioctlRows = ioctl.slice(0, 74).map(r => `<tr>
    <td>${r.index ?? ""}</td>
    <td><code>${esc(r.code || "—")}</code></td>
    <td>${esc(r.method || "—")}</td>
    <td>${fnLink(r.handler || "")}</td>
  </tr>`).join("");
  const fastRows = fast.map(e => `<tr>
    <td>${esc(e.kind || "")}</td>
    <td>${fnLink(e.from || "")}</td>
    <td>${fnLink(e.to || "")}</td>
  </tr>`).join("");
  const obs = pack.observations || [];
  const obsHtml = obs.map(o => `<li><code>${esc(o.bp || o.function || "")}</code> ${esc(o.watch || "")} — ${esc(o.why || "")}</li>`).join("");
  const hasAny = surface.status || ioctl.length || scores.length;
  if (!hasAny) {
    return `<p class="hint">启动后先解析 DeviceControl / FastIo，再打分并做绕过 / 变体狩猎。</p>`;
  }
  return `
    <p class="card-title">用户入口（IOCTL / FastIo）</p>
    <div class="brief-facts">
      <div class="brief-fact"><span>表面图</span><strong>${esc(surface.status || "未跑")}</strong></div>
      <div class="brief-fact"><span>处理函数</span><strong>${surface.handler_count ?? scores.length ?? "—"}</strong></div>
      <div class="brief-fact"><span>IOCTL 槽</span><strong>${dispatch.limit ?? ioctl.length ?? "—"}</strong></div>
    </div>
    ${ioctlRows ? table(["idx", "code", "method", "handler"], ioctlRows) : '<p class="hint">未能解析 DeviceControl 码表（驱动结构可能与 AFD 不同）。</p>'}
    <p class="card-title" style="margin-top:1.2rem">Immediate / FastIo</p>
    <p class="hint">Immediate 已填 ${imm.length} · FastIo 直接调用 ${fast.length}</p>
    ${fastRows ? table(["类型", "从", "到"], fastRows) : ""}
    <p class="card-title" style="margin-top:1.2rem">处理函数打分</p>
    ${renderScoreTable(scores)}
    <p class="card-title" style="margin-top:1.2rem">隔离 VM 观察清单</p>
    ${obsHtml ? `<ul class="research-obs">${obsHtml}</ul>` : '<p class="hint">无 high/medium 时不生成观察点。清单不是触发步骤。</p>'}
  `;
}

function renderResearchBody(job) {
  const lab = researchLabOf(job);
  const surface = lab.surface || (job?.result?.artifacts || {}).surface_map || {};
  const scores = lab.scores || (job?.result?.artifacts || {}).handler_scores || [];
  const dispatch = surface.dispatch || {};
  const ioctl = dispatch.ioctl || [];
  const imm = (surface.immediate || {}).entries || [];
  const fast = (surface.fastio || {}).callees || [];
  const ioctlRows = ioctl.slice(0, 74).map(r => `<tr>
    <td>${r.index ?? ""}</td>
    <td><code>${esc(r.code || "—")}</code></td>
    <td>${esc(r.method || "—")}</td>
    <td>${fnLink(r.handler || "")}</td>
  </tr>`).join("");
  const fastRows = fast.map(e => `<tr>
    <td>${esc(e.kind || "")}</td>
    <td>${fnLink(e.from || "")}</td>
    <td>${fnLink(e.to || "")}</td>
  </tr>`).join("");
  const obs = lab.observations || [];
  const obsHtml = obs.map(o => `<li><code>${esc(o.bp || o.function || "")}</code> ${esc(o.watch || "")} — ${esc(o.why || "")}</li>`).join("");
  const variant = lab.variant;
  return `
    <div class="brief-facts">
      <div class="brief-fact"><span>表面图</span><strong>${esc(surface.status || "未跑")}</strong></div>
      <div class="brief-fact"><span>处理函数</span><strong>${surface.handler_count ?? scores.length ?? "—"}</strong></div>
      <div class="brief-fact"><span>IOCTL 槽</span><strong>${dispatch.limit ?? ioctl.length ?? "—"}</strong></div>
      <div class="brief-fact"><span>LLM</span><strong>${lab.llm ? "变体狩猎" : "仅工具"}</strong></div>
    </div>
    <p class="card-title">IOCTL 表</p>
    ${ioctlRows ? table(["idx", "code", "method", "handler"], ioctlRows) : '<p class="hint">未能解析 DeviceControl 码表（驱动结构可能与 AFD 不同）。</p>'}
    <p class="card-title" style="margin-top:1.2rem">Immediate / FastIo</p>
    <p class="hint">Immediate 已填 ${imm.length} · FastIo 直接调用 ${fast.length}</p>
    ${fastRows ? table(["类型", "从", "到"], fastRows) : ""}
    <p class="card-title" style="margin-top:1.2rem">处理函数打分</p>
    ${renderScoreTable(scores)}
    ${variant ? `<p class="card-title" style="margin-top:1.2rem">变体狩猎</p>${renderHuntLabTrack("变体", variant, RESIDUAL_META)}` : ""}
    <p class="card-title" style="margin-top:1.2rem">隔离 VM 观察清单</p>
    ${obsHtml ? `<ul class="research-obs">${obsHtml}</ul>` : '<p class="hint">无 high/medium 时不生成观察点。清单不是触发步骤。</p>'}
    <p class="card-title" style="margin-top:1.2rem">研究报告</p>
    <div class="ioc-notes report-md md-compact threat-notes">${lab.report ? mdHtml(lab.report) : '<p class="hint">完成后显示五节短报告，不写入主报告 19 节。</p>'}</div>
  `;
}

function renderResearchPanel(job) {
  const lab = researchLabOf(job);
  const prog = job?.research_lab_progress || {};
  const status = lab.status || "";
  const running = researchLabRunning(job);
  const jobReady = job?.status === "completed";
  const pct = prog.percent != null ? prog.percent : (status === "completed" ? 100 : 0);
  const actions = running
    ? `<button type="button" class="btn ghost" data-cancel-research>取消</button>`
    : `<button type="button" class="btn primary" data-start-research ${jobReady ? "" : "disabled"}>启动研究流程</button>
       <label class="switch research-llm-switch"><input type="checkbox" data-research-llm checked /><span>LLM 变体</span></label>`;
  return `<section class="ioc-page huntlab-page">
    <div class="brief-head">
      <div>
        <h3>研究流程</h3>
        <p class="brief-kicker">表面图 → 处理函数打分 → 对照补丁 class 找残留 → 验证观察清单。与主流水线隔离。</p>
      </div>
      <div class="brief-actions">
        ${actions}
        <a class="btn ghost" href="${API}/jobs/${job.id}/research.json" target="_blank">JSON</a>
        <a class="btn ghost" href="${API}/jobs/${job.id}/research.md" target="_blank">报告 MD</a>
      </div>
    </div>
    ${!jobReady ? `<p class="hint">请先等主分析完成，再启动本功能。</p>` : ""}
    ${running || prog.message ? `<div class="huntlab-progress"><span>${esc(prog.message || "研究流程运行中…")}</span><strong>${pct}%</strong></div>` : ""}
    ${lab.error ? `<p class="err">${esc(lab.error)}</p>` : ""}
    ${renderResearchBody(job)}
  </section>`;
}

function ensureResearchPoll(jobId, job) {
  if (!researchLabRunning(job)) {
    clearInterval(researchLabTimer);
    return;
  }
  clearInterval(researchLabTimer);
  let busy = false;
  researchLabTimer = setInterval(async () => {
    if (busy) return;
    busy = true;
    try {
    const r = await fetch(`${API}/jobs/${jobId}?lite=1`);
    if (!r.ok) return;
    const j = await r.json();
    if (currentJobId !== jobId) return;
    const prev = lastJobData || {};
    const prevArt = (prev.result && prev.result.artifacts) || {};
    const nextArt = (j.result && j.result.artifacts) || {};
    lastJobData = {
      ...prev,
      ...j,
      result: { ...(prev.result || {}), artifacts: { ...prevArt, ...nextArt } },
    };
    const panel = $("#panel-research");
    if (panel) {
      panel.innerHTML = renderResearchPanel(j);
      hydrateMarkdown(panel);
    }
    if (!researchLabRunning(j)) clearInterval(researchLabTimer);
    } catch { /* keep last paint */ }
    finally { busy = false; }
  }, 2500);
}

function controlVerdict(row) {
  if (row.size_changed) return { cls: "warn", label: "存疑 · 尺寸已变" };
  if ((row.calls_added || []).length || (row.calls_removed || []).length) return { cls: "warn", label: "存疑 · 调用有变" };
  return { cls: "ok", label: "排除 · 仅重定位" };
}

function renderControlPanel(job) {
  const art = job?.result?.artifacts || {};
  const resized = new Set((art.symbol_diff?.functions_resized || []).map(f => f.name));
  const blocks = art.control_disasm || [];
  const names = art.control_names || [];
  const byName = Object.fromEntries(blocks.map(b => [b.name, b]));
  const ordered = [...names];
  for (const b of blocks) if (b.name && !ordered.includes(b.name)) ordered.push(b.name);
  const rows = ordered.map(name => {
    const b = byName[name] || { name };
    const o = b.old || {};
    const n = b.new || {};
    const sizeChanged = (o.size != null && n.size != null) ? o.size !== n.size : resized.has(name);
    return {
      name,
      old_size: o.size,
      new_size: n.size,
      old_rva: o.rva,
      new_rva: n.rva,
      size_changed: sizeChanged,
      calls_added: b.calls_added || [],
      calls_removed: b.calls_removed || [],
    };
  });
  const excluded = rows.filter(r => !r.size_changed && !r.calls_added.length && !r.calls_removed.length).length;
  const notes = (art.agent_notes || {}).control || "";
  const body = rows.map(r => {
    const v = controlVerdict(r);
    return `<tr data-fn="${esc(r.name)}">
      <td>${fnLink(r.name)}</td>
      <td>${esc(r.old_rva || "—")}</td>
      <td>${esc(r.new_rva || "—")}</td>
      <td>${r.old_size ?? "—"}</td>
      <td>${r.new_size ?? "—"}</td>
      <td class="${r.size_changed ? "delta-neg" : ""}">${r.size_changed ? "是" : "否"}</td>
      <td><span class="chip-row">${chips(r.calls_added, "add")}${chips(r.calls_removed, "del") || ""}</span>${!(r.calls_added || []).length && !(r.calls_removed || []).length ? "—" : ""}</td>
      <td><span class="tag-pill ${v.cls}">${esc(v.label)}</span></td>
    </tr>`;
  }).join("");
  return `<section class="ioc-page">
    <div class="brief-head">
      <div>
        <h3>对照路径排除</h3>
        <p class="brief-kicker">尺寸不变且调用不变的函数视为逻辑等价，排除为本次修复点。</p>
      </div>
      <div class="brief-actions">
        <button type="button" class="btn ghost" data-goto-panel="disasm">反汇编</button>
      </div>
    </div>
    <div class="brief-facts">
      <div class="brief-fact"><span>对照函数</span><strong>${rows.length}</strong></div>
      <div class="brief-fact"><span>可排除</span><strong>${excluded}</strong></div>
      <div class="brief-fact"><span>存疑</span><strong>${rows.length - excluded}</strong></div>
    </div>
    ${body ? table(["函数","Old RVA","New RVA","Old","New","尺寸变","调用差","结论"], body) : '<p class="empty">尚无对照函数。重新跑分析后会出现 Notify / Cleanup 等未改路径。</p>'}
    <p class="card-title" style="margin-top:1.2rem">分析师解读</p>
    <div class="ioc-notes report-md md-compact">${reviewNotesHtml(notes, "尚无对照路径解读。配置 LLM 后重新生成报告。")}</div>
  </section>`;
}

function verifyDriverName(art) {
  const pe = art.old_pe || art.new_pe || {};
  let name = String(pe.original_filename || "").split(/[/\\]/).pop().trim();
  if (!name && pe.path) name = String(pe.path).split(/[/\\]/).pop();
  if (name && !/\./.test(name)) name += ".sys";
  return /^[\w.\-]+\.sys$/i.test(name) ? name : "driver.sys";
}

function renderVerifyPanel(job) {
  const art = job?.result?.artifacts || {};
  const vp = art.verify_pack || {};
  const driver = vp.driver || verifyDriverName(art);
  const module = vp.module || driver.replace(/\.sys$/i, "").toLowerCase() || "driver";
  const oldVer = vp.old_version || (art.old_pe || {}).file_version || "";
  const newVer = vp.new_version || (art.new_pe || {}).file_version || "";
  const disasm = art.disassembly || [];
  const resized = (art.symbol_diff || {}).functions_resized || [];
  let hotspots = Array.isArray(vp.hotspots) ? vp.hotspots.filter(h => h && h.name) : [];
  if (!hotspots.length) {
    hotspots = (disasm.length ? disasm : resized).slice(0, 8).map(b => ({
      name: b.name,
      old_rva: b.old?.rva || b.old_rva,
      new_rva: b.new?.rva || b.new_rva,
      old_size: b.old?.size || b.old,
      new_size: b.new?.size || b.new,
    }));
  }
  let features = Array.isArray(vp.features) ? vp.features.filter(f => f && (f.feature_id || f.symbol)) : [];
  if (!features.length) {
    features = ((art.feature_trace || {}).features || []).slice(0, 8).map(f => ({
      feature_id: f.feature_id,
      featureState_rva: f.featureState_rva,
      on_disk_dword: f.on_disk_dword,
      symbol: `Feature_${f.feature_id}__private_featureState`,
    }));
  }
  const verifier = vp.verifier_cmd || `verifier /standard /driver ${driver}`;
  const windbg = (vp.windbg || [
    `$$ Patchalyzer 补丁核对 — 仅隔离 VM`,
    `lm m ${module}`,
    "!verifier 1",
    ...hotspots.filter(h => /^[A-Za-z_][\w]*$/.test(h.name || "")).map(h => `bp ${module}!${h.name}`),
    ...features.map(f => `dd ${module}!${f.symbol || `Feature_${f.feature_id}__private_featureState`} L1`),
  ].join("\n")).trim();
  const fileRole = {
    "README.md": "验证步骤",
    "setup_verifier_vm.cmd": "Driver Verifier 配置",
    "windbg_hotspots.wds": "WinDbg 断点 / Feature",
    "job_context.json": "任务上下文",
    "windbg_feature.wds": "WinDbg Feature（旧包）",
  };
  const files = (vp.files || ["README.md", "setup_verifier_vm.cmd", "windbg_hotspots.wds", "job_context.json"])
    .map(f => (typeof f === "string" ? { name: f, role: fileRole[f] || "材料" } : f))
    .filter(f => f && f.name && !/^poc_/i.test(f.name));
  const hotRows = hotspots.map(h => {
    const d = (h.new_size != null && h.old_size != null) ? h.new_size - h.old_size : null;
    return `<tr>
      <td>${fnLink(h.name)}</td>
      <td><code>${esc(h.old_rva || "—")}</code></td>
      <td><code>${esc(h.new_rva || "—")}</code></td>
      <td class="${d > 0 ? "delta-pos" : d < 0 ? "delta-neg" : ""}">${d == null ? "—" : (d >= 0 ? "+" : "") + d}</td>
    </tr>`;
  }).join("");
  const featRows = features.map(f => `<tr>
    <td><code>Feature_${esc(f.feature_id)}</code></td>
    <td><code>${esc(f.featureState_rva || "—")}</code></td>
    <td>${f.on_disk_dword == null ? "—" : esc(f.on_disk_dword)}</td>
  </tr>`).join("");
  const fileRows = files.map(f => `<tr><td><code>${esc(f.name)}</code></td><td>${esc(f.role || fileRole[f.name] || "材料")}</td></tr>`).join("");
  const jobId = job.id;
  return `<section class="ioc-page verify-page">
    <div class="brief-head">
      <div>
        <h3>补丁验证包</h3>
        <p class="brief-kicker">隔离 VM 里用 Driver Verifier 与 WinDbg 核对补丁，不含触发程序</p>
      </div>
      <div class="brief-actions">
        <button type="button" class="btn ghost" data-goto-panel="feature">Feature</button>
        <button type="button" class="btn ghost" data-goto-panel="disasm">反汇编</button>
        <a class="btn primary" href="${API}/jobs/${jobId}/verify.zip">下载 verify.zip</a>
      </div>
    </div>
    <div class="callout warn">${esc(vp.warning || "仅在隔离虚拟机中使用。分析服务器不会启用 Driver Verifier。")}</div>
    <div class="brief-facts">
      <div class="brief-fact"><span>驱动</span><strong>${esc(driver)}</strong></div>
      <div class="brief-fact"><span>模块</span><strong>${esc(module)}</strong></div>
      <div class="brief-fact"><span>漏洞版</span><strong>${esc(oldVer || "—")}</strong></div>
      <div class="brief-fact"><span>修复版</span><strong>${esc(newVer || "—")}</strong></div>
    </div>
    <p class="card-title" style="margin-top:1.2rem">核对步骤</p>
    <ol class="chain-text-list">
      <li>给虚拟机打快照。</li>
      <li>管理员运行 <code>setup_verifier_vm.cmd</code>，重启。</li>
      <li>分别在漏洞版 / 修复版上附加 WinDbg，执行 <code>windbg_hotspots.wds</code>。</li>
      <li>对照 Feature dword 与热点是否走到新增路径。</li>
      <li>结束后 <code>verifier /reset</code> 并还原快照。</li>
    </ol>
    <p class="card-title" style="margin-top:1.2rem">Driver Verifier</p>
    <pre class="asm">${esc(verifier)}\nverifier /flags 0x1 /driver ${esc(driver)}</pre>
    <p class="card-title" style="margin-top:1.2rem">WinDbg</p>
    <pre class="asm">${esc(windbg)}</pre>
    ${hotRows ? `<p class="card-title" style="margin-top:1.2rem">热点断点</p>${table(["函数", "Old RVA", "New RVA", "Δsize"], hotRows)}` : ""}
    ${featRows ? `<p class="card-title" style="margin-top:1.2rem">Feature 状态</p>${table(["Feature", "featureState RVA", "on-disk"], featRows)}` : ""}
    ${fileRows ? `<p class="card-title" style="margin-top:1.2rem">ZIP 内文件</p>${table(["文件", "用途"], fileRows)}` : ""}
  </section>`;
}

function renderCommunity(job) {
  const art = job.result?.artifacts || {};
  const byAgent = tracesByAgent(art.agent_traces);
  const live = (job.status === "running" || job.status === "pending")
    ? `<div class="progress-live">
        <strong>${esc(statusLabel(job.status))}</strong>
        <div class="progress-bar"><div style="width:${job.progress?.percent ?? 8}%;height:100%;background:var(--accent-strong)"></div></div>
        <p class="hint" style="margin:0">${esc(job.progress?.message || "排队 / 分析中…")}</p>
      </div>`
    : "";
  const canResume = job.status === "failed" || job.status === "cancelled"
    || (job.status === "completed" && !!(art.llm_error || !(art.llm_report || "").trim()));
  const resumeBtn = canResume ? ` <button type="button" class="btn ghost" id="resume-job">从断点继续</button>` : "";
  const errText = job.error || art.llm_error || "";
  const joinLabels = ["", "并行解读", "汇合输出"];
  const lanes = GRAPH_LANES.map((lane, i) => {
    const join = i ? `<div class="pipe-join"><span>${joinLabels[i] || "串行"}</span></div>` : "";
    return `${join}${renderLane(lane, job, byAgent)}`;
  }).join("");

  return `<div class="graph-page">
    ${renderBriefing(job)}
    <div class="graph-head">
      <div>
        <h3 class="graph-title">分析流水线</h3>
        <p class="graph-hint">点节点查看各阶段输出。</p>
      </div>
      <div class="graph-legend">
        <span><i class="lg-tool"></i>Tool</span>
        <span><i class="lg-agent"></i>Agent</span>
        <span><i class="lg-done"></i>完成</span>
        <span><i class="lg-run"></i>进行中</span>
        <span><i class="lg-skip"></i>跳过</span>
        <span><i class="lg-err"></i>失败</span>
      </div>
    </div>
    ${live}
    ${errText ? `<p class="err">${esc(errText)}${resumeBtn}</p>` : ""}
    <div class="pipe-board">
      <div class="pipe-lanes">${lanes}</div>
      <aside id="graph-pop" class="pipe-detail">${graphEmptyDetail()}</aside>
    </div>
  </div>`;
}

function syncTabChrome(name) {
  const group = PANEL_GROUP[name] || "conclude";
  $$(".modal-group").forEach(t => t.classList.toggle("active", t.dataset.group === group));
  $$(".tab-tier-sub").forEach(t => {
    const mine = t.dataset.groupPanel === group;
    t.classList.toggle("hidden", !mine);
  });
  $$(".modal-tab").forEach(t => t.classList.toggle("active", t.dataset.panel === name));
}

function leaveCase() {
  if (typeof window.__paCloseCase === "function") window.__paCloseCase();
  else window.__paGotoJobs?.();
}

function liveProgressBlock(job) {
  const running = job.status === "running" || job.status === "pending";
  if (!running && job.status !== "failed" && job.status !== "cancelled") return "";
  const pct = job.progress?.percent ?? (job.status === "pending" ? 0 : 8);
  const msg = job.progress?.message
    || (job.status === "pending" ? "排队中…" : job.status === "failed" || job.status === "cancelled" ? (job.error || "分析中断") : "分析进行中…");
  const err = job.error ? `<p class="err">${esc(job.error)}</p>` : "";
  return `<div class="decision-live">
    ${running ? `<div class="pa-progress"><i id="summary-progress-fill" style="width:${pct}%"></i></div>` : ""}
    <p class="hint" id="summary-progress-text">${esc(msg)}</p>
    ${err}
    <p class="brief-actions" style="margin-top:0.7rem">
      <button type="button" class="btn ghost" data-goto-panel="community">查看流水线</button>
    </p>
  </div>`;
}

async function activatePanel(name) {
  if (name === "report") {
    openExportMenu();
    return;
  }
  if (["disasm", "cfg", "control", "feature"].includes(name)) {
    await ensureFullJob();
  }
  fillEvidencePanel(name);
  syncTabChrome(name);
  $$(".modal-panel").forEach(p => p.classList.toggle("active", p.id === `panel-${name}`));
  if (name === "fullreport") fillFullReportPanel();
  const panel = document.getElementById(`panel-${name}`);
  if (panel) {
    resetCollapsedMermaid(panel);
    await hydrateMarkdown(panel);
  }
  if (typeof window.__paSetCaseTab === "function") window.__paSetCaseTab(name);
}

function openExportMenu() {
  const btn = $("#export-report");
  if (!btn) return;
  if (btn.disabled) {
    alert("尚未生成报告，请先完成分析或重新生成报告。");
    return;
  }
  renderExportSectionPicker();
  $("#export-menu")?.classList.remove("hidden");
}

function extractChainClient(art) {
  const existing = art.vuln_chain;
  if (existing && existing.present && ((existing.steps || []).length || existing.markdown || (existing.diagrams || []).length)) {
    return normalizeChain(existing);
  }
  const report = art.llm_report || "";
  const root = (art.agent_notes || {}).root_cause || "";
  let body = "";
  let source = "report";
  const m = report.match(/^##\s*6\.\s*漏洞链\s*\n([\s\S]*?)(?=^##\s*\d+\.|\s*$)/m);
  if (m) body = m[1].trim();
  else {
    const legacy = report.match(/^#{2,3}\s*.*(?:漏洞链|利用链|攻击链)[^\n]*\n([\s\S]*?)(?=^#{2,3}\s|\s*$)/m);
    if (legacy) {
      body = legacy[0].replace(/^#{2,3}\s*/, "## ").trim();
      source = "report_legacy";
    } else {
      source = "root_cause";
      const m2 = root.match(/^#{2,3}\s*漏洞链[^\n]*\n([\s\S]*?)(?=^#{2,3}\s|\s*$)/m);
      if (m2) body = m2[1].trim();
      else if (/漏洞链|利用链|攻击链/.test(root)) body = root.trim();
    }
  }
  if (!body) return { present: false, steps: [], markdown: "", diagrams: [], source: null, summary: "", meta: {} };

  return normalizeChain({
    present: true,
    source,
    markdown: body,
    steps: parseChainSteps(body),
    diagrams: extractMermaidBlocks(body),
    summary: "",
  });
}

/** Prefer §6 overview table rows; fall back to list lines with extractable APIs. */
function parseChainSteps(body) {
  const table = parseChainTable(body || "");
  if (table.length >= 2) return table;
  const steps = [];
  for (const line of (body || "").split("\n")) {
    const s = line.trim();
    const mt = s.match(/^(?:[-*+]|\d+[.)、]|步骤\s*\d+[.:：]?)\s*(.+)$/);
    if (!mt) continue;
    const content = mt[1].trim();
    if (content.startsWith("|") || content.startsWith("---")) continue;
    if (isNoiseChainLine(content)) continue;
    const apis = extractApis(content);
    if (!apis.length && content.length < 8) continue;
    steps.push({
      n: steps.length + 1,
      location: "",
      action: content.slice(0, 160),
      title: (apis[0] || content).slice(0, 120),
      detail: content,
      apis,
      raw: s,
    });
  }
  return steps.slice(0, 10);
}

/** | n | 位置 | 动作 | 涉及函数/API | 对象 | 结果 | 证据 | */
function parseChainTable(md) {
  const steps = [];
  for (const line of (md || "").split("\n")) {
    const s = line.trim();
    if (!/^\|\s*\d+\s*\|/.test(s) || /^\|\s*-+/.test(s)) continue;
    const cells = s.replace(/^\||\|$/g, "").split("|").map(c => c.trim());
    if (!cells[0] || !/^\d+$/.test(cells[0])) continue;
    const location = cells[1] || "";
    const action = cells[2] || "";
    const apiCell = cells[3] || "";
    const object = cells[4] || "";
    const result = cells[5] || "";
    const evidence = cells[6] || "";
    const apis = extractApis(`${apiCell} ${action}`);
    const thread = /线程\s*A/i.test(action) ? "A" : /线程\s*B/i.test(action) ? "B" : "";
    steps.push({
      n: parseInt(cells[0], 10),
      location,
      action,
      title: (apis[0] || action || location).slice(0, 120),
      detail: action || result,
      result,
      object,
      evidence,
      thread,
      apis,
      raw: s,
    });
  }
  return steps.slice(0, 10);
}

function isNoiseChainLine(text) {
  const t = String(text || "").replace(/[*`_]/g, "").trim();
  return /^(原语类型|对象所在池|影响路径|不编写|UAF\s*读|UAF\s*写|步骤\s*\d+\s*切断|切断步骤)/.test(t)
    || /仅描述概念/.test(t);
}

/** Pull Win32 / Winsock / Afd* style symbols out of free text. */
function extractApis(text) {
  const found = [];
  const seen = new Set();
  const push = (name) => {
    let n = String(name || "").trim().replace(/[`'"]/g, "");
    if (!n || n.length < 2 || n.length > 64) return;
    if (/^(等|无|或|and|or|N\/A|NULL|技术|mation|tion|name)$/i.test(n)) return;
    if (/^0x/i.test(n)) return;
    n = n.replace(/\(\)$/, "");
    if (!/^[A-Za-z_][\w]*$/.test(n)) return;
    const key = n.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    const userish = /^(socket|bind|listen|accept|connect|closesocket|getsockopt|setsockopt|recvfrom|sendto|WSA)/i.test(n);
    found.push(userish ? `${n}()` : n);
  };

  const src = String(text || "");
  for (const m of src.matchAll(/`([^`]+)`/g)) {
    for (const part of m[1].split(/[,，、;/|]+/)) {
      const chunk = part.trim();
      if (!chunk) continue;
      const ident = chunk.replace(/\(\)$/, "").trim();
      if (/^[A-Za-z_][\w.]*$/.test(ident)) {
        push(ident);
        continue;
      }
      if (/(?:^|[\s,，、])(?:或|\bor\b)(?:$|[\s,，、])/i.test(chunk)) {
        for (const piece of chunk.split(/\s*(?:或|\bor\b)\s*/i)) {
          const tok = piece.match(/[A-Za-z_][\w]{1,}/);
          if (tok) push(tok[0]);
        }
      } else {
        const tok = chunk.match(/[A-Za-z_][\w.]{1,}/);
        if (tok) push(tok[0]);
      }
    }
  }

  const re = /\b((?:Afd|Nt|Zw|Ke|Ex|Io|Mm|Ob|Rtl|Ps|Se|Hal|WSA)[A-Za-z][\w]*|(?:socket|bind|listen|accept|connect|closesocket|getsockopt|setsockopt|recvfrom|sendto|DeviceIoControl|CreateFile(?:W|A)?))\b/g;
  let m;
  while ((m = re.exec(src))) push(m[1]);
  return found.slice(0, 8);
}

function enrichStep(st) {
  const text = `${st.location || ""} ${st.action || ""} ${st.title || ""} ${st.detail || ""} ${st.result || ""} ${st.raw || ""}`;
  const apis = (st.apis && st.apis.length) ? st.apis.slice(0, 3) : extractApis(text);
  const kind = classifyChainStep(st);
  const kindLabel = { user: "用户态", kernel: "内核", prim: "原语", impact: "影响", patch: "补丁" };
  const location = st.location
    || (kind === "user" ? "用户态" : kind === "kernel" ? "内核" : (kindLabel[kind] || ""));
  const title = apis.length
    ? apis.slice(0, 2).join(" / ")
    : shortLabel(st.action || st.title || "", 40);
  const evidence = normalizeEvidence(st.evidence || "");
  const thread = st.thread
    || (/线程\s*A/i.test(st.action || "") ? "A" : /线程\s*B/i.test(st.action || "") ? "B" : "");
  return {
    ...st,
    apis,
    kind,
    location,
    title,
    action: st.action || st.detail || "",
    evidence,
    thread,
  };
}

function normalizeEvidence(ev) {
  const t = String(ev || "").replace(/[*`]/g, "").trim();
  if (!t) return "";
  if (/已证实|confirmed|proven/i.test(t)) return "已证实";
  if (/推断|推测|heuristic|likely/i.test(t)) return "推断";
  return t.slice(0, 12);
}

function classifyChainStep(st) {
  const loc = String(st.location || "");
  if (/用户态|user/i.test(loc)) return "user";
  if (/补丁|patch/i.test(loc)) return "patch";
  const result = String(st.result || "");
  const action = String(st.action || "");
  if (/切断|补丁修复|新增.*锁|引用计数保护/i.test(action) && /补丁|切断|Feature|KeAcquire/i.test(`${action} ${result}`)) {
    return "patch";
  }
  if (/UAF|原语|任意写|任意读|类型混淆|信息泄露|池块重用/i.test(result)) return "prim";
  if (/EoP|提权|SYSTEM|本地特权|DoS/i.test(result)) return "impact";
  if (/发生\s*UAF|形成原语/i.test(action)) return "prim";
  if (/用户态|Winsock/i.test(`${loc} ${action}`)) return "user";
  return "kernel";
}

function parseChainMeta(md) {
  const text = String(md || "");
  const meta = { oneLiner: "", primitive: "", impact: "", patches: [], object: "" };

  const primSec = text.match(/###\s*6\.3[^\n]*\n([\s\S]*?)(?=###\s*6\.4|###\s*\d|$)/i);
  const patchSec = text.match(/###\s*6\.4[^\n]*\n([\s\S]*?)(?=###\s*\d|^##\s|\s*$)/i);
  const primBody = (primSec && primSec[1]) || "";
  const patchBody = (patchSec && patchSec[1]) || "";

  const primLine = primBody.match(/\*\*原语类型\*\*[：:]\s*([^\n]+)/)
    || primBody.match(/原语类型[：:]\s*([^\n]+)/)
    || primBody.match(/^\s*([^\n]{8,80})/m);
  if (primLine) meta.primitive = primLine[1].replace(/[*`]/g, "").trim().slice(0, 120);

  const pool = primBody.match(/\*\*对象所在池\*\*[：:]\s*([^\n]+)/)
    || primBody.match(/对象所在池[：:]\s*([^\n]+)/);
  if (pool) meta.object = pool[1].replace(/[*`]/g, "").trim().slice(0, 140);

  const impact = primBody.match(/\*\*影响路径\*\*[：:]\s*([\s\S]*?)(?=\n\s*\*\*|\n\s*###|$)/)
    || primBody.match(/影响路径[：:]\s*([\s\S]*?)(?=\n\s*\*\*|\n\s*###|$)/);
  if (impact) {
    meta.impact = impact[1]
      .split("\n")
      .map(l => l.replace(/^[-*+]\s*/, "").replace(/[*`]/g, "").trim())
      .filter(l => l && !/不编写|仅描述/.test(l))
      .slice(0, 2)
      .join("；")
      .slice(0, 160);
  }

  for (const line of patchBody.split("\n")) {
    const s = line.trim();
    const m = s.match(/^(?:\d+[.)、]|[-*+])\s*(.+)$/);
    if (!m) continue;
    const content = m[1].replace(/[*`]/g, "").trim();
    if (!content || /Feature 关闭/.test(content)) continue;
    const apis = extractApis(content);
    meta.patches.push({
      text: content.slice(0, 140),
      apis,
    });
    if (meta.patches.length >= 5) break;
  }

  return meta;
}

function buildOneLiner(steps, meta) {
  if (meta && meta.oneLiner) return meta.oneLiner;
  const parts = (steps || []).map(st => {
    if (st.apis && st.apis[0]) return st.apis[0];
    if (st.kind === "prim") return "UAF";
    if (st.kind === "impact") return "EoP";
    return null;
  }).filter(Boolean);
  // de-dupe consecutive
  const uniq = [];
  for (const p of parts) {
    if (uniq[uniq.length - 1] === p) continue;
    uniq.push(p);
  }
  return uniq.slice(0, 8).join(" → ");
}

function extractMermaidBlocks(md) {
  const blocks = [];
  const re = /```mermaid\s*([\s\S]*?)```/gi;
  let m;
  while ((m = re.exec(md || ""))) {
    const code = sanitizeMermaidSource(m[1].trim());
    if (code) blocks.push(code);
  }
  return blocks;
}

function shortLabel(text, max = 36) {
  let s = String(text || "")
    .replace(/[*`_~]+/g, "")
    .replace(/【.*?】/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

function sanitizeMermaidLabel(text) {
  return shortLabel(text, 36)
    .replace(/[[\]{}|\\]/g, " ")
    .replace(/"/g, "'")
    .replace(/</g, "＜")
    .replace(/>/g, "＞")
    .replace(/#/g, "")
    .replace(/\s+/g, " ")
    .trim() || "步骤";
}

function sanitizeMermaidSource(code) {
  if (!code) return "";
  let s = String(code).replace(/\r\n/g, "\n").trim();
  s = s.replace(/^```mermaid\s*/i, "").replace(/```$/i, "").trim();
  s = s.replace(/\s*-->\s*\|[^|\n]*\+[^|\n]*\|\s*/g, " ==> ");
  s = s.replace(/\s*-\.->\s*\|[^|\n]*\|\s*/g, " -.-> ");
  s = s.replace(/^\s*classDef\s+\S+\s+.*#.*$/gm, "");
  s = s.replace(/:::\w+/g, "");
  s = s.replace(/\$/g, "_");
  s = s.replace(
    /^(\s*subgraph)\s+([^\s"\[][^\n]*)$/gm,
    (_, kw, title) => {
      const clean = sanitizeMermaidLabel(title);
      const idBase = clean.replace(/[^\w\u4e00-\u9fff]/g, "").slice(0, 12);
      const id = "sg_" + (idBase || "g");
      return `${kw} ${id}["${clean}"]`;
    }
  );
  if (!/^(flowchart|graph|sequenceDiagram|stateDiagram)/m.test(s)) {
    s = "flowchart TB\n" + s;
  }
  return s;
}

function mermaidFnId(name) {
  let raw = String(name || "fn").replace(/[^\w]/g, "_").replace(/_+/g, "_").replace(/^_|_$/g, "").slice(0, 40) || "fn";
  if (/^\d/.test(raw)) raw = "n_" + raw;
  if (/^(end|graph|subgraph|flowchart|class|classDef|style|click|linkStyle|interpolate|default)$/i.test(raw)) {
    raw = "fn_" + raw;
  }
  return "F_" + raw;
}

function mermaidFnLabel(name, delta) {
  let s = String(name || "fn")
    .replace(/\(\)$/, "")
    .replace(/[^\w.]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .slice(0, 40) || "fn";
  if (typeof delta === "number" && delta) {
    s += delta > 0 ? ` plus${delta}` : ` minus${Math.abs(delta)}`;
  }
  return s;
}

function isJunkFn(name) {
  const n = String(name || "").trim();
  return !n || /^\d+$/.test(n) || /^(?:\?\?|WPP_|__imp_|const_)/.test(n) || n.includes("??_C@") || n.includes("?$");
}

function buildFuncLogicGraph(art) {
  const interest = /Feature_|SpinLock|ExFree|ExAllocate|ExEnter|ExRelease|TdiCopy|KeAcquire|KeRelease|IoComplete|ProbeFor|Obf|MmProbe|RtlCopy|^Afd|^Nt|^Zw|Interlocked/i;
  const skip = /^(memcpy|memmove|memset|memcmp|memchr|_guard_|__security|__chkstk|__GSHandlerCheck|__C_specific_handler)/i;
  const resized = Object.fromEntries(((art.symbol_diff || {}).functions_resized || []).filter(f => f.name).map(f => [f.name, f]));
  const blocks = [...(art.disassembly || [])];
  const control = [...(art.control_disasm || [])];
  const byName = {};
  for (const b of [...blocks, ...control]) if (b.name) byName[b.name] = b;
  const hotspot = new Set(blocks.map(b => b.name).filter(Boolean));
  const deltaOf = b => {
    const o = b?.old?.size, n = b?.new?.size;
    return o != null && n != null ? n - o : (resized[b?.name]?.delta);
  };
  const ranked = [...blocks].filter(b => b.name && !isJunkFn(b.name)).sort((a, b) => Math.abs(deltaOf(b) || 0) - Math.abs(deltaOf(a) || 0)).slice(0, 8);
  const nodes = new Map();
  const edgeMap = new Map();
  const addNode = (name, kind) => {
    if (!name || nodes.has(name) || isJunkFn(name)) return;
    const b = byName[name] || {};
    const d = deltaOf(b) ?? resized[name]?.delta;
    let k = kind;
    if (!k) k = hotspot.has(name) || resized[name] ? "hotspot" : "callee";
    if (/^Feature|^Wil/.test(name)) k = "feature";
    nodes.set(name, {
      id: name,
      kind: k,
      delta: d,
      old_rva: b.old?.rva || resized[name]?.old_rva,
      new_rva: b.new?.rva || resized[name]?.new_rva,
    });
  };
  const addEdge = (from, to, change) => {
    if (!from || !to || from === to || isJunkFn(from) || isJunkFn(to)) return;
    const key = `${from}\0${to}`;
    const prev = edgeMap.get(key);
    if (!prev || (change !== "both" && prev === "both")) edgeMap.set(key, change);
  };
  for (const b of ranked) {
    const caller = b.name;
    if (!caller) continue;
    addNode(caller, "hotspot");
    const oldC = new Set(b.old?.calls || []);
    const newC = new Set(b.new?.calls || []);
    const all = [...new Set([...oldC, ...newC])];
    const kept = [];
    const extra = [];
    for (const c of all) {
      if (!c || c === caller || skip.test(c) || isJunkFn(c)) continue;
      if (hotspot.has(c) || byName[c] || interest.test(c)) kept.push(c);
      else extra.push(c);
    }
    for (const c of [...kept, ...extra.slice(0, 3)]) {
      addNode(c);
      const ch = oldC.has(c) && newC.has(c) ? "both" : newC.has(c) ? "added" : "removed";
      addEdge(caller, c, ch);
    }
  }
  const edges = [...edgeMap.entries()].map(([k, change]) => {
    const [from, to] = k.split("\0");
    return { from, to, change };
  }).slice(0, 48);
  const keep = new Set(edges.flatMap(e => [e.from, e.to]));
  const nodeList = [...nodes.values()].filter(n => keep.has(n.id));
  const mermaid = funcLogicMermaid(nodeList, edges);
  return { nodes: nodeList, edges, mermaid };
}

function funcLogicMermaid(nodes, edges) {
  const lines = ["flowchart TB"];
  const used = new Set();
  const idOf = new Map();
  for (const n of nodes || []) {
    const nid = mermaidFnId(n.id);
    if (!n.id || used.has(nid)) continue;
    used.add(nid);
    idOf.set(n.id, nid);
    lines.push(`  ${nid}["${mermaidFnLabel(n.id, n.delta)}"]`);
  }
  let nEdge = 0;
  for (const e of edges || []) {
    const a = idOf.get(e.from), b = idOf.get(e.to);
    if (!a || !b || a === b) continue;
    if (e.change === "added") lines.push(`  ${a} ==> ${b}`);
    else if (e.change === "removed") lines.push(`  ${a} -.-> ${b}`);
    else lines.push(`  ${a} --> ${b}`);
    nEdge += 1;
    if (nEdge >= 16) break;
  }
  return lines.join("\n");
}

function shapeVulnFuncChain(logic, chain) {
  const stepFns = [];
  const seen = new Set();
  const kindOf = new Map();
  for (const st of chain.steps || []) {
    for (const api of st.apis || []) {
      const name = String(api).replace(/\(\)$/, "").trim();
      if (!name || isJunkFn(name) || !/^[A-Za-z_][\w]*$/.test(name)) continue;
      if (/^(mation|tion|name|Inf|core)$/i.test(name)) continue;
      if (name.length < 4 && !/^(bind|recv|send|open|read)$/i.test(name)) continue;
      const key = name.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      stepFns.push(name);
      if (st.kind && !kindOf.has(name)) kindOf.set(name, st.kind);
      if (stepFns.length >= 10) break;
    }
    if (stepFns.length >= 10) break;
  }
  for (let i = stepFns.length - 1; i >= 0; i--) {
    const n = stepFns[i];
    if (stepFns.some((o, j) => j !== i && o.toLowerCase().startsWith(n.toLowerCase()) && o.length > n.length + 2)) {
      stepFns.splice(i, 1);
    }
  }
  const callEdges = logic.edges || [];
  const nodeMeta = Object.fromEntries((logic.nodes || []).map(n => [n.id, n]));
  const byFrom = new Map();
  for (const e of callEdges) {
    if (!byFrom.has(e.from)) byFrom.set(e.from, []);
    byFrom.get(e.from).push(e);
  }
  const nodes = new Map();
  const edges = [];
  const addNode = (name, kind) => {
    if (!name || isJunkFn(name) || nodes.has(name)) {
      if (name && kind && nodes.has(name) && kind !== "callee") nodes.get(name).kind = kind;
      return;
    }
    const meta = nodeMeta[name] || { id: name };
    let k = kind || kindOf.get(name) || meta.kind || "callee";
    if (!["hotspot", "callee", "feature", "user", "prim", "patch"].includes(k)) k = "hotspot";
    nodes.set(name, { ...meta, id: name, kind: k });
  };
  const addEdge = (from, to, change) => {
    if (!from || !to || from === to || edges.length >= 16) return;
    if (edges.some(e => e.from === from && e.to === to)) return;
    addNode(from);
    addNode(to);
    edges.push({ from, to, change: change || "both" });
  };
  const findCall = (a, b) => callEdges.find(e => e.from === a && e.to === b);

  if (stepFns.length >= 2) {
    stepFns.forEach((fn, i) => {
      addNode(fn, kindOf.get(fn) || nodeMeta[fn]?.kind || "hotspot");
      if (i > 0) {
        const real = findCall(stepFns[i - 1], fn);
        addEdge(stepFns[i - 1], fn, real ? real.change : "both");
      }
    });
    for (const fn of stepFns) {
      let n = 0;
      for (const e of byFrom.get(fn) || []) {
        if (n >= 2 || stepFns.includes(e.to)) continue;
        addNode(e.to, nodeMeta[e.to]?.kind || "callee");
        addEdge(fn, e.to, e.change);
        n += 1;
      }
    }
  } else {
    const callers = [...new Set(callEdges.map(e => e.from))].slice(0, 4);
    for (const c of callers) {
      addNode(c, "hotspot");
      let n = 0;
      for (const e of byFrom.get(c) || []) {
        if (n >= 3) break;
        addNode(e.to, nodeMeta[e.to]?.kind || "callee");
        addEdge(c, e.to, e.change);
        n += 1;
      }
    }
    if (!edges.length && stepFns.length) addNode(stepFns[0], kindOf.get(stepFns[0]) || "hotspot");
  }
  const nodeList = [...nodes.values()];
  return { nodes: nodeList, edges, mermaid: funcLogicMermaid(nodeList, edges) };
}

function stepsToMermaid(steps) {
  const lines = ["flowchart TD"];
  (steps || []).forEach((st, i) => {
    const id = `N${i + 1}`;
    const kind = st.kind || "kernel";
    const apiLabel = (st.apis && st.apis.length)
      ? st.apis.slice(0, 2).join(" / ")
      : (st.title || `step${i + 1}`);
    const shape = kind === "prim" || kind === "impact"
      ? `${id}{"${sanitizeMermaidLabel(apiLabel)}"}`
      : `${id}["${sanitizeMermaidLabel(apiLabel)}"]`;
    lines.push(`  ${shape}:::${kind}`);
    if (i > 0) {
      const prev = steps[i - 1];
      const race = (prev.thread === "A" && st.thread === "B") || (prev.thread === "B" && st.thread === "A");
      lines.push(race ? `  N${i} -.-> ${id}` : `  N${i} --> ${id}`);
    }
  });
  lines.push("  classDef user fill:#E3F2FD,stroke:#0288D1,color:#01579B");
  lines.push("  classDef kernel fill:#F7F9FB,stroke:#90A4AE,color:#37474F");
  lines.push("  classDef prim fill:#ECEFF1,stroke:#546E7A,color:#263238");
  lines.push("  classDef impact fill:#FFEBEE,stroke:#C62828,color:#B71C1C");
  lines.push("  classDef patch fill:#E3F2FD,stroke:#0288D1,color:#01579B");
  return lines.join("\n");
}

function normalizeChain(chain) {
  let steps = [];
  if (chain.markdown) {
    const fromMd = parseChainSteps(chain.markdown);
    if (fromMd.length) steps = fromMd;
  }
  if (!steps.length) steps = chain.steps || [];
  steps = steps
    .map((st, i) => enrichStep({ ...st, n: st.n || i + 1 }))
    .filter(st => !isNoiseChainLine(st.title || "") && !isNoiseChainLine(st.action || ""))
    .slice(0, 10)
    .map((st, i) => ({ ...st, n: i + 1 }));

  const meta = parseChainMeta(chain.markdown || "");
  const oneLiner = buildOneLiner(steps, meta);
  meta.oneLiner = oneLiner;

  // Single auto diagram — avoid TD+LR duplicate noise.
  const diagrams = steps.length >= 2 ? [stepsToMermaid(steps)] : [];

  return {
    ...chain,
    present: !!(chain.present || steps.length || chain.markdown || diagrams.length),
    steps,
    diagrams,
    meta,
    summary: oneLiner || chain.summary || "",
  };
}

function mermaidPre(src) {
  if (!src) return "";
  return `<pre class="mermaid" data-src="${encodeURIComponent(src)}">${esc(src)}</pre>`;
}

function funcLogicMarkdown(logic) {
  const byCaller = new Map();
  for (const e of logic.edges || []) {
    if (!byCaller.has(e.from)) byCaller.set(e.from, []);
    byCaller.get(e.from).push(e);
  }
  const nodeOf = id => (logic.nodes || []).find(n => n.id === id) || { id };
  const lines = [];
  for (const caller of byCaller.keys()) {
    const n = nodeOf(caller);
    const d = typeof n.delta === "number" && n.delta ? ` (${n.delta > 0 ? "+" : ""}${n.delta})` : "";
    lines.push(`- \`${caller}\`${d}`);
    for (const e of byCaller.get(caller) || []) {
      const mark = e.change === "added" ? "+" : e.change === "removed" ? "−" : "·";
      lines.push(`  - \`[${mark}]\` \`${e.to}\``);
    }
  }
  return lines.join("\n");
}

function renderChainPanel(art) {
  const chain = extractChainClient(art || {});
  const shaped = shapeVulnFuncChain(buildFuncLogicGraph(art), chain);
  const steps = chain.steps || [];
  const changeLabel = { both: "漏洞链顺序 / 两版都有", added: "修复版新增 CALL", removed: "漏洞版已去掉" };
  const edgeRows = (shaped.edges || []).map(e => {
    const n = (shaped.nodes || []).find(x => x.id === e.from) || {};
    const d = typeof n.delta === "number" ? `${n.delta > 0 ? "+" : ""}${n.delta}` : "—";
    return `<tr>
      <td>${fnLink(e.from)}</td>
      <td>${fnLink(e.to)}</td>
      <td><span class="chip ${e.change === "added" ? "add" : e.change === "removed" ? "del" : ""}">${esc(changeLabel[e.change] || e.change)}</span></td>
      <td class="${(n.delta || 0) > 0 ? "delta-pos" : (n.delta || 0) < 0 ? "delta-neg" : ""}">${esc(d)}</td>
    </tr>`;
  }).join("");
  const hasGraph = (shaped.nodes || []).length && shaped.mermaid;
  const graphHtml = hasGraph
    ? `${mermaidPre(shaped.mermaid)}
       <p class="func-logic-legend">
         <span class="chip">实线 · 漏洞链顺序 / 两版都有</span>
         <span class="chip add">粗箭头 · 修复版新增 CALL</span>
         <span class="chip del">虚线 · 漏洞版已去掉</span>
       </p>
       ${edgeRows ? table(["调用方", "被调", "含义", "调用方 Δsize"], edgeRows) : ""}`
    : `<p class="hint">当前样本还没有足够的函数名画漏洞链。完成反汇编或重新生成报告后会出现。</p>`;
  const raw = (chain.markdown || "").replace(/```mermaid[\s\S]*?```/gi, "").replace(/^###\s*6\.2[\s\S]*?(?=^###\s*6\.|\s*$)/m, "").trim();
  let narrative = "";
  if (steps.length) {
    narrative = `<ol class="chain-text-list">${steps.map(st => {
      const api = (st.apis && st.apis[0]) ? `${fnLink(st.apis[0])} · ` : "";
      const loc = st.location ? `${esc(st.location)} · ` : "";
      const action = esc(st.action || st.detail || st.title || "");
      return `<li>${loc}${api}${action}</li>`;
    }).join("")}</ol>`;
  } else if (raw) {
    narrative = mdHtml(raw) || "";
  }
  return `<section class="chain-page">
    <div class="brief-head">
      <div>
        <h3>函数逻辑漏洞链</h3>
        <p class="brief-kicker">Mermaid：节点是函数，箭头按触发顺序串起来${(shaped.edges || []).length ? ` · ${shaped.edges.length} 条` : ""}</p>
      </div>
      <div class="brief-actions">
        <button type="button" class="btn ghost" data-goto-panel="disasm">反汇编</button>
      </div>
    </div>
    <div class="func-logic-wrap">${graphHtml}</div>
    ${narrative ? `<p class="card-title" style="margin-top:1.2rem">叙事步骤</p><div class="chain-prose report-md">${narrative}</div>` : (!hasGraph ? `<p class="empty">尚未提取到漏洞链。重新生成报告后，§6 会写入完整链路。</p>` : "")}
  </section>`;
}

function typesetMath(root) {
  const renderMathInElement = globalThis.renderMathInElement;
  if (!root || typeof renderMathInElement !== "function") return;
  renderMathInElement(root, {
    delimiters: [
      { left: "$$", right: "$$", display: true },
      { left: "\\[", right: "\\]", display: true },
      { left: "$", right: "$", display: false },
      { left: "\\(", right: "\\)", display: false },
    ],
    throwOnError: false,
    ignoredTags: ["script", "noscript", "style", "textarea", "pre", "code"],
  });
}

function liftMermaidBlocks(root) {
  if (!root) return;
  root.querySelectorAll("pre > code.language-mermaid").forEach(code => {
    const pre = code.parentElement;
    const wrap = document.createElement("pre");
    wrap.className = "mermaid report-mermaid";
    wrap.textContent = code.textContent || "";
    pre.replaceWith(wrap);
  });
}

function resetCollapsedMermaid(root) {
  if (!root) return;
  root.querySelectorAll(".mermaid").forEach(el => {
    const svg = el.querySelector("svg");
    const packed = el.getAttribute("data-src") || el.getAttribute("data-m");
    if (svg && svg.getBoundingClientRect().height >= 24 && svg.querySelector(".node, .actor, g")) return;
    if (!packed && !el.textContent.trim()) return;
    let src = (el.textContent || "").trim();
    if (packed) {
      try { src = decodeURIComponent(packed); } catch { src = packed; }
    }
    if (!src) return;
    el.textContent = src;
    el.removeAttribute("data-processed");
  });
}

async function renderMermaidIn(root) {
  if (!root || !window.mermaid) return;
  const nodes = [...root.querySelectorAll(".mermaid")].filter(el => !el.querySelector("svg") && !el.getAttribute("data-processed"));
  if (!nodes.length) return;
  try {
    const mermaid = globalThis.mermaid;
    mermaid.initialize({
      startOnLoad: false,
      theme: "neutral",
      securityLevel: "loose",
      flowchart: { curve: "basis", htmlLabels: false, padding: 12, useMaxWidth: true, nodeSpacing: 40, rankSpacing: 56 },
    });
    for (const el of nodes) {
      let src = (el.textContent || "").trim();
      const packed = el.getAttribute("data-src") || el.getAttribute("data-m");
      if (packed) {
        try { src = decodeURIComponent(packed); } catch { /* keep text */ }
      }
      src = sanitizeMermaidSource(src);
      if (!src) continue;
      el.setAttribute("data-src", encodeURIComponent(src));
      try {
        const id = "mmd" + Math.random().toString(36).slice(2, 10);
        const out = await mermaid.render(id, src);
        el.innerHTML = out.svg || "";
        el.setAttribute("data-processed", "true");
        if (typeof out.bindFunctions === "function") out.bindFunctions(el);
        el.querySelectorAll("svg .node").forEach(g => {
          const t = g.querySelector("text");
          if (!t) return;
          const raw = (t.textContent || "").replace(/\s+plus\d+\s*$/, "").replace(/\s+minus\d+\s*$/, "").trim();
          if (raw) {
            g.setAttribute("data-goto-fn", raw);
            g.style.cursor = "pointer";
          }
        });
      } catch (err) {
        console.warn("mermaid node failed", err);
        el.removeAttribute("data-processed");
        el.textContent = src;
      }
    }
  } catch (err) {
    console.warn("mermaid render failed", err);
  }
}

async function renderMarkdownReport(el, md) {
  el.innerHTML = mdHtml(md) || `<pre>${esc(md || "")}</pre>`;
  salvageTablesInDom(el);
  convertTablesToProse(el);
  await hydrateMarkdown(el);
}

function mdTable(headers, rows) {
  if (!rows.length) return "_无_\n";
  const val = c => (c == null || c === "") ? "—" : String(c);
  if (headers.length <= 2) {
    return rows.map(r => `- **${val(r[0])}**：${val(r[1])}`).join("\n") + "\n";
  }
  return rows.map(r => {
    const { step, text } = narrativeFromRow(headers, r);
    return step ? `${step}. ${text}` : text;
  }).join("\n\n") + "\n";
}

function demoteSpecialistHeadings(md) {
  return String(md || "").replace(/^#{1,2}(?!#)\s+/gm, "### ");
}

function iocSectionMarkdown(pack) {
  const identRows = (pack.identity || []).map(item => [
    item.role || "",
    item.filename || "",
    item.file_version || "",
    item.machine || "",
    item.sha256 ? `\`${item.sha256}\`` : "—",
    item.md5 ? `\`${item.md5}\`` : "—",
  ]);
  const apiU = pack.apis?.user_mode || [];
  const apiK = pack.apis?.kernel || [];
  const huntRows = (pack.hunts || []).map(h => [
    h.n ?? "",
    h.location || "",
    (h.apis || []).join(", ") || "—",
    String(h.action || "").slice(0, 80),
  ]);
  const featRows = (pack.features || []).map(f => [
    f.feature_id || "",
    f.featureState_rva || "",
    f.on_disk_dword ?? "",
    (f.gated_functions || []).join(", ") || "—",
  ]);
  const fnRows = (pack.functions || []).map(f => [
    f.name ? `\`${f.name}\`` : "",
    f.old_rva || "",
    f.new_rva || "",
    f.old_size ?? f.old ?? "",
    f.new_size ?? f.new ?? "",
    f.delta ?? "",
  ]);
  const vuln = (pack.identity || []).find(i => i.role === "vulnerable") || {};
  const patched = (pack.identity || []).find(i => i.role === "patched") || {};
  const cve = pack.cve || "";
  const component = pack.component || vuln.filename || "";
  const kbs = pack.kbs || [];
  let sigma = "缺少漏洞版 SHA256，无法生成映像加载规则。";
  if (vuln.sha256) {
    sigma = [
      "```yaml",
      `title: Patchalyzer.ai vulnerable driver ${cve || component || ""}`.trim(),
      "logsource:",
      "  product: windows",
      "  category: image_load",
      "detection:",
      "  selection:",
      `    Hashes|contains: '${vuln.sha256}'`,
      component ? `    OriginalFileName: '${component}'` : null,
      vuln.file_version ? `    FileVersion: '${vuln.file_version}'` : null,
      "  condition: selection",
      "falsepositives:",
      "  - 已打补丁但仍缓存旧映像的安装介质",
      "level: high",
      "```",
    ].filter(x => x != null).join("\n");
  }
  let notes = demoteSpecialistHeadings((pack.detection_notes || "").trim());
  if (!notes || notes.startsWith("（")) {
    notes = "可依据上表做资产清点：匹配漏洞版 SHA256 / FileVersion，并关注用户态 API 时序与热点内核函数。";
  }
  return [
    "## 16. IOC / 检测方法",
    "",
    "文件哈希与版本号来自样本实算，可用于资产清点与威胁狩猎。",
    "",
    `- CVE：\`${cve || "（标题未解析到 CVE）"}\``,
    `- 组件：\`${component || "—"}\``,
    `- 建议补丁版本：\`${patched.file_version || "见修复版样本"}\`${kbs.length ? `（KB${kbs.join(", KB")}）` : ""}`,
    "",
    "### 16.1 样本身份（IOC）",
    "",
    mdTable(["角色", "文件名", "FileVersion", "架构", "SHA256", "MD5"], identRows),
    "### 16.2 行为检测线索",
    "",
    `- 用户态 API：${apiU.length ? apiU.map(x => `\`${x}\``).join("、") : "（漏洞链未抽出用户态 API）"}`,
    `- 内核函数：${apiK.length ? apiK.map(x => `\`${x}\``).join("、") : "（见热点函数表）"}`,
    "",
    huntRows.length ? mdTable(["步骤", "位置", "API/函数", "动作"], huntRows) : "",
    "### 16.3 Feature / 热点函数",
    "",
    featRows.length ? mdTable(["Feature", "featureState RVA", "on-disk", "门控函数"], featRows) : "无新增 Feature。\n",
    mdTable(["函数", "Old RVA", "New RVA", "Old size", "New size", "Δ"], fnRows),
    "### 16.4 示例 Sigma（映像加载）",
    "",
    sigma,
    "",
    "### 16.5 运营检测方法",
    "",
    notes,
    "",
  ].join("\n");
}

function replaceNumberedSection(text, number, section) {
  const body = String(section || "").replace(/\s+$/, "") + "\n\n";
  const src = String(text || "").replace(/\r\n/g, "\n");
  if (!new RegExp(`^##\\s*${number}\\.`, "m").test(src)) {
    return `${src.replace(/\s+$/, "")}\n\n${body}`;
  }
  const untilNext = new RegExp(`^##\\s*${number}\\.[^\\n]*\\n[\\s\\S]*?(?=^##\\s*\\d+\\.)`, "m");
  const replaced = src.replace(untilNext, body);
  if (replaced !== src) return replaced;
  return src.replace(new RegExp(`^##\\s*${number}\\.[\\s\\S]*$`, "m"), body);
}

function ensureIocSection(md, pack) {
  return replaceNumberedSection(md, 16, iocSectionMarkdown(pack));
}

function threatSectionMarkdown(pack) {
  pack = pack || {};
  const kev = pack.kev || {};
  const nvd = pack.nvd || {};
  const epss = pack.epss || {};
  const hits = pack.search_hits || [];
  const hitMd = hits.map(h => {
    const title = h.title || h.url || "结果";
    const url = h.url || "";
    const snippet = (h.snippet || "").trim();
    const link = url ? `[${title}](${url})` : title;
    return `- ${link}` + (snippet ? `  \n  ${snippet}` : "");
  }).join("\n") || "- 未检索到相关公开报道";
  let notes = demoteSpecialistHeadings((pack.threat_notes || "").trim());
  if (!notes || notes.startsWith("（")) {
    notes = "尚无分析师解读。检索结果见下节。";
  }
  const errs = (pack.errors || []).map(e => `- ${e}`).join("\n");
  return [
    "## 17. 在野利用 / 威胁情报",
    "",
    pack.summary || "",
    "",
    "### 17.1 分析师解读",
    "",
    notes,
    "",
    "### 17.2 检索结果",
    "",
    hitMd,
    "",
    "### 17.3 目录对照",
    "",
    mdTable(["项", "值"], [
      ["CVE", pack.cve || "（未解析到 CVE）"],
      ["CISA KEV", pack.in_kev ? `是 · ${kev.date_added || ""}` : (pack.status === "not_in_kev" ? "否" : "—")],
      ["勒索软件活动（CISA）", kev.ransomware || pack.ransomware_campaign || "—"],
      ["NVD CVSS", [nvd.cvss, nvd.severity].filter(Boolean).join(" ") || "—"],
      ["EPSS", epss.epss != null ? `${epss.epss}（percentile ${epss.percentile ?? "—"}）` : "—"],
      ["检索时间", pack.fetched_at || "—"],
    ]),
    errs ? `**查询告警**\n\n${errs}\n` : "",
    "",
  ].filter(x => x != null).join("\n");
}

function ensureThreatSection(md, pack) {
  return replaceNumberedSection(md, 17, threatSectionMarkdown(pack));
}

function reviewSectionMarkdown(kind, pack) {
  pack = pack || {};
  if (kind === "bypass") {
    const title = (BYPASS_META[pack.verdict] || BYPASS_META.unknown).title;
    const rows = (pack.findings || []).map(f => [f.method || "—", f.target || "—", f.status || "—", f.likelihood || "—", f.evidence || "—"]);
    return [
      "## 18. 补丁完整性 / 绕过面",
      "",
      `**结论**：${title}。${pack.summary || ""}`.trim(),
      "",
      "### 18.1 分析师解读",
      "",
      demoteSpecialistHeadings((pack.notes || "").trim()) || "尚无 BypassAnalyst 解读。",
      "",
      "### 18.2 绕过面清单",
      "",
      rows.length ? mdTable(["维度", "涉及函数", "状态", "可能性", "证据"], rows) : "本样本未列出可核对的绕过面。",
      "",
    ].join("\n");
  }
  const title = (RESIDUAL_META[pack.verdict] || RESIDUAL_META.unknown).title;
  const rows = (pack.findings || []).map(f => [f.function || "—", f.pattern || "—", f.severity || "—", f.status || "—", f.evidence || "—"]);
  return [
    "## 19. 残留漏洞 / 同类缺陷",
    "",
    `**结论**：${title}。${pack.summary || ""}`.trim(),
    "",
    "### 19.1 分析师解读",
    "",
    demoteSpecialistHeadings((pack.notes || "").trim()) || "尚无 ResidualVulnAnalyst 解读。",
    "",
    "### 19.2 嫌疑函数",
    "",
    rows.length ? mdTable(["函数", "模式", "严重度", "状态", "证据"], rows) : "未发现与本次根因同类的未修复函数。",
    "",
  ].join("\n");
}

function ensureNumberedSection(md, number, section) {
  return replaceNumberedSection(md, number, section);
}

function reportMarkdown() {
  if (!lastJobData) return "";
  const art = lastJobData.result?.artifacts || {};
  let md = unwrapMarkdownFence(art.llm_report || "");
  md = ensureFuncLogicInReport(md, art);
  md = ensureIocSection(md, iocFromJob(lastJobData));
  md = ensureThreatSection(md, art.threat_intel || {});
  md = ensureNumberedSection(md, 18, reviewSectionMarkdown("bypass", art.bypass_pack || {}));
  md = ensureNumberedSection(md, 19, reviewSectionMarkdown("residual", art.residual_pack || {}));
  return md;
}

let fullReportJobId = null;
function stampReportHeadings(root) {
  root.querySelectorAll("h1, h2").forEach(h => {
    const m = String(h.textContent || "").match(/^(\d+)\.\s/);
    if (m) h.id = `report-sec-${m[1]}`;
  });
}

function reportTocHtml(md) {
  const { sections } = splitReportSections(md);
  if (sections.length < 3) return "";
  return `<nav class="report-toc" aria-label="报告目录">${sections.map(s => {
    const title = REPORT_EXPORT_SECTIONS.find(x => x.n === s.n)?.title || "";
    return `<a href="#report-sec-${s.n}" data-report-sec="${s.n}">${s.n}. ${esc(title)}</a>`;
  }).join("")}</nav>`;
}

function bindReportTocSpy() {
  const body = document.querySelector("#job-modal .drawer-body");
  const toc = document.querySelector("#panel-fullreport .report-toc");
  if (!body || !toc) return;
  const heads = [...document.querySelectorAll("#panel-fullreport [id^=report-sec-]")];
  const onScroll = () => {
    let current = heads[0];
    for (const h of heads) {
      if (h.getBoundingClientRect().top <= 160) current = h;
    }
    const id = current?.id?.replace(/^report-sec-/, "") || "";
    toc.querySelectorAll("a").forEach(a => a.classList.toggle("on", a.dataset.reportSec === id));
  };
  if (body._tocSpy) body.removeEventListener("scroll", body._tocSpy);
  body._tocSpy = onScroll;
  body.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
}

function fillFullReportPanel() {
  const el = $("#panel-fullreport");
  if (!el || !lastJobData) return;
  const art = lastJobData.result?.artifacts || {};
  const sig = `${lastJobData.id}:${String(art.llm_report || "").length}`;
  if (fullReportJobId === sig && el.querySelector(".report-md")) return;
  const fullMd = reportMarkdown();
  const nums = presentSectionNumbers(fullMd);
  const missing = REPORT_EXPORT_SECTIONS.map(s => s.n).filter(n => !nums.has(n));
  const kicker = missing.length
    ? `缺 §${missing.join("、")}。已用专家笔记补全缺节，可点「重新生成报告」重写全文。`
    : `19 节任务正文，与导出内容一致。`;
  const toc = reportTocHtml(fullMd);
  el.innerHTML = fullMd.trim()
    ? `<section class="ioc-page report-full"><div class="brief-head"><div><h3>完整报告</h3><p class="brief-kicker">${kicker}</p></div></div><div class="report-full-layout">${toc}<div class="report-md">${mdHtml(fullMd)}</div></div></section>`
    : `<section class="ioc-page"><p class="hint">尚未生成完整报告。分析完成后或点击「重新生成报告」。</p></section>`;
  stampReportHeadings(el);
  bindReportTocSpy();
  fullReportJobId = sig;
}

function ensureFuncLogicInReport(md, art) {
  const g = shapeVulnFuncChain(buildFuncLogicGraph(art), extractChainClient(art));
  if (!(g.mermaid || "").trim() || !(g.nodes || []).length) return md || "";
  const block = [
    "### 6.2 函数逻辑链",
    "",
    "节点是函数，箭头按漏洞链顺序。实线为链路顺序或两版都有的 CALL，粗箭头为修复版新增，虚线为漏洞版已去掉。",
    "",
    "```mermaid",
    g.mermaid,
    "```",
    "",
  ].join("\n");
  const text = String(md || "").replace(/\r\n/g, "\n");
  if (/^###\s*6\.2\b/m.test(text)) {
    return text.replace(/^###\s*6\.2\b[\s\S]*?(?=^###\s*6\.\d|^##\s*\d+\.|\s*$)/m, block + "\n");
  }
  if (/^##\s*6\.\s*漏洞链/m.test(text)) {
    return text.replace(/(^##\s*6\.\s*漏洞链[^\n]*\n)/m, `$1\n${block}\n`);
  }
  return text;
}

const REPORT_EXPORT_SECTIONS = [
  { n: 1, title: "执行摘要" },
  { n: 2, title: "分析方法论" },
  { n: 3, title: "CVE/MSRC 描述对照" },
  { n: 4, title: "漏洞根因" },
  { n: 5, title: "竞态/同步时序" },
  { n: 6, title: "漏洞链" },
  { n: 7, title: "汇编证据" },
  { n: 8, title: "伪代码对比" },
  { n: 9, title: "状态机/标志位" },
  { n: 10, title: "Feature 开关" },
  { n: 11, title: "用户态触发面" },
  { n: 12, title: "利用难度与影响" },
  { n: 13, title: "对照路径排除" },
  { n: 14, title: "修复有效性与残余风险" },
  { n: 15, title: "附录" },
  { n: 16, title: "IOC / 检测方法" },
  { n: 17, title: "在野利用 / 威胁情报" },
  { n: 18, title: "补丁完整性 / 绕过面" },
  { n: 19, title: "残留漏洞 / 同类缺陷" },
];
const EXPORT_SECTION_PRESETS = {
  all: REPORT_EXPORT_SECTIONS.map(s => s.n),
  core: [1, 4, 5, 6, 7, 8, 10, 13, 14],
  soc: [1, 12, 16, 17, 18, 19],
  none: [],
};
const EXPORT_SECTION_STORE = "patchalyzer.export_sections";

function splitReportSections(md) {
  const text = String(md || "").replace(/\r\n/g, "\n");
  const re = /^##\s*(\d+)\.\s[^\n]*/gm;
  const hits = [];
  let m;
  while ((m = re.exec(text))) {
    const n = Number(m[1]);
    if (n >= 1 && n <= 19) hits.push({ n, index: m.index });
  }
  const bounds = [];
  let last = 0;
  for (const h of hits) {
    if (h.n >= last) {
      bounds.push(h);
      last = h.n;
    }
  }
  const preamble = bounds.length ? text.slice(0, bounds[0].index) : text;
  const sections = bounds.map((h, i) => {
    const end = i + 1 < bounds.length ? bounds[i + 1].index : text.length;
    return { n: h.n, body: text.slice(h.index, end) };
  });
  return { preamble, sections };
}

function presentSectionNumbers(md) {
  return new Set(splitReportSections(md).sections.map(s => s.n));
}

function filterReportMarkdown(md, selected) {
  const want = new Set((selected || []).map(Number));
  if (!want.size) return "";
  const { preamble, sections } = splitReportSections(md);
  if (!sections.length) return want.size ? String(md || "") : "";
  const parts = [preamble.replace(/\s+$/, "")];
  for (const s of sections) {
    if (want.has(s.n)) parts.push(s.body.replace(/\s+$/, ""));
  }
  return parts.filter(Boolean).join("\n\n") + "\n";
}

function loadSavedExportSections() {
  try {
    const raw = JSON.parse(localStorage.getItem(EXPORT_SECTION_STORE) || "null");
    if (Array.isArray(raw) && raw.length) {
      const known = new Set(REPORT_EXPORT_SECTIONS.map(s => s.n));
      const nums = raw.map(Number).filter(n => known.has(n));
      if (nums.length) return nums;
    }
  } catch { /* ignore */ }
  return EXPORT_SECTION_PRESETS.soc.slice();
}

function selectedExportSections() {
  const boxes = $$("#export-sections input[name=export-sec]");
  if (!boxes.length) return loadSavedExportSections();
  return boxes.filter(el => el.checked).map(el => Number(el.value));
}

function persistExportSections(nums) {
  try { localStorage.setItem(EXPORT_SECTION_STORE, JSON.stringify(nums)); } catch { /* ignore */ }
}

function setExportSectionChecks(nums) {
  const want = new Set(nums.map(Number));
  $$("#export-sections input[name=export-sec]").forEach(el => {
    el.checked = want.has(Number(el.value));
  });
  persistExportSections(selectedExportSections());
}

function renderExportSectionPicker() {
  const box = $("#export-sections");
  if (!box) return;
  const present = presentSectionNumbers(reportMarkdown());
  const saved = loadSavedExportSections();
  box.innerHTML = REPORT_EXPORT_SECTIONS.map(s => {
    const miss = present.size > 0 && !present.has(s.n);
    return `<label class="${miss ? "is-missing" : ""}">
      <input type="checkbox" name="export-sec" value="${s.n}" ${saved.includes(s.n) ? "checked" : ""} />
      <span>${s.n}. ${s.title}${miss ? "<small>报告中无此节</small>" : ""}</span>
    </label>`;
  }).join("");
}

function stripReportToc(md) {
  return String(md || "").replace(/\n##\s*目录\s*\n(?:\s*\d+\.\s*\[[^\]]+\]\([^)]+\)\s*\n)+/g, "\n");
}

function selectedExportMarkdown() {
  const full = reportMarkdown().trim();
  if (!full) {
    alert("尚未生成报告，请先完成分析或重新生成报告。");
    return "";
  }
  const picked = selectedExportSections();
  if (!picked.length) {
    alert("请至少勾选一节再导出。");
    return "";
  }
  persistExportSections(picked);
  return stripReportToc(filterReportMarkdown(full, picked)).trim();
}

function exportFilename(ext) {
  const title = lastJobData?.title || currentJobId || "report";
  const slug = String(title).replace(/[^\w\u4e00-\u9fff.-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 80) || "report";
  return `${slug}.${ext}`;
}

function watermarkSvgDataUri(text) {
  const label = String(text || "Patchalyzer.ai")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="340" height="240"><text x="170" y="125" text-anchor="middle" fill="#0288d1" fill-opacity="0.07" font-size="22" font-weight="700" font-family="Segoe UI, Microsoft YaHei, sans-serif" transform="rotate(-28 170 125)">${label}</text></svg>`;
  return `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;
}

function exportDocCss({ forPrint = false } = {}) {
  const print = forPrint ? `
    html, body {
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
      color-adjust: exact;
      background-color: #fff;
      background-image: ${watermarkSvgDataUri(PRODUCT_MARK)};
      background-repeat: repeat;
      background-size: 320px 220px;
    }
    .wm-footer-fixed {
      position: fixed; left: 0; right: 0; bottom: 5px; z-index: 1;
      text-align: center; font-size: 8.5px; color: #90a4ae;
      pointer-events: none;
    }
    @page { size: A4; margin: 14mm 12mm 16mm; }
    @media print {
      .print-hint { display: none !important; }
      html, body {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
        background-color: #fff;
      }
      body { max-width: none; margin: 0; padding: 0 0 18px; }
      a { color: inherit; text-decoration: none; }
      .md-scroll, .table-wrap { overflow: visible !important; border: 0; }
      table { page-break-inside: auto; }
    }
  ` : "";
  return `
    * { box-sizing: border-box; }
    body {
      font-family: "Segoe UI", "Microsoft YaHei", sans-serif;
      color: #212121; line-height: 1.6; background: #fff;
      max-width: 880px; margin: 24px auto; padding: 0 28px 48px;
      font-size: 13px;
    }
    .report-banner {
      display: flex; justify-content: space-between; gap: 1rem; align-items: baseline;
      margin: 0 0 1.05rem; padding-bottom: 0.5rem; border-bottom: 2px solid #01579b;
    }
    .report-banner .brand { font-weight: 700; color: #01579b; font-size: 13px; letter-spacing: 0.02em; }
    .report-banner .meta { color: #607d8b; font-size: 12px; }
    .report-body h1, .report-body h2, .report-body h3, .report-body h4,
    h1, h2, h3, h4 { color: #01579b; font-weight: 600; break-after: avoid; page-break-after: avoid; }
    h1 { font-size: 1.45rem; margin: 0 0 0.55rem; }
    h2 { font-size: 1.14rem; margin-top: 1.35em; }
    h3 { font-size: 1rem; margin-top: 1em; }
    p { margin: 0.4rem 0 0.7rem; }
    ul, ol { margin: 0.3rem 0 0.8rem; padding-left: 1.3rem; }
    hr { border: 0; border-top: 1px solid #cfd8dc; margin: 1.1rem 0; }
    .md-scroll, .table-wrap { overflow-x: auto; margin: 0.65em 0 1em; }
    table, table.report-table {
      border-collapse: collapse; width: 100%; table-layout: fixed;
      margin: 0.65em 0 1em; page-break-inside: auto; break-inside: auto;
      border: 1px solid #b0bec5;
    }
    thead { display: table-header-group; }
    tfoot { display: table-footer-group; }
    tr { break-inside: avoid; page-break-inside: avoid; }
    th, td {
      border: 1px solid #b0bec5; padding: 5px 8px; text-align: left;
      font-size: 11.5px; vertical-align: top;
      overflow-wrap: anywhere; word-break: break-word;
    }
    th { background: #eceff1; font-weight: 600; white-space: normal; color: #37474f; }
    table.is-wide th, table.is-wide td { font-size: 10px; padding: 4px 6px; }
    td code, th code {
      background: #eef3f7; padding: 0.05em 0.28em; border-radius: 3px;
      font-size: 0.9em; word-break: break-all;
    }
    code {
      background: #f1f3f4; padding: 0.1em 0.35em; border-radius: 3px;
      font-family: Consolas, "Roboto Mono", monospace; font-size: 0.86em;
      overflow-wrap: anywhere; word-break: break-all;
    }
    pre {
      background: #fafbfc; padding: 12px; overflow: visible;
      border: 1px solid #e0e0e0; border-radius: 6px; white-space: pre-wrap; break-inside: auto;
    }
    pre code { background: none; padding: 0; }
    img, svg { max-width: 100%; height: auto; }
    .mermaid svg { max-width: 100% !important; height: auto !important; }
    .katex-display { overflow-x: auto; overflow-y: hidden; margin: 0.8rem 0; }
    .print-hint { background: #e3f2fd; color: #01579b; padding: 10px 14px; border-radius: 6px; font-size: 13px; }
    .report-prose { margin: 0.35em 0 0.95em; }
    .report-prose p { margin: 0.35em 0 0.65em; line-height: 1.75; }
    .mermaid, .report-mermaid { max-width: 100%; page-break-inside: avoid; }
    .mermaid, .report-mermaid { page-break-inside: avoid; max-width: 100%; }
    ${print}
  `;
}

async function buildStandaloneReportHtml({ forPrint = false } = {}) {
  const md = selectedExportMarkdown();
  if (!md) return null;
  const holder = document.createElement("div");
  await renderMarkdownReport(holder, md);
  salvageTablesInDom(holder);
  convertTablesToProse(holder);
  if (forPrint) unwrapTableWraps(holder);
  const title = lastJobData?.title || `${PRODUCT_NAME} 分析报告`;
  const meta = [
    lastJobData?.id || "",
    lastJobData?.cve || "",
    lastJobData?.created_at ? fmtDate(lastJobData.created_at) : "",
  ].filter(Boolean).join(" · ");
  const footerBits = [
    PRODUCT_MARK,
    "仅供内部分析使用",
    lastJobData?.id || "",
    lastJobData?.created_at ? fmtDate(lastJobData.created_at) : "",
  ].filter(Boolean).join("  ·  ");
  return `<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${esc(title)}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.22/dist/katex.min.css"/>
<style>${exportDocCss({ forPrint })}</style>
</head><body>
${forPrint ? `<p class="print-hint">在打印对话框中选择「另存为 PDF」，并关闭「页眉和页脚」。如需水印，请勾选「背景图形」。</p>` : ""}
<header class="report-banner">
  <div class="brand">${esc(PRODUCT_MARK)}</div>
  <div class="meta">${esc(meta)}</div>
</header>
<article class="report-body">
${holder.innerHTML}
</article>
${forPrint ? `<div class="wm-footer-fixed">${esc(footerBits)}</div>` : ""}
</body></html>`;
}

async function exportReportPdf() {
  const html = await buildStandaloneReportHtml({ forPrint: true });
  if (!html) return false;
  const iframe = document.createElement("iframe");
  iframe.setAttribute("aria-hidden", "true");
  iframe.style.cssText = "position:fixed;left:-100vw;top:0;width:210mm;height:297mm;border:0;opacity:0;pointer-events:none;";
  document.body.appendChild(iframe);
  const doc = iframe.contentDocument;
  if (!doc) {
    iframe.remove();
    alert("无法创建打印预览，请允许本页使用 iframe 后再导出 PDF。");
    return false;
  }
  doc.open();
  doc.write(html);
  doc.close();
  const win = iframe.contentWindow;
  const cleanup = () => { if (iframe.parentNode) iframe.remove(); };
  win.addEventListener("afterprint", cleanup);
  setTimeout(cleanup, 120000);
  const go = async () => {
    try {
      if (doc.fonts && doc.fonts.ready) await doc.fonts.ready;
    } catch { /* ignore */ }
    await new Promise(r => setTimeout(r, 280));
    try { win.focus(); win.print(); } catch { cleanup(); }
  };
  if (doc.readyState === "complete") setTimeout(go, 350);
  else iframe.addEventListener("load", () => setTimeout(go, 350));
  return true;
}

async function exportReportHtml() {
  const html = await buildStandaloneReportHtml({ forPrint: false });
  if (!html) return false;
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = exportFilename("html");
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2500);
  return true;
}

async function exportReportMarkdown() {
  const md = selectedExportMarkdown();
  if (!md) return false;
  const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = exportFilename("md");
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2500);
  return true;
}

function huntLabRunning(job) {
  const st = huntLabCurrent(job).status;
  return st === "running" || (Boolean(job?.hunt_lab_progress) && st !== "completed" && st !== "failed" && st !== "cancelled" && st !== "interrupted");
}

function ensureHuntLabPoll(jobId, job) {
  if (!huntLabRunning(job)) {
    clearInterval(huntLabTimer);
    return;
  }
  clearInterval(huntLabTimer);
  let busy = false;
  huntLabTimer = setInterval(async () => {
    if (busy) return;
    busy = true;
    try {
    const r = await fetch(`${API}/jobs/${jobId}?lite=1`);
    if (!r.ok) return;
    const j = await r.json();
    if (currentJobId !== jobId) return;
    const viewing = huntLabRunning(j) ? null : lastJobData?._huntView;
    const prev = lastJobData || {};
    const prevArt = (prev.result && prev.result.artifacts) || {};
    const nextArt = (j.result && j.result.artifacts) || {};
    lastJobData = {
      ...prev,
      ...j,
      result: { ...(prev.result || {}), artifacts: { ...prevArt, ...nextArt } },
    };
    if (viewing) lastJobData._huntView = viewing;
    const panel = $("#panel-huntlab");
    if (panel) {
      panel.innerHTML = renderHuntLabPanel(lastJobData);
      hydrateMarkdown(panel);
    }
    const st = huntLabCurrent(j).status;
    if (st === "completed" || st === "failed" || st === "cancelled" || !huntLabRunning(j)) {
      clearInterval(huntLabTimer);
    }
    } catch { /* keep last paint */ }
    finally { busy = false; }
  }, 2500);
}

let jobFullLoaded = false;
const evidenceFilled = new Set();

async function ensureFullJob() {
  if (!currentJobId || jobFullLoaded || !lastJobData?.ui_slim) return lastJobData;
  const res = await fetch(`${API}/jobs/${currentJobId}?full=1`);
  if (!res.ok) return lastJobData;
  const job = await res.json();
  lastJobData = job;
  jobFullLoaded = true;
  evidenceFilled.clear();
  return job;
}

function fillEvidencePanel(name) {
  const job = lastJobData;
  if (!job) return;
  const key = `${job.id}:${name}`;
  if (evidenceFilled.has(key)) return;
  const art = job.result?.artifacts || {};
  const notes = art.agent_notes || {};
  const sym = art.symbol_diff || {};
  const jobId = job.id;
  if (name === "timeline") {
    const tl = art.size_timeline || {};
    const labels = tl.labels || [];
    const trows = (tl.rows || []).map(r => `<tr><td>${fnLink(r.name)}</td>${labels.map(l => `<td>${r[l] ?? "—"}</td>`).join("")}</tr>`).join("");
    $("#panel-timeline").innerHTML = labels.length
      ? table(["函数", ...labels.map(esc)], trows)
      : '<p class="empty">无时间线。上传第三份更早样本可对比三版本。</p>';
  } else if (name === "bytediff") {
    const bd = art.byte_diff || {};
    const brows = (bd.top || []).slice(0, 30).map(x => `<tr><td>${esc(x.label)}</td><td>${x.size_old ?? ""}</td><td>${x.size_new ?? ""}</td><td>${x.patch_bytes}</td></tr>`).join("");
    $("#panel-bytediff").innerHTML = `
      <div class="stats" style="grid-template-columns:1fr 1fr">
        <div class="stat"><span>代码节变化字节</span><strong>${bd.total_bytes ?? "—"}</strong></div>
        <div class="stat"><span>涉及函数</span><strong>${bd.functions_with_byte_changes ?? "—"}</strong></div>
      </div>
      <p class="hint">${esc(bd.note || "含 RIP 重定位噪声，归因以 .pdata 尺寸为准。")}</p>
      ${table(["函数","old size","new size","patch bytes"], brows || "<tr><td colspan=4>无</td></tr>")}
    `;
  } else if (name === "symbols") {
    const resized = [...(sym.functions_resized || [])].sort((a, b) => Math.abs(b.delta || 0) - Math.abs(a.delta || 0));
    const rows = resized.slice(0, 30).map(f => `
      <tr>
        <td>${fnLink(f.name)}</td>
        <td>${f.old}</td><td>${f.new}</td>
        <td class="${f.delta >= 0 ? "delta-pos" : "delta-neg"}">${f.delta >= 0 ? "+" : ""}${f.delta}</td>
      </tr>`).join("");
    const callRowsSym = (art.disassembly || []).map(b => {
      const d = (b.new?.size || 0) - (b.old?.size || 0);
      return `<tr>
        <td>${fnLink(b.name)}</td>
        <td class="${d >= 0 ? "delta-pos" : "delta-neg"}">${d >= 0 ? "+" : ""}${d}</td>
        <td><span class="chip-row">${chips(b.calls_added, "add") || "—"}</span></td>
        <td><span class="chip-row">${chips(b.calls_removed, "del") || "—"}</span></td>
      </tr>`;
    }).join("");
    $("#panel-symbols").innerHTML = `
      <p class="card-title">尺寸变化</p>
      ${table(["函数","Old","New","Δ"], rows || "<tr><td colspan=4>无</td></tr>")}
      ${callRowsSym ? `<p class="card-title" style="margin-top:1.2rem">调用差</p>${table(["函数","Δ","新增","删除"], callRowsSym)}` : ""}
      <p class="card-title" style="margin-top:1.2rem">新增符号</p>
      <pre class="asm">${esc((sym.symbols_added||[]).slice(0,40).join("\n") || "无")}</pre>
    `;
  } else if (name === "disasm") {
    const dis = (art.disassembly || []).map((block, i) => `
      <details class="block" data-fn="${esc(block.name)}" ${i === 0 ? "open" : ""}>
        <summary><code>${esc(block.name)}</code>
          ${(block.calls_added||[]).slice(0,4).map(c => `<span class="chip add">${esc(c)}</span>`).join("")}
          ${(block.calls_removed||[]).slice(0,3).map(c => `<span class="chip del">${esc(c)}</span>`).join("")}
        </summary>
        <div class="body asm-grid">
          <div class="asm-col"><h4>OLD · ${esc(block.old?.rva || "")} · ${block.old?.size ?? ""} B</h4><pre class="asm">${esc((block.old?.disasm||[]).join("\n"))}</pre></div>
          <div class="asm-col"><h4>NEW · ${esc(block.new?.rva || "")} · ${block.new?.size ?? ""} B</h4><pre class="asm">${esc((block.new?.disasm||[]).join("\n"))}</pre></div>
        </div>
      </details>
    `).join("");
    $("#panel-disasm").innerHTML = dis || '<p class="empty">无反汇编数据</p>';
  } else if (name === "cfg") {
    const cfg = art.cfg_diff || {};
    const cfgRows = (cfg.functions || []).map(f => `
      <tr>
        <td>${fnLink(f.name)}</td>
        <td>${esc(f.old?.rva)} · ${f.old?.size ?? "—"} B · ${f.old?.blocks ?? 0} 块</td>
        <td>${esc(f.new?.rva)} · ${f.new?.size ?? "—"} B · ${f.new?.blocks ?? 0} 块</td>
        <td class="${(f.delta_size||0) >= 0 ? "delta-pos" : "delta-neg"}">${(f.delta_size||0) >= 0 ? "+" : ""}${f.delta_size ?? ""}</td>
      </tr>`).join("");
    $("#panel-cfg").innerHTML = `
      <p class="hint">${esc(cfg.note || "Capstone 基本块并排对比。")}</p>
      <p style="margin:0.6rem 0 1rem">
        <a class="btn ghost" href="${API}/jobs/${jobId}/cfg_diff.html" target="_blank">打开完整 CFG</a>
      </p>
      ${table(["函数","Old","New","Δ"], cfgRows || "<tr><td colspan=4>无</td></tr>")}
      <div id="cfg-preview" class="hint" style="margin-top:1rem">加载基本块预览…</div>
    `;
    fetch(`${API}/jobs/${jobId}/cfg_diff.json`).then(r => r.ok ? r.json() : null).then(full => {
      const box = $("#cfg-preview");
      if (!box || !full) { if (box) box.textContent = "尚无基本块详情（请用新流水线重新分析）。"; return; }
      const first = (full.functions || []).find(f => (f.old_blocks||[]).length || (f.new_blocks||[]).length);
      if (!first) { box.textContent = "无基本块。"; return; }
      const nShow = Math.min(5, Math.max((first.old_blocks||[]).length, (first.new_blocks||[]).length));
      let html = `<p class="card-title">预览 ${esc(first.name)}</p>`;
      for (let i = 0; i < nShow; i++) {
        const L = (first.old_blocks||[])[i];
        const R = (first.new_blocks||[])[i];
        html += `<div class="cfg-row">
          <div class="cfg-block ${L?.hot ? "hot" : ""}"><div class="hdr">old ${esc(L?.start || "—")}</div><pre>${esc((L?.lines||[]).join("\n"))}</pre></div>
          <div class="cfg-block ${R?.hot ? "hot" : ""}"><div class="hdr">new ${esc(R?.start || "—")}</div><pre>${esc((R?.lines||[]).join("\n"))}</pre></div>
        </div>`;
      }
      box.innerHTML = html;
    }).catch(() => { const b = $("#cfg-preview"); if (b) b.textContent = "无法加载 cfg_diff.json"; });
  } else if (name === "feature") {
    const ft = art.feature_trace || {};
    const feats = (ft.features || []).map(f => `
      <details class="block" open>
        <summary>Feature <code>${esc(f.feature_id)}</code>
          <span class="chip">state ${esc(f.featureState_rva)}</span>
          <span class="chip">on-disk ${f.on_disk_dword ?? "—"}</span>
          <span class="chip add">cache ${esc(f.enable_semantics?.cached_valid_bit)}</span>
          <span class="chip add">enable ${esc(f.enable_semantics?.enabled_bit)}</span>
        </summary>
        <div class="body">
          <p class="hint">${esc(f.default_note)}</p>
          ${table(["RVA","target","函数"], (f.xrefs||[]).map(x => `<tr><td><code>${esc(x.rva)}</code></td><td>${esc(x.target)}</td><td>${fnLink(x.in_function)}</td></tr>`).join("") || "<tr><td colspan=3>无 xref</td></tr>")}
          <p class="card-title" style="margin-top:1rem">IsEnabled</p>
          <pre class="asm">${esc((f.isEnabled_disasm||[]).join("\n"))}</pre>
        </div>
      </details>`).join("");
    $("#panel-feature").innerHTML = (ft.count ? feats : '<p class="empty">无新增 Feature_* 符号</p>')
      + (notes.feature ? `<details class="block"><summary>FeatureAnalyst</summary><div class="body"><div class="report-md md-compact">${mdHtml(notes.feature)}</div></div></details>` : "");
  } else if (name === "verify") {
    $("#panel-verify").innerHTML = renderVerifyPanel(job);
  } else if (name === "huntlab") {
    $("#panel-huntlab").innerHTML = renderHuntLabPanel(job);
  } else if (name === "control") {
    $("#panel-control").innerHTML = renderControlPanel(job);
  } else {
    return;
  }
  evidenceFilled.add(key);
}

function shellVersionLine(j) {
  const a = j?.old_label || "";
  const b = j?.new_label || "";
  if (a && b) return `${a} → ${b}`;
  return a || b || "";
}

function paintJobShell(job) {
  if (!job) return;
  const title = $("#modal-title");
  if (title) title.textContent = job.title || "正在读取任务…";
  const idEl = $("#modal-job-id");
  if (idEl) idEl.textContent = job.id || "";
  const sub = $("#modal-sub");
  if (sub) {
    sub.textContent = shellVersionLine(job)
      || job.progress?.message
      || (job.status === "running" || job.status === "pending" ? "分析进行中…" : "正在读取详情…");
  }
  setRing(job);
  const st = job.status || "";
  const tags = [
    `<span class="tag-pill ${st === "completed" ? "ok" : st === "failed" || st === "cancelled" ? "err" : "warn"}">${statusLabel(st)}</span>`,
  ];
  if (job.in_kev === 1 || job.in_kev === true) tags.push(`<span class="tag-pill err">#KEV 在野</span>`);
  if (String(job.bypass_verdict || "") === "bypassable") tags.push(`<span class="tag-pill err">#有绕过面</span>`);
  const tagRow = $("#modal-tags");
  if (tagRow) tagRow.innerHTML = tags.join("");
  if (job.id) {
    const api = API;
    const ioc = $("#download-ioc");
    if (ioc) ioc.href = `${api}/jobs/${job.id}/ioc.json`;
    const threat = $("#download-threat");
    if (threat) threat.href = `${api}/jobs/${job.id}/threat.json`;
    const bypass = $("#download-bypass");
    if (bypass) bypass.href = `${api}/jobs/${job.id}/bypass.json`;
    const residual = $("#download-residual");
    if (residual) residual.href = `${api}/jobs/${job.id}/residual.json`;
    const cfg = $("#download-cfg");
    if (cfg) cfg.href = `${api}/jobs/${job.id}/cfg_diff.html`;
    const verify = $("#download-verify");
    if (verify) verify.href = `${api}/jobs/${job.id}/verify.zip`;
  }
  if (st === "running" || st === "pending" || st === "failed" || st === "cancelled") {
    paintCommunity(job);
    const sum = $("#panel-summary");
    if (sum && !sum.dataset.ready) {
      const action = caseAction(job, {});
      sum.innerHTML = `<section class="decision-page">
        <div class="decision-action ${action.tone}">
          <span>现在做什么</span>
          <strong>${esc(action.title)}</strong>
          <p>${esc(action.detail)}</p>
        </div>
        ${liveProgressBlock(job)}
      </section>`;
    }
  } else if (!lastJobData || lastJobData.id !== job.id) {
    const sum = $("#panel-summary");
    if (sum && !sum.dataset.ready) {
      sum.innerHTML = `<section class="decision-page"><p class="hint">正在读取任务详情…</p></section>`;
    }
  }
}

function applyLiveRow(jobId, row) {
  const pct = row.progress?.percent ?? (row.status === "pending" ? 0 : 10);
  const fill = $("#summary-progress-fill") || $("#progress-fill");
  if (fill) fill.style.width = pct + "%";
  const txt = $("#summary-progress-text") || $("#progress-text");
  if (txt) txt.textContent = row.progress?.message || row.status + (row.error ? ": " + row.error : "");
  $("#cancel-job")?.classList.toggle("hidden", !(row.status === "running" || row.status === "pending"));
  if (currentJobId !== jobId) return;
  lastJobData = { ...(lastJobData || {}), ...row, result: lastJobData?.result };
  paintCommunity(lastJobData);
  setRing(lastJobData);
  const sub = $("#modal-sub");
  if (sub && row.progress?.message) sub.textContent = row.progress.message;
}

function watchLiveJob(jobId, { switchToJobs = false, analyze = false } = {}) {
  unsubLive?.();
  const onLive = window.__paOnJobsLive;
  if (typeof onLive !== "function") return;
  unsubLive = onLive((live, finished) => {
    const row = (live || []).find(j => j.id === jobId);
    if (row) applyLiveRow(jobId, row);
    const done = (finished || []).find(j => j.id === jobId);
    if (!done) return;
    unsubLive?.();
    unsubLive = null;
    if (analyze && window.__paOpenJob) {
      window.__paOpenJob(jobId);
      return;
    }
    if (switchToJobs) window.__paGotoJobs?.();
    if (currentJobId === jobId) openJobModal(jobId);
  });
}

async function waitForCaseDom() {
  for (let i = 0; i < 24; i++) {
    if ($("#job-modal") && $("#panel-summary")) return true;
    await new Promise(r => requestAnimationFrame(r));
  }
  return !!$("#job-modal");
}

async function openJobModal(jobId, panelName) {
  if (panelName === "research") panelName = "huntlab";
  if (currentJobId !== jobId) graphSelectedId = null;
  currentJobId = jobId;
  jobFullLoaded = false;
  evidenceFilled.clear();
  ui.reportOpen = true;
  if (!(await waitForCaseDom())) return;
  $("#job-modal")?.classList.remove("hidden");
  document.body.classList.add("report-open");
  const seed = window.__paPeekJob?.(jobId) || (lastJobData?.id === jobId ? lastJobData : null);
  paintJobShell(seed || { id: jobId, title: "正在读取任务…", status: "pending" });
  const mdP = ensureMarkdownLibs().then(() => configureMarked());
  const jobP = fetch(`${API}/jobs/${jobId}`).then(r => r.json());
  const [, job] = await Promise.all([mdP, jobP]);
  if (currentJobId !== jobId) return;
  if (!$("#job-modal")) return;
  lastJobData = job;
  const sum = $("#panel-summary");
  if (sum) sum.dataset.ready = "1";
  const title = $("#modal-title");
  if (title) title.textContent = job.title;
  const jobIdEl = $("#modal-job-id");
  if (jobIdEl) jobIdEl.textContent = job.id;
  const iocTop = $("#download-ioc");
  if (iocTop) iocTop.href = `${API}/jobs/${jobId}/ioc.json`;
  const threatLinkTop = $("#download-threat");
  if (threatLinkTop) threatLinkTop.href = `${API}/jobs/${jobId}/threat.json`;
  const bypassTop = $("#download-bypass");
  if (bypassTop) bypassTop.href = `${API}/jobs/${jobId}/bypass.json`;
  const residualTop = $("#download-residual");
  if (residualTop) residualTop.href = `${API}/jobs/${jobId}/residual.json`;

  const art = job.result?.artifacts || {};
  const sym = art.symbol_diff || {};
  const notes = art.agent_notes || {};
  const features = (art.feature_trace || {}).features || [];
  const resized = sym.functions_resized || [];
  const pr = art.patch_resolve;
  const chain = extractChainClient(art);

  setRing(job);
  const peOld = art.old_pe || {};
  const peNew = art.new_pe || {};
  const component = pr?.old_file || peOld.original_filename || job.title || "驱动样本";
  const verOld = pr?.old_version || peOld.file_version || job.old_label || "漏洞版";
  const verNew = pr?.new_version || peNew.file_version || job.new_label || "修复版";
  const sub = $("#modal-sub");
  if (sub) sub.textContent = [component, `${verOld} → ${verNew}`].filter(Boolean).join(" · ");

  const tags = [
    `<span class="tag-pill ${job.status === "completed" ? "ok" : job.status === "failed" ? "err" : "warn"}">${statusLabel(job.status)}</span>`,
  ];
  if (pr?.old_file) tags.push(`<span class="tag-pill">#${esc(pr.old_file)}</span>`);
  (pr?.matched_kbs || []).forEach(k => tags.push(`<span class="tag-pill">#KB${esc(k)}</span>`));
  if (resized.length) tags.push(`<span class="tag-pill">#Δ${resized.length}</span>`);
  if (features.length) tags.push(`<span class="tag-pill">#Feature${features.length}</span>`);
  if (chain.present) tags.push(`<span class="tag-pill ok">#漏洞链</span>`);
  if (art.threat_intel?.in_kev) tags.push(`<span class="tag-pill err">#KEV 在野</span>`);
  else if (art.threat_intel?.status === "not_in_kev") tags.push(`<span class="tag-pill">#未列入 KEV</span>`);
  if (art.bypass_pack?.verdict === "bypassable") tags.push(`<span class="tag-pill err">#有绕过面</span>`);
  else if (art.bypass_pack?.verdict === "partial") tags.push(`<span class="tag-pill warn">#部分闭合</span>`);
  if (art.residual_pack?.verdict === "likely") tags.push(`<span class="tag-pill err">#残留漏洞</span>`);
  else if (art.residual_pack?.verdict === "suspects") tags.push(`<span class="tag-pill warn">#同类嫌疑</span>`);
  const tagRow = $("#modal-tags");
  if (tagRow) tagRow.innerHTML = tags.join("");
  await new Promise(r => requestAnimationFrame(r));

  paintCommunity(job);

  const action = caseAction(job, art);
  const verdict = caseVerdict(job);
  const vulnType = extractVulnType(art);
  if (sum) sum.innerHTML = `
    ${qualityBanner(art)}
    <section class="decision-page">
      <div class="decision-action ${action.tone}">
        <span>现在做什么</span>
        <strong>${esc(action.title)}</strong>
        <p>${esc(action.detail)}</p>
      </div>
      ${liveProgressBlock(job)}
      <div class="conclude-grid">
        <div class="conclude-card"><span>根因一句话</span><p>${esc(extractRootOneLiner(art) || "尚无根因总结")}</p></div>
        <div class="conclude-card"><span>补丁切断点</span><p>${esc(extractPatchCut(art) || "尚无切断点")}</p></div>
      </div>
      <div class="brief-facts">
        <div class="brief-fact"><span>结论</span><strong>${esc(verdict.sub || verdict.value)}</strong></div>
        <div class="brief-fact"><span>组件</span><strong>${esc(component)}</strong></div>
        <div class="brief-fact"><span>版本</span><strong>${esc(`${verOld} → ${verNew}`)}</strong></div>
        ${vulnType ? `<div class="brief-fact"><span>类型</span><strong>${esc(vulnType)}</strong></div>` : ""}
        <div class="brief-fact"><span>在野</span><strong>${art.threat_intel?.in_kev || job.in_kev ? "CISA KEV" : (art.threat_intel?.status === "not_in_kev" ? "未列入" : "待查")}</strong></div>
      </div>
      <div class="brief-actions" style="margin:1rem 0">
        <button type="button" class="btn ghost" data-goto-panel="ioc">去检测</button>
        <button type="button" class="btn ghost" data-goto-panel="chain">漏洞链</button>
        <button type="button" class="btn ghost" data-goto-panel="threat">在野利用</button>
        <button type="button" class="btn ghost" data-goto-panel="bypass">绕过面</button>
        <button type="button" class="btn ghost" data-goto-panel="fullreport">阅读全文</button>
        <button type="button" class="btn ghost" data-open-export="1">导出</button>
      </div>
      ${art.llm_error ? `<p class="err">${esc(art.llm_error)}</p>` : ""}
      ${job.error ? `<p class="err">${esc(job.error)}</p>` : ""}
      <p class="card-title">样本身份</p>
      <div class="ident-grid">
        ${[
          ["漏洞版", peOld, job.old_label],
          ["修复版", peNew, job.new_label],
          art.mid_pe ? ["更早版本", art.mid_pe, job.mid_label] : null,
        ].filter(Boolean).map(([role, pe, label]) => `
          <article class="ident-card">
            <p class="ident-role">${esc(role)}${label ? ` · ${esc(label)}` : ""}</p>
            <h4>${esc(pe.original_filename || "—")} <span>${esc(pe.file_version || "")}</span></h4>
            <p class="hint">${esc(pe.machine || "—")} · ${pe.size ? fmtBytes(pe.size) : "—"}</p>
            <div class="ident-dl">${hashLine("SHA256", pe.sha256)}</div>
          </article>`).join("")}
      </div>
      ${hotspotPickerHtml(art, job)}
    </section>
  `;

  const chainEl = $("#panel-chain");
  if (chainEl) {
    try {
      chainEl.innerHTML = renderChainPanel(art);
    } catch (err) {
      console.warn("chain panel failed", err);
      chainEl.innerHTML = `<section class="chain-page"><h3>函数逻辑漏洞链</h3><p class="err">绘制失败：${esc(err.message || String(err))}</p></section>`;
    }
  }
  fullReportJobId = null;
  const fullEl = $("#panel-fullreport");
  if (fullEl) fullEl.innerHTML = `<section class="ioc-page"><p class="hint">打开「全文」时加载 19 节正文。</p></section>`;

  const iocEl = $("#panel-ioc");
  if (iocEl) iocEl.innerHTML = renderIocPanel(job);
  const iocLink = $("#ioc-json-link");
  if (iocLink) iocLink.href = `${API}/jobs/${jobId}/ioc.json`;
  const threatEl = $("#panel-threat");
  if (threatEl) threatEl.innerHTML = renderThreatPanel(job);
  const threatLink = $("#threat-json-link");
  if (threatLink) threatLink.href = `${API}/jobs/${jobId}/threat.json`;
  const bypassEl = $("#panel-bypass");
  if (bypassEl) bypassEl.innerHTML = renderBypassPanel(job);
  const bypassLink = $("#bypass-json-link");
  if (bypassLink) bypassLink.href = `${API}/jobs/${jobId}/bypass.json`;
  const residualEl = $("#panel-residual");
  if (residualEl) residualEl.innerHTML = renderResidualPanel(job);
  const residualLink = $("#residual-json-link");
  if (residualLink) residualLink.href = `${API}/jobs/${jobId}/residual.json`;

  const report = art.llm_report || "";
  const exportBtn = $("#export-report");
  if (exportBtn) exportBtn.disabled = !String(report).trim();

  await activatePanel(panelName || "summary");
  $("#job-modal")?.classList.remove("hidden");
  document.body.classList.add("report-open");
  ui.reportOpen = true;

  if (job.status === "running" || job.status === "pending") {
    watchLiveJob(jobId);
  }
  ensureHuntLabPoll(jobId, job);
  ensureResearchPoll(jobId, job);
}

function closeJobModal() {
  graphSelectedId = null;
  $("#export-menu")?.classList.add("hidden");
  $("#job-modal")?.classList.add("hidden");
  document.body.classList.remove("report-open");
  ui.reportOpen = false;
  unsubLive?.();
  unsubLive = null;
  const sum = $("#panel-summary");
  if (sum) delete sum.dataset.ready;
  clearInterval(pollTimer);
  clearInterval(huntLabTimer);
  clearInterval(researchLabTimer);
}

document.addEventListener("keydown", e => {
  if (e.key !== "Escape") return;
  const settings = $("#settings-drawer");
  if (settings && !settings.classList.contains("hidden")) {
    closeSettings();
    return;
  }
  if (!$("#job-modal") || $("#job-modal").classList.contains("hidden")) return;
  if (graphSelectedId) {
    closeGraphPop();
    return;
  }
  leaveCase();
});
document.addEventListener("click", async e => {
  const modal = e.target.closest("#job-modal");
  if (!modal) return;
  if (e.target.closest("#modal-close")) {
    leaveCase();
    return;
  }
  if (e.target.closest("#copy-job-id")) {
    const id = $("#modal-job-id")?.textContent;
    if (!id) return;
    try {
      await navigator.clipboard.writeText(`${location.origin}/jobs/${id}`);
      const btn = $("#copy-job-id");
      if (btn) {
        btn.textContent = "已复制";
        setTimeout(() => { btn.textContent = "复制链接"; }, 1200);
      }
    } catch { /* ignore */ }
    return;
  }
  if (e.target.closest("#regen-report")) {
    if (!currentJobId) return;
    const regen = $("#regen-report");
    if (regen) regen.disabled = true;
    try {
      const res = await fetch(`${API}/jobs/${currentJobId}/report`, { method: "POST" });
      if (!res.ok) throw new Error(await res.text());
      await openJobModal(currentJobId);
    } catch (err) {
      alert(err.message);
    } finally {
      if (regen) regen.disabled = false;
    }
    return;
  }
  const exportBtn = e.target.closest("#export-report");
  if (exportBtn) {
    if (exportBtn.disabled) return;
    renderExportSectionPicker();
    $("#export-menu")?.classList.toggle("hidden");
    return;
  }
  const preset = e.target.closest("[data-export-preset]");
  if (preset) {
    e.preventDefault();
    setExportSectionChecks(EXPORT_SECTION_PRESETS[preset.dataset.exportPreset] || EXPORT_SECTION_PRESETS.all);
    return;
  }
  const exportFmt = e.target.closest("[data-export]");
  if (exportFmt) {
    e.preventDefault();
    let ok = false;
    if (exportFmt.dataset.export === "pdf") ok = await exportReportPdf();
    else if (exportFmt.dataset.export === "html") ok = await exportReportHtml();
    else if (exportFmt.dataset.export === "md") ok = await exportReportMarkdown();
    if (ok) $("#export-menu")?.classList.add("hidden");
    return;
  }
  const toc = e.target.closest("[data-report-sec]");
  if (toc) {
    e.preventDefault();
    const target = document.getElementById(`report-sec-${toc.dataset.reportSec}`);
    target?.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  const closePop = e.target.closest("[data-close-pop]");
  if (closePop) {
    closeGraphPop();
    return;
  }
  const node = e.target.closest(".gnode");
  if (node) {
    openGraphPop(node.dataset.node, { toggle: true });
    return;
  }
  const refresh = e.target.closest("#threat-refresh");
  if (refresh) {
    if (!currentJobId) return;
    refresh.disabled = true;
    refresh.textContent = "查询中…";
    try {
      const r = await fetch(`${API}/jobs/${currentJobId}/threat.json?refresh=1`);
      if (!r.ok) throw new Error(await r.text());
      const pack = await r.json();
      if (!lastJobData.result) lastJobData.result = {};
      if (!lastJobData.result.artifacts) lastJobData.result.artifacts = {};
      lastJobData.result.artifacts.threat_intel = pack;
      $("#panel-threat").innerHTML = renderThreatPanel(lastJobData);
      await hydrateMarkdown($("#panel-threat"));
      const threatLink = $("#threat-json-link");
      if (threatLink) threatLink.href = `${API}/jobs/${currentJobId}/threat.json`;
      paintCommunity(lastJobData);
    } catch (err) {
      refresh.disabled = false;
      refresh.textContent = "查询失败，重试";
      alert(err.message || "公开情报查询失败");
    }
    return;
  }
  const openExport = e.target.closest("[data-open-export]");
  if (openExport) {
    e.preventDefault();
    openExportMenu();
    return;
  }
  const jump = e.target.closest("[data-goto-panel]");
  if (jump) {
    e.preventDefault();
    activatePanel(jump.dataset.gotoPanel);
    return;
  }
  const hist = e.target.closest("[data-hunt-run]");
  if (hist) {
    e.preventDefault();
    if (!currentJobId || !lastJobData) return;
    const runId = hist.dataset.huntRun;
    const currentId = huntLabCurrent(lastJobData).run_id || "current";
    if (!runId || runId === "current" || runId === currentId) {
      delete lastJobData._huntView;
    } else {
      try {
        const r = await fetch(`${API}/jobs/${currentJobId}/hunt-lab.json?run_id=${encodeURIComponent(runId)}`);
        if (!r.ok) {
          alert("无法读取该轮记录");
          return;
        }
        lastJobData._huntView = await r.json();
      } catch (err) {
        alert(err.message || String(err));
        return;
      }
    }
    const panel = $("#panel-huntlab");
    if (panel) {
      panel.innerHTML = renderHuntLabPanel(lastJobData);
      hydrateMarkdown(panel);
    }
    return;
  }
  const startHunt = e.target.closest("[data-start-huntlab], [data-start-research]");
  if (startHunt) {
    e.preventDefault();
    if (startHunt.disabled || !currentJobId) return;
    startHunt.disabled = true;
    try {
      const r = await fetch(`${API}/jobs/${currentJobId}/hunt-lab`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tracks: ["bypass", "similar"] }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        alert(data.detail || "无法启动深度狩猎");
        startHunt.disabled = false;
        return;
      }
      const jr = await fetch(`${API}/jobs/${currentJobId}`);
      const j = await jr.json();
      lastJobData = j;
      delete lastJobData._huntView;
      const panel = $("#panel-huntlab");
      if (panel) {
        panel.innerHTML = renderHuntLabPanel(j);
        hydrateMarkdown(panel);
      }
      ensureHuntLabPoll(currentJobId, j);
    } catch (err) {
      alert(err.message || String(err));
      startHunt.disabled = false;
    }
    return;
  }
  const cancelHunt = e.target.closest("[data-cancel-huntlab], [data-cancel-research]");
  if (cancelHunt) {
    e.preventDefault();
    if (!currentJobId) return;
    cancelHunt.disabled = true;
    await fetch(`${API}/jobs/${currentJobId}/hunt-lab/cancel`, { method: "POST" });
    return;
  }
  const fn = e.target.closest("[data-goto-fn]");
  if (fn) {
    e.preventDefault();
    gotoFn(fn.dataset.gotoFn);
    return;
  }
  const jsonCopy = e.target.closest("[data-copy-json]");
  if (jsonCopy) {
    e.preventDefault();
    const text = JSON_COPY.get(jsonCopy.dataset.copyJson) || "";
    try {
      await navigator.clipboard.writeText(text);
      const old = jsonCopy.textContent;
      jsonCopy.textContent = "已复制";
      setTimeout(() => { jsonCopy.textContent = old; }, 1000);
    } catch { /* ignore */ }
    return;
  }
  const hunt = e.target.closest("[data-copy-hunt]");
  if (hunt) {
    const text = huntClipboard(iocFromJob(lastJobData));
    try {
      await navigator.clipboard.writeText(text);
      const old = hunt.textContent;
      hunt.textContent = "已复制";
      setTimeout(() => { hunt.textContent = old; }, 1000);
    } catch { /* ignore */ }
    return;
  }
  const btn = e.target.closest("[data-copy]");
  if (!btn || !btn.dataset.copy) return;
  try {
    await navigator.clipboard.writeText(btn.dataset.copy);
    const old = btn.textContent;
    btn.textContent = "已复制";
    setTimeout(() => { btn.textContent = old; }, 1000);
  } catch { /* ignore */ }
});
document.addEventListener("change", e => {
  if (e.target.closest("#export-sections")) persistExportSections(selectedExportSections());
});
document.addEventListener("click", e => {
  if (!e.target.closest(".export-wrap")) $("#export-menu")?.classList.add("hidden");
});

function statusLabel(s) {
  return ({ completed: "完成", failed: "失败", running: "运行中", pending: "排队", cancelled: "已取消" })[s] || s;
}
function esc(s) {
  return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function fmtDate(iso) {
  try { return new Date(iso).toLocaleString("zh-CN"); } catch { return iso; }
}
function fmtRel(iso) {
  if (!iso) return "";
  try {
    const t = new Date(iso).getTime();
    const d = Date.now() - t;
    if (d < 60_000) return "刚刚";
    if (d < 3600_000) return `${Math.floor(d / 60_000)} 分钟前`;
    if (d < 86400_000) return `${Math.floor(d / 3600_000)} 小时前`;
    if (d < 30 * 86400_000) return `${Math.floor(d / 86400_000)} 天前`;
    return fmtDate(iso);
  } catch { return iso; }
}

export { openJobModal, closeJobModal, activatePanel, pollJob, startCveJob, loadSettings };
