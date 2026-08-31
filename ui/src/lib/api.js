export function apiError(data, fallback) {
  const d = data && data.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map(x => x.msg || JSON.stringify(x)).join("; ");
  if (d && typeof d === "object") return d.msg || JSON.stringify(d);
  if (data && data.message) return data.message;
  return fallback || "请求失败";
}

const nativeFetch = window.fetch.bind(window);
let onUnauthorized = () => {};

export function setUnauthorizedHandler(fn) {
  onUnauthorized = typeof fn === "function" ? fn : () => {};
}

function apiUrl(input) {
  if (typeof input === "string") return input;
  return input?.url || "";
}

function isApiPath(url) {
  return typeof url === "string" && (url.startsWith("/api") || url.includes("/api/"));
}

export function apiFetch(input, init = {}) {
  const url = apiUrl(input);
  const opts = { ...init, credentials: "include" };
  return nativeFetch(input, opts).then(res => {
    if (
      res.status === 401 &&
      isApiPath(url) &&
      !/\/api\/auth\/(login|me|logout)(?:\?|$)/.test(url)
    ) {
      onUnauthorized();
    }
    return res;
  });
}

window.fetch = function(input, init) {
  if (isApiPath(apiUrl(input))) return apiFetch(input, init);
  return nativeFetch(input, init);
};

export async function readJson(res) {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(text.replace(/<[^>]+>/g, " ").trim().slice(0, 300) || `HTTP ${res.status}`);
  }
}

export async function apiGet(path, { timeout = 12000 } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await apiFetch(`/api${path}`, { signal: ctrl.signal });
    const data = await readJson(res);
    if (!res.ok) throw new Error(apiError(data, `HTTP ${res.status}`));
    return data;
  } catch (e) {
    if (e?.name === "AbortError") throw new Error("请求超时，请稍后重试");
    throw e;
  } finally {
    clearTimeout(t);
  }
}

export async function apiSend(path, { method = "POST", json, form } = {}) {
  const opts = { method, credentials: "include" };
  if (json) {
    opts.headers = { "Content-Type": "application/json" };
    opts.body = JSON.stringify(json);
  } else if (form) {
    opts.body = form;
  }
  const res = await apiFetch(`/api${path}`, opts);
  const data = await readJson(res);
  if (!res.ok) throw new Error(apiError(data, `HTTP ${res.status}`));
  return data;
}

export function statusLabel(s) {
  return ({ completed: "已完成", failed: "失败", running: "分析中", pending: "排队中", cancelled: "已取消" })[s] || s;
}

export function fmtDate(iso) {
  try { return new Date(iso).toLocaleString("zh-CN"); } catch { return iso; }
}

export function isLiveJob(j) {
  return !!j && (j.status === "running" || j.status === "pending");
}

export function isFailJob(j) {
  return !!j && (j.status === "failed" || j.status === "cancelled");
}

/** Latest-run outcome for a CVE's jobs. Live wins; a newer fail after an older success is still fail. */
export function cveJobOutcome(jobs) {
  const list = jobs || [];
  if (!list.length) return "none";
  if (list.some(isLiveJob)) return "live";
  const latest = [...list].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))[0];
  if (isFailJob(latest)) return "fail";
  if (list.some(j => j.status === "completed")) return "done";
  return "fail";
}

export function jobCve(j) {
  const fromField = String(j?.cve || "").toUpperCase();
  if (/^CVE-\d{4}-\d+$/.test(fromField)) return fromField;
  const m = String(j?.title || "").match(/CVE-\d{4}-\d+/i);
  return m ? m[0].toUpperCase() : "";
}

const JOB_RANK = { running: 0, pending: 1, completed: 2, failed: 3, cancelled: 4 };

export function groupJobsByCve(jobs) {
  const map = Object.create(null);
  for (const j of jobs || []) {
    const cve = jobCve(j);
    if (!cve) continue;
    (map[cve] ||= []).push(j);
  }
  for (const list of Object.values(map)) {
    list.sort((a, b) => {
      const ra = JOB_RANK[a.status] ?? 9;
      const rb = JOB_RANK[b.status] ?? 9;
      if (ra !== rb) return ra - rb;
      return String(b.created_at || "").localeCompare(String(a.created_at || ""));
    });
  }
  return map;
}

export function primaryJob(jobs) {
  return (jobs && jobs[0]) || null;
}

export function isAuditJob(j) {
  if (!j) return false;
  const kind = String(j.kind || "");
  if (kind === "kernel_audit" || kind === "audit") return true;
  return String(j.new_label || "") === "单文件审计";
}

export function jobVersionLine(j) {
  if (isAuditJob(j)) return j.old_label || "单文件审计";
  const bits = [j?.old_label, j?.mid_label, j?.new_label].filter(Boolean);
  if (!bits.length) return "";
  if (bits.length === 1) return bits[0];
  return `${bits[0]}${j.mid_label ? " / " + j.mid_label : ""} → ${bits[bits.length - 1]}`;
}

export function relativeTime(iso) {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return iso || "";
  const s = (Date.now() - t) / 1000;
  if (s < 45) return "刚刚";
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  if (s < 86400 * 7) return `${Math.floor(s / 86400)} 天前`;
  return fmtDate(iso);
}

export function initials(title) {
  return (title || "P").replace(/^CVE-/i, "").slice(0, 2).toUpperCase() || "PA";
}

export function jobRiskRank(j) {
  if (!j) return 99;
  if (j.in_kev === 1 || j.in_kev === true) return 0;
  const bv = String(j.bypass_verdict || "");
  if (bv === "bypassable") return 1;
  const rv = String(j.residual_verdict || "");
  if (rv === "likely") return 2;
  if (bv === "partial") return 3;
  if (rv === "suspects") return 4;
  if (j.status === "failed" || j.status === "cancelled") return 5;
  if (j.status === "completed") return 7;
  return 6;
}

export function jobPills(j) {
  const pills = [];
  if (isAuditJob(j)) {
    pills.push({ t: "内核审计", k: "accent" });
    const av = String(j.audit_verdict || "");
    if (av === "likely") pills.push({ t: "高优先级嫌疑", k: "err" });
    else if (av === "suspects") pills.push({ t: "有嫌疑", k: "warn" });
    return pills;
  }
  if (j.in_kev === 1 || j.in_kev === true) pills.push({ t: "KEV", k: "err" });
  const bv = String(j.bypass_verdict || "");
  if (bv === "bypassable") pills.push({ t: "有绕过面", k: "err" });
  else if (bv === "partial") pills.push({ t: "部分闭合", k: "warn" });
  else if (bv === "closed") pills.push({ t: "已闭合", k: "ok" });
  const rv = String(j.residual_verdict || "");
  if (rv === "likely") pills.push({ t: "残留", k: "err" });
  else if (rv === "suspects") pills.push({ t: "同类嫌疑", k: "warn" });
  return pills;
}

export const AGENTS = [
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

export const AGENT_PRESETS = {
  all: AGENTS.map(a => a.id),
  core: ["PEAnalyst", "SymbolAnalyst", "DisasmAnalyst", "FeatureAnalyst", "ControlPathAnalyst", "RootCauseAnalyst"],
  soc: ["DetectionAnalyst", "ThreatIntelAnalyst", "BypassAnalyst", "FeatureOffAnalyst", "ResidualVulnAnalyst", "AliasSiteAnalyst", "ReportWriter"],
  report: ["ReportWriter"],
  none: [],
};

export const LIKELY = {
  more: "较可能被利用",
  less: "较不可能",
  unlikely: "不太可能",
  detected: "已发现在野利用",
};
