<template>
  <div class="pa-page jobs">
    <PageHeader title="任务" :sub="headSub">
      <button class="pa-btn" type="button" @click="goBack">返回</button>
      <router-link class="pa-btn primary" to="/analyze">新建分析</router-link>
      <router-link class="pa-btn" to="/audit">内核审计</router-link>
      <button class="pa-btn" type="button" :disabled="loading || refreshing" @click="load(true)">{{ loading || refreshing ? "读取中…" : "刷新" }}</button>
    </PageHeader>
    <div class="pa-stack">
      <p v-if="notice" class="pa-banner" :class="{ bad: noticeBad }">{{ notice }}</p>
      <div class="pa-card flush">
        <div class="pa-stats">
          <button type="button" class="pa-stat run" :class="{ on: filter === 'live' }" @click="setFilter('live')">
            <span>进行中</span><b>{{ liveN }}</b>
          </button>
          <button type="button" class="pa-stat ok" :class="{ on: filter === 'done' }" @click="setFilter('done')">
            <span>已完成</span><b>{{ doneN }}</b>
          </button>
          <button type="button" class="pa-stat" :class="{ err: failN, on: filter === 'fail' }" @click="setFilter('fail')">
            <span>需要处理</span><b>{{ failN }}</b>
          </button>
          <button type="button" class="pa-stat" :class="{ on: filter === 'all' }" @click="setFilter('all')">
            <span>全部</span><b>{{ pool.length }}</b>
          </button>
        </div>
      </div>
      <div class="pa-card flush">
        <div class="jobs-toolbar">
          <input
            ref="searchEl"
            v-model="query"
            class="jobs-search-inline"
            type="search"
            placeholder="搜索 CVE、文件名或任务  ·  /"
            autocomplete="off"
          />
          <button type="button" class="pa-chip" :class="{ on: kindAudit }" @click="toggleKind">内核审计</button>
          <span class="pa-more">{{ pageLabel }}</span>
        </div>
        <div v-if="loading && !jobs.length" class="empty">正在读取任务…</div>
        <div v-else-if="error && !jobs.length" class="empty empty-hero">
          <strong>任务列表暂时读不到</strong>
          <p>{{ error }}</p>
          <div class="pa-links" style="justify-content:center;margin-top:0.85rem">
            <button class="pa-btn primary" type="button" @click="load(true)">重试</button>
          </div>
        </div>
        <div v-else-if="!shown.length" class="empty empty-hero">
          <strong>{{ emptyTitle }}</strong>
          <p>{{ emptyHint }}</p>
          <div v-if="!jobs.length || (kindAudit && !pool.length)" class="pa-links" style="justify-content:center;margin-top:0.85rem">
            <router-link v-if="kindAudit" class="pa-btn primary" to="/audit">去内核审计</router-link>
            <template v-else>
              <router-link class="pa-btn primary" to="/patch">从本月补丁开始</router-link>
              <router-link class="pa-btn" to="/analyze">上传样本</router-link>
              <router-link class="pa-btn" to="/audit">内核审计</router-link>
            </template>
          </div>
          <div v-else class="pa-links" style="justify-content:center;margin-top:0.85rem">
            <button v-if="query" class="pa-btn" type="button" @click="query = ''">清除搜索</button>
            <button v-if="filter === 'done' && failN" class="pa-btn" type="button" @click="setFilter('fail')">查看失败任务</button>
            <button v-else-if="filter !== 'all'" class="pa-btn" type="button" @click="setFilter('all')">查看全部任务</button>
          </div>
        </div>
        <div v-else class="jobs-board">
          <div class="jobs-cols">
            <span>任务</span>
            <span>版本</span>
            <span>状态</span>
            <span>时间</span>
            <span></span>
          </div>
          <template v-for="g in groups" :key="g.key">
            <h3 class="jobs-group">{{ g.title }}</h3>
            <article
              v-for="j in g.items"
              :key="j.id"
              class="jobs-item"
              :class="{ on: selected?.id === j.id }"
              @click="open(j.id)"
            >
              <div class="job-main">
                <strong class="job-title">{{ j.title || "未命名分析" }}</strong>
                <div class="job-flags">
                  <span class="job-flag" v-for="p in jobPills(j)" :key="p.t" :class="p.k">{{ p.t }}</span>
                </div>
                <div v-if="isLiveJob(j) && (j.progress?.percent != null || j.progress?.message)" class="pa-progress">
                  <i :style="{ width: (j.progress?.percent ?? 8) + '%' }"></i>
                </div>
                <p v-if="isLiveJob(j) && j.progress?.message" class="job-msg">{{ j.progress.message }}</p>
              </div>
              <div class="job-ver" :title="jobVersionLine(j)">{{ jobVersionLine(j) || "—" }}</div>
              <span class="job-st" :class="j.status">{{ statusLabel(j.status) }}</span>
              <span class="job-time">{{ relativeTime(j.created_at) }}</span>
              <div class="job-act">
                <button v-if="canResume(j)" class="text-link" type="button" :disabled="busy(j.id)" @click.stop="resumeJob(j)">继续</button>
                <button v-else-if="isLiveJob(j)" class="text-link" type="button" :disabled="busy(j.id)" @click.stop="cancelJob(j)">取消</button>
                <button v-else class="text-link" type="button" @click.stop="open(j.id)">打开</button>
              </div>
            </article>
          </template>
          <Pager
            :total="shown.length"
            :page="safePage"
            :count="pageCount"
            :label="pageLabel"
            :buttons="pageButtons"
            @go="goPage"
          />
        </div>
      </div>
    </div>
  </div>
</template>
<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import PageHeader from "../components/PageHeader.vue";
import Pager from "../components/Pager.vue";
import {
  apiSend, isAuditJob, isLiveJob, jobPills, jobRiskRank, jobVersionLine, relativeTime, statusLabel,
} from "../lib/api.js";
import { jobsStore, loadJobs } from "../lib/jobs.js";
import { parsePage, usePager } from "../lib/pager.js";
import { ui } from "../lib/store.js";
import { openReport } from "../lib/engine.js";

const FILTERS = new Set(["all", "live", "done", "fail"]);
const route = useRoute();
const router = useRouter();
const jobs = computed(() => jobsStore.items);
const loading = computed(() => jobsStore.loading);
const refreshing = computed(() => jobsStore.refreshing);
const error = computed(() => jobsStore.error);
const selected = ref(null);
const query = ref("");
const kindAudit = computed(() => String(route.query.kind || "") === "audit");
function defaultFilter() {
  if (FILTERS.has(String(route.query.f || ""))) return String(route.query.f);
  return kindAudit.value ? "all" : "done";
}
const filter = ref(defaultFilter());
const actingIds = ref(new Set());
const notice = ref("");
const noticeBad = ref(false);
const searchEl = ref(null);

function goBack() {
  if (window.history.state && window.history.state.back != null) {
    router.back();
    return;
  }
  router.push("/app");
}
function canResume(j) {
  return j && (j.status === "failed" || j.status === "cancelled");
}
function busy(id) {
  return actingIds.value.has(id);
}
function setBusy(id, on) {
  const next = new Set(actingIds.value);
  if (on) next.add(id);
  else next.delete(id);
  actingIds.value = next;
}
function dayLabel(iso) {
  const t = new Date(iso);
  if (!Number.isFinite(t.getTime())) return "更早";
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const that = new Date(t);
  that.setHours(0, 0, 0, 0);
  const diff = Math.round((today - that) / 86400000);
  if (diff <= 0) return "今天";
  if (diff === 1) return "昨天";
  if (diff < 7) return "本周";
  return "更早";
}
function flash(msg, bad = false) {
  notice.value = msg;
  noticeBad.value = bad;
}

const pool = computed(() => kindAudit.value ? jobs.value.filter(isAuditJob) : jobs.value);
const liveN = computed(() => pool.value.filter(isLiveJob).length);
const doneN = computed(() => pool.value.filter(j => j.status === "completed").length);
const failN = computed(() => pool.value.filter(j => j.status === "failed" || j.status === "cancelled").length);
const shown = computed(() => {
  const q = query.value.trim().toLowerCase();
  return pool.value.filter(j => {
    if (filter.value === "live" && !isLiveJob(j)) return false;
    if (filter.value === "done" && j.status !== "completed") return false;
    if (filter.value === "fail" && j.status !== "failed" && j.status !== "cancelled") return false;
    if (!q) return true;
    const blob = `${j.title || ""} ${j.id} ${j.kind || ""} ${j.old_label || ""} ${j.new_label || ""} ${j.mid_label || ""}`.toLowerCase();
    return blob.includes(q);
  });
});
const ordered = computed(() => {
  const rows = shown.value;
  const live = rows.filter(isLiveJob);
  const rest = filter.value === "all" || filter.value === "live" ? rows.filter(j => !isLiveJob(j)) : rows;
  const out = [];
  if (live.length && filter.value !== "done" && filter.value !== "fail") out.push(...live);
  const buckets = { 今天: [], 昨天: [], 本周: [], 更早: [] };
  for (const j of rest) buckets[dayLabel(j.created_at)].push(j);
  for (const title of ["今天", "昨天", "本周", "更早"]) {
    buckets[title].sort((a, b) => {
      const d = jobRiskRank(a) - jobRiskRank(b);
      if (d) return d;
      return String(b.created_at || "").localeCompare(String(a.created_at || ""));
    });
    out.push(...buckets[title]);
  }
  return out;
});
const page = computed(() => parsePage(route.query.p));
const { pageCount, safePage, paged, pageLabel, pageButtons } = usePager(ordered, page);
const groups = computed(() => {
  const rows = paged.value;
  const live = rows.filter(isLiveJob);
  const rest = filter.value === "all" || filter.value === "live" ? rows.filter(j => !isLiveJob(j)) : rows;
  const out = [];
  if (live.length && filter.value !== "done" && filter.value !== "fail") {
    out.push({ key: "live", title: "进行中", items: live });
  }
  const order = ["今天", "昨天", "本周", "更早"];
  const buckets = { 今天: [], 昨天: [], 本周: [], 更早: [] };
  for (const j of rest) buckets[dayLabel(j.created_at)].push(j);
  for (const title of order) {
    buckets[title].sort((a, b) => {
      const d = jobRiskRank(a) - jobRiskRank(b);
      if (d) return d;
      return String(b.created_at || "").localeCompare(String(a.created_at || ""));
    });
    if (buckets[title].length) out.push({ key: title, title, items: buckets[title] });
  }
  return out;
});
const emptyTitle = computed(() => {
  if (!pool.value.length) return kindAudit.value ? "还没有内核审计任务" : "还没有分析任务";
  if (query.value.trim()) return "没有匹配的任务";
  if (filter.value === "live") return kindAudit.value ? "当前没有进行中的审计" : "当前没有进行中的分析";
  if (filter.value === "fail") return "没有需要处理的任务";
  if (filter.value === "done") return kindAudit.value ? "还没有完成的审计" : "还没有完成的报告";
  return "没有符合筛选的任务";
});
const emptyHint = computed(() => {
  if (!pool.value.length) {
    return kindAudit.value
      ? "到内核审计页上传一份驱动，任务会保存在这里。"
      : "从本月补丁里选一条 CVE，或上传样本开始对照分析。";
  }
  if (query.value.trim()) return `没有找到「${query.value.trim()}」。`;
  return kindAudit.value ? "换一个筛选，或再审计一份样本。" : "换一个筛选，或新建一次分析。";
});
const headSub = computed(() => {
  const noun = kindAudit.value ? "内核审计" : "任务";
  if (filter.value === "fail") {
    if (failN.value) return `${failN.value} 个${noun}失败或已取消，可从断点继续。`;
    return "当前没有失败任务。";
  }
  if (filter.value === "live") {
    if (liveN.value) return `${liveN.value} 个${noun}正在进行。`;
    return kindAudit.value ? "当前没有进行中的审计。" : "当前没有进行中的分析。";
  }
  if (filter.value === "all") {
    if (pool.value.length) return kindAudit.value ? `共 ${pool.value.length} 个内核审计任务。` : `共 ${pool.value.length} 个任务。`;
    return kindAudit.value ? "上传驱动开始一次内核审计。" : "从补丁日选 CVE，或上传样本开始一次对照分析。";
  }
  if (doneN.value) {
    return failN.value
      ? `${doneN.value} 个已完成。失败的请点「需要处理」。`
      : `${doneN.value} 个已完成${noun}。点一条打开。`;
  }
  if (failN.value) return `还没有成功任务。${failN.value} 个失败，点「需要处理」查看。`;
  if (liveN.value) return `${liveN.value} 个${noun}正在进行。`;
  return kindAudit.value ? "上传驱动开始一次内核审计。" : "从补丁日选 CVE，或上传样本开始一次对照分析。";
});

function setFilter(f) {
  const fallback = kindAudit.value ? "all" : "done";
  filter.value = filter.value === f && f !== fallback ? fallback : f;
}

function syncQuery() {
  const q = { ...route.query };
  const fallback = kindAudit.value ? "all" : "done";
  if (filter.value !== fallback) q.f = filter.value;
  else delete q.f;
  if (kindAudit.value) q.kind = "audit";
  else delete q.kind;
  if (selected.value?.id) q.id = selected.value.id;
  else delete q.id;
  const p = parsePage(q.p);
  if (p <= 1) delete q.p;
  else q.p = String(p);
  const cur = `${route.query.f || ""}|${route.query.kind || ""}|${route.query.id || ""}|${route.query.p || ""}`;
  const next = `${q.f || ""}|${q.kind || ""}|${q.id || ""}|${q.p || ""}`;
  if (cur === next) return;
  router.replace({ path: "/jobs", query: q });
}

function toggleKind() {
  const q = { ...route.query };
  if (kindAudit.value) delete q.kind;
  else {
    q.kind = "audit";
    q.f = filter.value === "done" ? "all" : filter.value;
  }
  delete q.p;
  router.replace({ path: "/jobs", query: q });
}

function goPage(n) {
  const next = Math.min(pageCount.value, Math.max(1, n));
  if (next === page.value) return;
  const q = { ...route.query };
  const fallback = kindAudit.value ? "all" : "done";
  if (filter.value !== fallback) q.f = filter.value;
  else delete q.f;
  if (kindAudit.value) q.kind = "audit";
  else delete q.kind;
  if (next > 1) q.p = String(next);
  else delete q.p;
  router.replace({ path: "/jobs", query: q });
  document.querySelector(".pa-body")?.scrollTo({ top: 0 });
}

function pick(j) {
  selected.value = j;
  syncQuery();
}
function primary(j) {
  pick(j);
  if (canResume(j)) resumeJob(j);
  else open(j.id);
}

watch(() => `${route.query.f || ""}|${route.query.kind || ""}`, () => {
  const next = defaultFilter();
  if (next !== filter.value) filter.value = next;
});
watch(filter, () => {
  if (parsePage(route.query.p) > 1) goPage(1);
  else syncQuery();
});
watch(query, () => {
  if (parsePage(route.query.p) > 1) goPage(1);
});
watch(shown, rows => {
  if (selected.value && rows.some(j => j.id === selected.value.id)) {
    selected.value = rows.find(j => j.id === selected.value.id) || selected.value;
    return;
  }
  const want = route.query.id;
  selected.value = (want && rows.find(j => j.id === want)) || null;
});
watch(pageCount, n => {
  if (!ordered.value.length) return;
  if (page.value > n) goPage(n);
});

async function load(force = false) {
  if (force) flash("");
  await loadJobs({ force, silent: !force && !!jobs.value.length });
}

function open(id) { openReport(id); }

async function cancelJob(j) {
  if (!j || busy(j.id)) return;
  setBusy(j.id, true);
  try {
    await apiSend(`/jobs/${j.id}/cancel`);
    flash("已取消，可稍后从断点继续");
    await load(false);
  } catch (e) { flash(e.message, true); }
  finally { setBusy(j.id, false); }
}
async function resumeJob(j) {
  if (!j || busy(j.id)) return;
  setBusy(j.id, true);
  try {
    await apiSend(`/jobs/${j.id}/resume`);
    flash("已继续分析");
    filter.value = "live";
    load(false);
  } catch (e) { flash(e.message, true); }
  finally { setBusy(j.id, false); }
}

function onKey(e) {
  if (ui.reportOpen || ui.settingsOpen) return;
  const tag = (e.target && e.target.tagName) || "";
  const typing = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || e.target?.isContentEditable;
  if (e.key === "/" && !typing) {
    e.preventDefault();
    searchEl.value?.focus();
    searchEl.value?.select();
    return;
  }
  if (e.key === "Escape" && typing) {
    if (query.value) query.value = "";
    e.target.blur?.();
    return;
  }
  if (typing) return;
  const rows = paged.value;
  const i = rows.findIndex(j => j.id === selected.value?.id);
  if (e.key === "ArrowDown" || e.key === "j") {
    e.preventDefault();
    if (i < 0) { if (rows[0]) pick(rows[0]); }
    else if (rows[i + 1]) pick(rows[i + 1]);
    else if (safePage.value < pageCount.value) goPage(safePage.value + 1);
  } else if (e.key === "ArrowUp" || e.key === "k") {
    e.preventDefault();
    if (i < 0) { if (rows[0]) pick(rows[0]); }
    else if (rows[i - 1]) pick(rows[i - 1]);
    else if (safePage.value > 1) goPage(safePage.value - 1);
  } else if (e.key === "Enter" && selected.value) {
    e.preventDefault();
    primary(selected.value);
  } else if (e.key === "Escape" && query.value) {
    query.value = "";
  }
}

onMounted(() => {
  filter.value = defaultFilter();
  load(false);
  window.addEventListener("keydown", onKey);
});
onUnmounted(() => {
  window.removeEventListener("keydown", onKey);
});
</script>
<style scoped>
.pa-stat {
  cursor: pointer;
  font: inherit;
  text-align: left;
  width: 100%;
}
.pa-stat.on { background: #f8fbff; }
.jobs-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.35rem 1rem;
  padding: 0.55rem 1.1rem;
  min-height: 2.7rem;
  border-bottom: 1px solid var(--line);
  font-size: var(--text-md);
  color: var(--muted);
}
.jobs-toolbar .pa-more { margin-left: auto; }
.jobs-search-inline {
  flex: 1;
  min-width: 12rem;
  border: 1px solid var(--line-strong);
  border-radius: 8px;
  padding: 0.4rem 0.7rem;
  font-size: var(--text-md);
  background: #fff;
  outline: none;
}
.jobs-search-inline:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(26, 115, 232, 0.12);
}
.jobs-board { min-width: 0; }
.jobs-cols,
.jobs-item {
  display: grid;
  grid-template-columns: minmax(11rem, 16rem) minmax(0, 1fr) 5.5rem 7.5rem 3.2rem;
  column-gap: 1rem;
  align-items: center;
  padding: 0.75rem 1.1rem;
}
.jobs-cols {
  font-size: var(--text-sm);
  font-weight: 600;
  color: var(--muted);
  background: #fafbfc;
  border-bottom: 1px solid var(--line);
  padding-top: 0.7rem;
  padding-bottom: 0.7rem;
}
.jobs-group {
  margin: 0;
  padding: 0.7rem 1.1rem 0.35rem;
  background: #fafbfc;
  font-size: var(--text-sm);
  font-weight: 600;
  letter-spacing: 0;
  text-transform: none;
  color: var(--muted);
  border-top: 1px solid var(--line);
}
.jobs-item {
  border-bottom: 1px solid var(--line);
  cursor: pointer;
  font-size: var(--text-lg);
}
.jobs-item:hover { background: #f8fbff; }
.jobs-item.on { background: #f4f8ff; }
.job-main { min-width: 0; }
.job-ver {
  min-width: 0;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: var(--text-md);
}
.job-time {
  color: var(--muted);
  white-space: nowrap;
  font-size: var(--text-md);
}
.job-act { text-align: right; }
.empty-hero { padding: 2.4rem 1.4rem; }
.empty-hero strong {
  display: block;
  color: var(--ink);
  font-size: var(--text-lg);
  font-weight: 500;
}
.empty-hero p {
  margin: 0.35rem 0 0;
  color: var(--muted);
}
.job-title { color: var(--ink); font-weight: 500; }
.job-flags { display: flex; flex-wrap: wrap; gap: 0.28rem; margin-top: 0.28rem; }
.job-flag {
  font-size: var(--text-xs);
  font-weight: 500;
  color: var(--muted);
}
.job-flag.err { color: var(--err); }
.job-flag.warn { color: var(--warn); }
.job-flag.ok { color: var(--ok); }
.job-flag.accent { color: var(--accent); }
.job-msg {
  margin: 0.3rem 0 0;
  font-size: var(--text-sm);
  color: var(--muted);
}
.job-st {
  font-size: var(--text-sm);
  font-weight: 500;
  color: var(--muted);
  white-space: nowrap;
}
.job-st.running, .job-st.pending { color: var(--accent); }
.job-st.completed { color: var(--ok); }
.job-st.failed { color: var(--err); }
</style>
