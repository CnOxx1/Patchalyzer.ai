<template>
  <div class="pa-page patch">
    <template v-if="reading">
      <PageHeader :title="selected.cve" :sub="selected.title || ''">
        <button class="pa-btn" type="button" @click="backToList">返回列表</button>
        <button
          v-if="primaryFor(selected)"
          class="pa-btn"
          type="button"
          @click="openJob(primaryFor(selected))"
        >{{ isLiveJob(primaryFor(selected)) ? "查看进度" : "打开任务" }}</button>
        <button class="pa-btn primary" type="button" :disabled="isBusy(selected.cve)" @click="run(selected)">
          {{ enqueueLabel(selected) }}
        </button>
        <button class="pa-btn" type="button" @click="copyCve">{{ copied ? "已复制" : "复制编号" }}</button>
        <a class="pa-btn" :href="'https://msrc.microsoft.com/update-guide/vulnerability/' + selected.cve" target="_blank" rel="noopener">MSRC</a>
      </PageHeader>
      <div class="pa-stack">
        <p v-if="notice" class="pa-banner" :class="{ bad: noticeBad }">
          {{ notice }}
          <button v-if="noticeJobId" class="text-link" type="button" @click="openReport(noticeJobId)">打开任务</button>
        </p>
        <div class="pa-card">
          <div class="pa-meta">
            <div>
              <span>状态</span>
              <b><span class="pa-badge" :class="impactClass(selected) || 'muted'">{{ selected.impact_label }}</span></b>
            </div>
            <div>
              <span>利用可能</span>
              <b :class="likelyClass(selected)">{{ LIKELY[selected.exploit_likely] || "未标注" }}</b>
            </div>
            <div>
              <span>组件</span>
              <b>{{ selected.filename_guess || "未知" }}</b>
            </div>
            <div>
              <span>对照适配</span>
              <b>{{ analysisLabel(selected) }}</b>
            </div>
            <div>
              <span>补丁日</span>
              <b>{{ fmtPatchDate(bulletin?.release_date) || activeMonth }}</b>
            </div>
            <div>
              <span>任务</span>
              <b>{{ selectedJobs.length ? `${selectedJobs.length} 次` : "未分析" }}</b>
            </div>
          </div>
        </div>
        <div class="pa-card">
          <h3 class="pa-card-title" style="padding-left:0;padding-top:0">对照适配</h3>
          <p class="hint" style="margin:0.45rem 0 0">
            {{ analysisLabel(selected) }}
            <template v-if="analysisOf(selected).score != null"> · 分 {{ analysisOf(selected).score }}</template>
          </p>
          <p v-if="(analysisOf(selected).reasons || []).length" class="patch-faq">{{ analysisOf(selected).reasons.join(" · ") }}</p>
          <p v-if="(analysisOf(selected).blockers || []).length" class="patch-faq">{{ analysisOf(selected).blockers.join(" · ") }}</p>
        </div>
        <div class="pa-card">
          <h3 class="pa-card-title" style="padding-left:0;padding-top:0">公告摘要</h3>
          <p class="patch-body">{{ selected.description || "这条公告没有独立描述，标题即摘要。" }}</p>
        </div>
        <div v-if="(selected.faq || []).length" class="pa-card">
          <h3 class="pa-card-title" style="padding-left:0;padding-top:0">FAQ</h3>
          <p v-for="(f, i) in selected.faq" :key="i" class="patch-faq">{{ f }}</p>
        </div>
        <div v-if="(selected.guesses || []).length > 1" class="pa-card">
          <h3 class="pa-card-title" style="padding-left:0;padding-top:0">组件猜测</h3>
          <p class="hint" style="margin:0">{{ selected.guesses.join(" · ") }}</p>
        </div>
        <div v-if="(selected.kbs || []).length" class="pa-card">
          <h3 class="pa-card-title" style="padding-left:0;padding-top:0">相关 KB</h3>
          <p class="kb-line">
            <a
              v-for="kb in selected.kbs.slice(0, 10)"
              :key="kb"
              :href="'https://support.microsoft.com/help/' + kb"
              target="_blank"
              rel="noopener"
            >KB{{ kb }}</a>
          </p>
        </div>
        <div class="pa-card flush">
          <h3 class="pa-card-title">分析任务{{ selectedJobs.length ? ` · ${selectedJobs.length}` : "" }}</h3>
          <div v-if="!selectedJobs.length" class="empty">还没有分析过这条 CVE。点右上角开始一次对照。</div>
          <div v-else class="patch-jobs">
            <template v-for="g in selectedJobGroups" :key="g.key">
              <h4 class="patch-job-group">{{ g.title }} · {{ g.items.length }}</h4>
              <article
                v-for="j in g.items"
                :key="j.id"
                class="patch-job"
                @click="openJob(j)"
              >
              <div class="patch-job-main">
                <strong>{{ jobVersionLine(j) || "样本对照中" }}</strong>
                <div class="hint">
                  {{ relativeTime(j.created_at) }}
                  <span v-if="j.progress?.message"> · {{ j.progress.message }}</span>
                </div>
                <div v-if="isLiveJob(j) && (j.progress?.percent != null || j.progress?.message)" class="pa-progress">
                  <i :style="{ width: (j.progress?.percent ?? 8) + '%' }"></i>
                </div>
              </div>
              <div class="patch-job-end">
                <span class="pa-st" :class="j.status">{{ statusLabel(j.status) }}</span>
                <div class="pa-pills" v-if="jobPills(j).length">
                  <span v-for="p in jobPills(j)" :key="p.t" class="pa-pill" :class="p.k">{{ p.t }}</span>
                </div>
              </div>
            </article>
            </template>
          </div>
        </div>
        <p class="hint">描述来自当月 CVRF，用来判断值不值得分析，不是本工具的结论。↑↓ 切换 CVE，Esc 返回。</p>
      </div>
    </template>
    <template v-else>
      <PageHeader title="本月补丁" :sub="headSub">
        <router-link class="pa-btn" to="/jobs">全部任务</router-link>
        <button class="pa-btn" type="button" :disabled="loading" @click="refresh">{{ loading ? "读取中…" : "刷新" }}</button>
        <button v-if="bulletin" class="pa-btn" type="button" @click="autoKernel">分析本期内核 CVE</button>
      </PageHeader>
      <div class="pa-stack">
        <p v-if="notice" class="pa-banner" :class="{ bad: noticeBad }">
          {{ notice }}
          <button v-if="noticeJobId" class="text-link" type="button" @click="openReport(noticeJobId)">打开任务</button>
        </p>
        <div class="pa-card">
          <div class="pa-meta">
            <div>
              <span>补丁日</span>
              <b>
                <select class="patch-select" :value="activeMonth" @change="goMonth($event.target.value)">
                  <option v-for="m in months" :key="m.id" :value="m.id">{{ m.title || m.id }}</option>
                </select>
              </b>
            </div>
            <div>
              <span>发布</span>
              <b>{{ fmtPatchDate(bulletin?.release_date) || "—" }}</b>
            </div>
            <div>
              <span>Windows CVE</span>
              <b>{{ allCves.length || "—" }}</b>
            </div>
            <div>
              <span>优先对照</span>
              <b>{{ bulletin ? (bulletin.priority_count ?? allCves.filter(r => analysisRank(r) === "priority").length) : "—" }}</b>
            </div>
            <div>
              <span>可利用向</span>
              <b>{{ bulletin ? (bulletin.weaponizable_count ?? allCves.filter(r => r.weaponizable).length) : "—" }}</b>
            </div>
            <div>
              <span>监控</span>
              <b>
                <label class="pa-check"><input type="checkbox" v-model="watchEnabled" @change="saveWatch" /> 补丁日</label>
                <label class="pa-check"><input type="checkbox" v-model="watchAuto" @change="saveWatch" /> 自动内核</label>
              </b>
            </div>
          </div>
        </div>
        <div class="pa-card flush">
          <div class="pa-stats">
            <button type="button" class="pa-stat run" :class="{ on: jobFilter === 'live' }" @click="setJobFilter('live')">
              <span>进行中</span><b>{{ liveN }}</b>
            </button>
            <button type="button" class="pa-stat ok" :class="{ on: jobFilter === 'done' }" @click="setJobFilter('done')">
              <span>已完成</span><b>{{ doneN }}</b>
            </button>
            <button type="button" class="pa-stat" :class="{ err: failN, on: jobFilter === 'fail' }" @click="setJobFilter('fail')">
              <span>需要处理</span><b>{{ failN }}</b>
            </button>
            <button type="button" class="pa-stat" :class="{ on: jobFilter === 'all' }" @click="setJobFilter('all')">
              <span>全部</span><b>{{ scoped.length || 0 }}</b>
            </button>
          </div>
        </div>
        <div class="pa-card flush">
          <div class="patch-toolbar">
            <input
              ref="searchEl"
              v-model="query"
              class="patch-search"
              type="search"
              placeholder="搜索 CVE、组件或标题  ·  /"
              autocomplete="off"
            />
            <nav v-if="bulletin" class="patch-tabs">
              <button type="button" :class="{ on: impact === 'priority' }" @click="impact = 'priority'">
                优先对照 <i>{{ tabCounts.priority }}</i>
              </button>
              <button type="button" :class="{ on: impact === 'weaponizable' }" @click="impact = 'weaponizable'">
                可利用向 <i>{{ tabCounts.weaponizable }}</i>
              </button>
              <button type="button" :class="{ on: impact === 'all' }" @click="impact = 'all'">
                全部 <i>{{ tabCounts.all }}</i>
              </button>
              <button type="button" :class="{ on: impact === 'dos' }" @click="impact = 'dos'">
                拒绝服务 <i>{{ tabCounts.dos }}</i>
              </button>
              <button type="button" :class="{ on: impact === 'info' }" @click="impact = 'info'">
                信息泄露 <i>{{ tabCounts.info }}</i>
              </button>
            </nav>
            <label v-if="bulletin" class="pa-check"><input type="checkbox" v-model="kernelOnly" /> 仅内核</label>
            <span class="pa-more">{{ bulletin ? pageLabel : (months.length ? `${months.length} 期` : "") }}</span>
          </div>
          <div v-if="loading && !bulletin" class="empty">正在读取公告…</div>
          <div v-else-if="!months.length" class="empty">{{ emptyDays || "正在读取补丁日…" }}</div>
          <div v-else-if="!filtered.length" class="empty">
            {{ emptyHint }}
            <div v-if="canRelax" class="pa-links" style="justify-content:center;margin-top:0.7rem">
              <button v-if="query" class="pa-btn" type="button" @click="query = ''">清除搜索</button>
              <button v-if="impact !== 'all'" class="pa-btn" type="button" @click="impact = 'all'">查看全部</button>
              <button v-if="kernelOnly" class="pa-btn" type="button" @click="kernelOnly = false">取消仅内核</button>
              <button v-if="jobFilter !== 'all'" class="pa-btn" type="button" @click="setJobFilter('all')">查看全部任务状态</button>
            </div>
          </div>
          <table v-else class="pa-table">
            <thead>
              <tr>
                <th class="fit-cve">编号</th>
                <th class="fit">影响</th>
                <th class="fit-file">组件</th>
                <th class="fill">摘要</th>
                <th class="fit-job">任务</th>
                <th class="fit-sm"></th>
              </tr>
            </thead>
            <tbody>
              <template v-for="g in pagedGroups" :key="g.key">
                <tr v-if="showJobGroups" class="patch-group">
                  <td colspan="6">{{ g.title }} <i>{{ g.total }}</i></td>
                </tr>
                <tr
                  v-for="r in g.items"
                  :key="r.cve"
                  class="click"
                  :class="{ on: selected?.cve === r.cve }"
                  @click="pick(r)"
                >
                  <td class="fit-cve">
                    <strong class="patch-cve">{{ r.cve }}</strong>
                    <div class="patch-flags">
                      <span v-if="analysisRank(r) === 'priority'" class="pa-badge hot">优先</span>
                      <span v-else-if="analysisRank(r) === 'ready'" class="pa-badge">可对照</span>
                      <span v-if="r.exploit_likely === 'detected'" class="pa-badge hot">在野</span>
                      <span v-else-if="r.exploit_likely === 'more'" class="pa-badge warn">较可能</span>
                      <span v-if="r.kernelish" class="pa-badge muted">内核</span>
                    </div>
                  </td>
                  <td class="fit"><span class="pa-badge" :class="impactClass(r) || 'muted'">{{ r.impact_label }}</span></td>
                  <td class="fit-file muted">{{ r.filename_guess || "未知" }}</td>
                  <td class="fill clip">{{ r.title }}</td>
                  <td class="fit-job">
                    <div v-if="chipsFor(r).length" class="patch-job-cell">
                      <button
                        v-for="j in chipsFor(r)"
                        :key="j.id"
                        class="pa-st"
                        :class="j.status"
                        type="button"
                        :title="jobChipTip(r, j)"
                        @click.stop="openJob(j)"
                      >{{ statusLabel(j.status) }}</button>
                      <button
                        v-if="extraJobCount(r)"
                        class="patch-job-more"
                        type="button"
                        :title="`${jobsFor(r.cve).length} 次分析，点开查看全部`"
                        @click.stop="pick(r)"
                      >+{{ extraJobCount(r) }}</button>
                    </div>
                    <span v-else class="muted">未分析</span>
                  </td>
                  <td class="fit-sm">
                    <button class="text-link" type="button" :disabled="isBusy(r.cve) && runLabel(r) !== '查看'" @click.stop="runOrOpen(r)">{{ runLabel(r) }}</button>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
          <Pager
            :total="filtered.length"
            :page="safePage"
            :count="pageCount"
            :label="pageLabel"
            :buttons="pageButtons"
            @go="goPage"
          />
        </div>
      </div>
    </template>
  </div>
</template>
<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import PageHeader from "../components/PageHeader.vue";
import Pager from "../components/Pager.vue";
import {
  apiGet, apiSend, cveJobOutcome, groupJobsByCve, isFailJob, isLiveJob, jobPills, jobVersionLine, LIKELY,
  primaryJob, relativeTime, statusLabel,
} from "../lib/api.js";
import { jobsStore, loadJobs, upsertJob } from "../lib/jobs.js";
import { PAGE_SIZE, parsePage, usePager } from "../lib/pager.js";
import { ui } from "../lib/store.js";
import { openReport } from "../lib/engine.js";

const JOB_FILTERS = new Set(["all", "live", "done", "fail"]);
const OUTCOME_ORDER = { fail: 0, live: 1, done: 2, none: 3 };
const OUTCOME_TITLE = { fail: "需要处理", live: "进行中", done: "已完成", none: "未分析" };
const JOB_GROUP_TITLE = { live: "进行中", fail: "需要处理", done: "已完成", other: "其他" };

const route = useRoute();
const router = useRouter();
const months = ref([]);
const bulletin = ref(null);
const selected = ref(null);
const empty = ref("");
const emptyDays = ref("");
const notice = ref("");
const noticeBad = ref(false);
const noticeJobId = ref("");
const watchEnabled = ref(true);
const watchAuto = ref(false);
const impact = ref(localStorage.getItem("patchImpactFilter") || "priority");
const kernelOnly = ref(localStorage.getItem("patchKernelOnly") === "1");
const query = ref("");
const loading = ref(false);
const copied = ref(false);
const queued = ref({});
const jobs = computed(() => jobsStore.items);
const searchEl = ref(null);
const cache = {};
let daysCache = null;
let copyTimer = 0;
let opening = "";

function readJobFilter() {
  const fromQuery = String(route.query.f || "");
  return JOB_FILTERS.has(fromQuery) ? fromQuery : "all";
}
const jobFilter = ref(readJobFilter());

watch(impact, v => localStorage.setItem("patchImpactFilter", v));
watch(kernelOnly, v => localStorage.setItem("patchKernelOnly", v ? "1" : "0"));
watch(() => String(route.query.f || ""), f => {
  const next = JOB_FILTERS.has(f) ? f : "all";
  if (next !== jobFilter.value) jobFilter.value = next;
});

function fmtPatchDate(iso) {
  const d = String(iso || "").slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return "";
  const [y, m, day] = d.split("-");
  return `${y} 年 ${Number(m)} 月 ${Number(day)} 日`;
}
function applyWatch(w) {
  if (!w) return;
  watchEnabled.value = w.enabled !== false;
  watchAuto.value = !!w.auto_kernel;
}
function analysisOf(r) {
  return (r && r.analysis) || {};
}
function analysisRank(r) {
  return analysisOf(r).rank || "";
}
function analysisLabel(r) {
  const rank = analysisRank(r);
  if (rank === "priority") return "优先对照";
  if (rank === "ready") return "可自动对照";
  if ((analysisOf(r).blockers || []).length) return "需手填 / 收益低";
  return "对照收益低";
}
function impactClass(r) {
  if (r.weaponizable || r.impact === "rce" || r.exploit_likely === "detected") return "hot";
  if (r.impact === "dos") return "warn";
  return "";
}
function likelyClass(r) {
  if (r.exploit_likely === "detected") return "hot";
  if (r.exploit_likely === "more") return "warn";
  return "";
}
function flash(msg, bad = false, jobId = "") {
  notice.value = msg;
  noticeBad.value = bad;
  noticeJobId.value = jobId || "";
}
function jobsFor(cve) {
  return jobIndex.value[String(cve || "").toUpperCase()] || [];
}
function primaryFor(row) {
  return primaryJob(jobsFor(row?.cve));
}
function outcomeFor(row) {
  return cveJobOutcome(jobsFor(row?.cve));
}
function chipsFor(row) {
  const list = jobsFor(row?.cve);
  if (!list.length) return [];
  const pick = (pred) => {
    let best = null;
    for (const j of list) {
      if (!pred(j)) continue;
      if (!best || String(j.created_at || "") > String(best.created_at || "")) best = j;
    }
    return best;
  };
  const chips = [];
  const live = pick(isLiveJob);
  const fail = pick(isFailJob);
  const done = pick(j => j.status === "completed");
  if (live) chips.push(live);
  if (fail) chips.push(fail);
  if (done) chips.push(done);
  return chips;
}
function extraJobCount(row) {
  return Math.max(0, jobsFor(row?.cve).length - chipsFor(row).length);
}
function jobGroupKey(j) {
  if (isLiveJob(j)) return "live";
  if (j.status === "completed") return "done";
  if (isFailJob(j)) return "fail";
  return "other";
}
function isBusy(cve) {
  if (queued.value[cve] === "busy") return true;
  return jobsFor(cve).some(isLiveJob);
}
function runLabel(r) {
  const s = queued.value[r.cve];
  if (s === "busy") return "排队中";
  if (isBusy(r.cve)) return "查看";
  if (jobsFor(r.cve).length) return "再分析";
  if (s === "queued") return "再分析";
  return "分析";
}
function enqueueLabel(r) {
  if (!r) return "分析此 CVE";
  if (queued.value[r.cve] === "busy") return "排队中";
  if (isBusy(r.cve)) return "分析中";
  if (jobsFor(r.cve).length) return "再分析";
  return "分析此 CVE";
}
function jobChipTip(r, j) {
  const extra = jobsFor(r.cve).length > 1 ? `（共 ${jobsFor(r.cve).length} 次）` : "";
  return `${statusLabel(j.status)}${extra} · 点状态打开这次分析`;
}
function setJobFilter(f) {
  if (!JOB_FILTERS.has(f)) f = "all";
  if (f !== "all" && impact.value !== "all") {
    const nAll = scoped.value.filter(r => outcomeFor(r) === f).length;
    const nNow = impactRows.value.filter(r => outcomeFor(r) === f).length;
    if (nAll && !nNow) {
      impact.value = "all";
      flash("已切到「全部」CVE，当前影响页签下没有对应任务。");
    }
  }
  jobFilter.value = f;
  const q = { ...route.query };
  if (!q.b && activeMonth.value) q.b = activeMonth.value;
  if (f === "all") delete q.f;
  else q.f = f;
  delete q.p;
  router.replace({ path: "/patch", query: q });
}
function openJob(j) {
  if (j?.id) openReport(j.id);
}
function runOrOpen(r) {
  if (isBusy(r.cve) || runLabel(r) === "查看") {
    const j = primaryFor(r);
    if (j) openJob(j);
    return;
  }
  run(r);
}
function matchQuery(r, q) {
  if (!q) return true;
  const blob = `${r.cve} ${r.title || ""} ${r.filename_guess || ""} ${(r.guesses || []).join(" ")}`.toLowerCase();
  return blob.includes(q);
}

const pendingEdge = ref("");

const activeMonth = computed(() => String(route.query.b || bulletin.value?.bulletin || months.value[0]?.id || ""));
const reading = computed(() => !!(route.query.cve && selected.value));
const allCves = computed(() => bulletin.value?.cves || []);
const jobIndex = computed(() => groupJobsByCve(jobs.value));
const selectedJobs = computed(() => jobsFor(selected.value?.cve));
const selectedJobGroups = computed(() => {
  const buckets = { live: [], fail: [], done: [], other: [] };
  for (const j of selectedJobs.value) buckets[jobGroupKey(j)].push(j);
  return ["live", "fail", "done", "other"]
    .filter(k => buckets[k].length)
    .map(k => ({ key: k, title: JOB_GROUP_TITLE[k], items: buckets[k] }));
});
const scoped = computed(() => {
  const q = query.value.trim().toLowerCase();
  return allCves.value.filter(r => {
    if (kernelOnly.value && !r.kernelish) return false;
    return matchQuery(r, q);
  });
});
const tabCounts = computed(() => {
  const rows = scoped.value;
  return {
    all: rows.length,
    priority: rows.filter(r => analysisRank(r) === "priority").length,
    weaponizable: rows.filter(r => r.weaponizable).length,
    dos: rows.filter(r => r.impact === "dos").length,
    info: rows.filter(r => r.impact === "info").length,
  };
});
const impactRows = computed(() => {
  if (impact.value === "all") return scoped.value;
  if (impact.value === "priority") return scoped.value.filter(r => analysisRank(r) === "priority");
  if (impact.value === "weaponizable") return scoped.value.filter(r => r.weaponizable);
  return scoped.value.filter(r => (r.impact || "") === impact.value);
});
const liveN = computed(() => scoped.value.filter(r => outcomeFor(r) === "live").length);
const doneN = computed(() => scoped.value.filter(r => outcomeFor(r) === "done").length);
const failN = computed(() => scoped.value.filter(r => outcomeFor(r) === "fail").length);
const filtered = computed(() => {
  const rows = impactRows.value.filter(r => {
    if (jobFilter.value === "all") return true;
    return outcomeFor(r) === jobFilter.value;
  });
  if (jobFilter.value !== "all") return rows;
  return [...rows].sort((a, b) => (OUTCOME_ORDER[outcomeFor(a)] ?? 9) - (OUTCOME_ORDER[outcomeFor(b)] ?? 9));
});
const showJobGroups = computed(() => jobFilter.value === "all");
const page = computed(() => parsePage(route.query.p));
const { pageCount, safePage, paged, pageLabel, pageButtons } = usePager(filtered, page);
const pagedGroups = computed(() => {
  const groups = [];
  const totals = { fail: 0, live: 0, done: 0, none: 0 };
  for (const r of filtered.value) totals[outcomeFor(r)] = (totals[outcomeFor(r)] || 0) + 1;
  for (const r of paged.value) {
    const key = outcomeFor(r);
    const last = groups[groups.length - 1];
    if (last && last.key === key) last.items.push(r);
    else groups.push({ key, title: OUTCOME_TITLE[key] || key, total: totals[key] || 0, items: [r] });
  }
  return groups;
});
const canRelax = computed(() => allCves.value.length && !!(query.value || impact.value !== "all" || kernelOnly.value || jobFilter.value !== "all"));
const IMPACT_NAME = { all: "全部", priority: "优先对照", weaponizable: "可利用向", dos: "拒绝服务", info: "信息泄露" };
const JOB_FILTER_NAME = { all: "全部", live: "进行中", done: "已完成", fail: "需要处理" };
const emptyHint = computed(() => {
  if (empty.value) return empty.value;
  if (query.value.trim()) return `没有匹配「${query.value.trim()}」的 CVE。`;
  if (jobFilter.value !== "all" && impact.value !== "all") {
    return `「${IMPACT_NAME[impact.value] || impact.value}」下没有「${JOB_FILTER_NAME[jobFilter.value]}」的 CVE。可改选影响页签的「全部」。`;
  }
  if (jobFilter.value === "fail") return "当前筛选下没有需要处理的 CVE。失败或已取消、且还没有更新一次成功分析的条目会出现在这里。";
  if (jobFilter.value === "done") return "当前筛选下没有已完成的 CVE。";
  if (jobFilter.value === "live") return "当前没有正在分析的 CVE。";
  if (allCves.value.length) return "当前筛选下没有 CVE。可改选「全部」，或取消「仅内核」。";
  return months.value.length ? "正在读取这一期 CVE…" : "选择一个补丁日。";
});
const headSub = computed(() => {
  const date = fmtPatchDate(bulletin.value?.release_date);
  const n = allCves.value.length;
  const w = bulletin.value?.weaponizable_count ?? allCves.value.filter(r => r.weaponizable).length;
  const k = bulletin.value?.kernel_count ?? allCves.value.filter(r => r.kernelish).length;
  const p = bulletin.value?.priority_count ?? allCves.value.filter(r => analysisRank(r) === "priority").length;
  const bits = [
    date,
    n ? `${n} 条 Windows CVE` : "",
    p ? `优先对照 ${p}` : "",
    w ? `可利用向 ${w}` : "",
    k ? `内核 ${k}` : "",
    n ? `已完成 ${doneN.value}` : "",
    failN.value ? `需要处理 ${failN.value}` : "",
    liveN.value ? `分析中 ${liveN.value}` : "",
  ].filter(Boolean);
  return bits.join(" · ") || "选择补丁日，浏览 CVE。";
});

watch(filtered, rows => {
  const want = route.query.cve;
  if (!want) {
    if (selected.value && !rows.some(r => r.cve === selected.value.cve)) selected.value = null;
    return;
  }
  selected.value = rows.find(r => r.cve === want) || allCves.value.find(r => r.cve === want) || null;
});
watch(paged, rows => {
  if (!pendingEdge.value || !rows.length) return;
  selected.value = pendingEdge.value === "last" ? rows[rows.length - 1] : rows[0];
  pendingEdge.value = "";
});
watch([impact, query, kernelOnly, jobFilter], () => {
  if (Number(route.query.p || 1) > 1 && !route.query.cve) goPage(1);
});
watch(pageCount, n => {
  if (!filtered.value.length) return;
  if (page.value > n) goPage(n);
});

function pageOf(cve) {
  const i = filtered.value.findIndex(r => r.cve === cve);
  return i < 0 ? 1 : Math.floor(i / PAGE_SIZE) + 1;
}

function syncCveQuery(cve) {
  const cur = route.query.cve || "";
  const nextPage = cve ? pageOf(cve) : page.value;
  const curPage = String(route.query.p || "");
  const nextPageQ = nextPage > 1 ? String(nextPage) : "";
  if ((cve || "") === cur && curPage === nextPageQ) return;
  const q = { ...route.query };
  if (!q.b && activeMonth.value) q.b = activeMonth.value;
  if (cve) q.cve = cve;
  else delete q.cve;
  if (nextPage > 1) q.p = String(nextPage);
  else delete q.p;
  router.replace({ path: "/patch", query: q });
}

function goPage(n) {
  const next = Math.min(pageCount.value, Math.max(1, n));
  if (next === page.value) return;
  const q = { ...route.query };
  if (!q.b && activeMonth.value) q.b = activeMonth.value;
  if (next > 1) q.p = String(next);
  else delete q.p;
  router.replace({ path: "/patch", query: q });
  if (!q.cve) document.querySelector(".pa-body")?.scrollTo({ top: 0 });
}

async function loadDays(force = false) {
  if (!force && daysCache?.length) {
    months.value = daysCache;
    return months.value;
  }
  try {
    const data = await apiGet(force ? "/patch-tuesday?refresh=1" : "/patch-tuesday");
    months.value = data.months || [];
    daysCache = months.value;
    applyWatch(data.watch);
    emptyDays.value = months.value.length ? "" : "MSRC 没有返回月度公告。";
    return months.value;
  } catch (e) {
    emptyDays.value = e.message;
    flash("读取补丁日失败", true);
    return months.value;
  }
}

async function openMonth(id, force = false) {
  if (!id) return;
  if (!force && bulletin.value?.bulletin === id && cache[id]) return;
  if (!force && opening === id && cache[id]) return;
  opening = id;
  if (bulletin.value?.bulletin !== id) {
    selected.value = null;
    query.value = "";
  }
  const cached = !force && cache[id];
  if (!cached) loading.value = true;
  flash(force ? `正在向微软刷新 ${id}…` : (cached ? "" : `正在读取 ${id}…`));
  try {
    const data = cached || await apiGet(`/patch-tuesday?bulletin=${encodeURIComponent(id)}${force ? "&refresh=1" : ""}`);
    cache[id] = data;
    if (opening !== id && !force) return;
    bulletin.value = data;
    applyWatch(data.watch);
    const all = data.cves || [];
    empty.value = all.length ? "" : "这一期没有可列的 Windows CVE。";
    flash("");
    const want = route.query.cve;
    const hit = want && all.find(r => r.cve === want);
    if (hit) {
      selected.value = hit;
      if (impact.value !== "all" && ((impact.value === "weaponizable" && !hit.weaponizable) || (impact.value !== "weaponizable" && hit.impact !== impact.value))) {
        impact.value = "all";
      }
    }
  } catch (e) {
    empty.value = e.message;
    flash("读取公告失败", true);
  } finally {
    if (opening === id) loading.value = false;
  }
}

function goMonth(id) {
  if (!id) return;
  if (String(route.query.b || "") === id && !route.query.cve) return;
  const q = { b: id };
  if (jobFilter.value !== "all") q.f = jobFilter.value;
  router.replace({ path: "/patch", query: q });
}

function backToList() {
  selected.value = null;
  syncCveQuery("");
}

async function refresh() {
  await Promise.all([loadDays(true), loadJobs()]);
  const id = activeMonth.value || months.value[0]?.id;
  if (id) await openMonth(id, true);
}

function pick(r) {
  selected.value = r;
  syncCveQuery(r.cve);
}

async function saveWatch() {
  try {
    await apiSend("/config/watch", { method: "PUT", json: { enabled: watchEnabled.value, auto_kernel: watchAuto.value } });
  } catch (e) { flash("保存监控设置失败: " + e.message, true); }
}
async function autoKernel() {
  const n = bulletin.value?.ready_count ?? allCves.value.filter(r => analysisOf(r).auto_ok).length;
  if (!window.confirm(`将为本期尚未分析、且适合自动对照的 CVE 排队（最多 6 条，当前约 ${n} 条可自动对照）。是否继续？`)) return;
  flash("正在排队本期内核/驱动 CVE…");
  try {
    const q = bulletin.value?.bulletin ? `?bulletin=${encodeURIComponent(bulletin.value.bulletin)}` : "";
    const data = await apiSend(`/patch-tuesday${q}`);
    const started = (data.started || []).filter(x => x.job_id);
    for (const x of started) queued.value[x.cve] = "queued";
    queued.value = { ...queued.value };
    flash(started.length ? `已启动 ${started.length} 个任务` : "没有新的可自动分析项", false, started[0]?.job_id || "");
    await loadJobs();
  } catch (e) { flash("自动分析失败: " + e.message, true); }
}
async function run(row) {
  if (isBusy(row.cve)) return;
  queued.value = { ...queued.value, [row.cve]: "busy" };
  try {
    const data = await apiSend("/jobs/from-cve", {
      json: {
        cve: row.cve,
        filename: row.filename_guess || "",
        run_llm: true,
        routing_mode: localStorage.getItem("patchalyzer.routing_mode") || "auto",
      },
    });
    const jobId = data.job_id || "";
    if (jobId) {
      upsertJob({
        id: jobId,
        title: row.cve,
        cve: row.cve,
        status: "pending",
        created_at: new Date().toISOString(),
        old_label: row.filename_guess || "",
      });
    }
    queued.value = { ...queued.value, [row.cve]: "queued" };
    loadJobs();
    if (jobId) openJob({ id: jobId });
  } catch (e) {
    const next = { ...queued.value };
    delete next[row.cve];
    queued.value = next;
    flash(e.message, true);
  }
}
async function copyCve() {
  if (!selected.value) return;
  try {
    await navigator.clipboard.writeText(selected.value.cve);
  } catch {
    flash("复制失败", true);
    return;
  }
  copied.value = true;
  clearTimeout(copyTimer);
  copyTimer = setTimeout(() => { copied.value = false; }, 1400);
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
  const rows = reading.value ? filtered.value : paged.value;
  const i = rows.findIndex(r => r.cve === selected.value?.cve);
  const move = (row) => {
    if (!row) return;
    if (reading.value) pick(row);
    else selected.value = row;
  };
  if (e.key === "ArrowDown" || e.key === "j") {
    e.preventDefault();
    if (i < 0) move(rows[0]);
    else if (rows[i + 1]) move(rows[i + 1]);
    else if (!reading.value && safePage.value < pageCount.value) {
      pendingEdge.value = "first";
      goPage(safePage.value + 1);
    }
  } else if (e.key === "ArrowUp" || e.key === "k") {
    e.preventDefault();
    if (i < 0) move(rows[0]);
    else if (rows[i - 1]) move(rows[i - 1]);
    else if (!reading.value && safePage.value > 1) {
      pendingEdge.value = "last";
      goPage(safePage.value - 1);
    }
  } else if (e.key === "Enter" && selected.value) {
    e.preventDefault();
    if (reading.value) {
      const j = primaryFor(selected.value);
      if (j) openJob(j);
      else run(selected.value);
    } else pick(selected.value);
  } else if (e.key === "Escape") {
    if (reading.value) {
      e.preventDefault();
      backToList();
    } else if (query.value) {
      query.value = "";
    }
  }
}

watch(() => String(route.query.b || ""), async b => {
  if (b) {
    if (!months.value.length) loadDays(false);
    await openMonth(b);
    return;
  }
  if (!months.value.length) await loadDays(false);
  const id = months.value[0]?.id || "";
  if (!id) return;
  router.replace({ path: "/patch", query: { ...route.query, b: id } });
}, { immediate: true });

onMounted(() => {
  window.addEventListener("keydown", onKey);
  loadJobs({ silent: true });
});
onUnmounted(() => {
  window.removeEventListener("keydown", onKey);
  clearTimeout(copyTimer);
});
</script>
<style scoped>
.patch-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.35rem 0.85rem;
  padding: 0.55rem 1.1rem;
  min-height: 2.7rem;
  border-bottom: 1px solid var(--line);
  font-size: var(--text-md);
  color: var(--muted);
}
.patch-toolbar .pa-more { margin-left: auto; }
.patch-search {
  flex: 1;
  min-width: 12rem;
  border: 1px solid var(--line-strong);
  border-radius: 8px;
  padding: 0.4rem 0.7rem;
  font-size: var(--text-md);
  background: #fff;
  outline: none;
}
.patch-search:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(26, 115, 232, 0.12);
}
.patch-select {
  border: 1px solid var(--line-strong);
  border-radius: 8px;
  padding: 0.22rem 0.5rem;
  background: #fff;
  font: inherit;
  font-weight: 500;
  max-width: 16rem;
}
.patch-tabs {
  display: flex;
  align-items: stretch;
  gap: 0;
}
.patch-tabs button {
  background: none;
  border: 0;
  border-bottom: 2px solid transparent;
  padding: 0.55rem 0.55rem;
  color: var(--muted);
  cursor: pointer;
  font: inherit;
  font-size: var(--text-md);
}
.patch-tabs button i {
  font-style: normal;
  margin-left: 0.28rem;
  font-size: var(--text-xs);
  color: #80868b;
}
.patch-tabs button:hover { color: var(--ink); }
.patch-tabs button.on {
  color: var(--ink);
  border-bottom-color: var(--accent);
  font-weight: 600;
}
.patch-tabs button.on i { color: var(--accent); }
.patch-cve { color: var(--accent); font-weight: 600; letter-spacing: -0.01em; }
.patch-flags { display: flex; flex-wrap: wrap; gap: 0.25rem; margin-top: 0.28rem; }
.patch-body {
  margin: 0.55rem 0 0;
  font-size: var(--text-lg);
  line-height: 1.7;
  color: #3c4043;
}
.patch-faq {
  margin: 0.45rem 0 0;
  font-size: var(--text-md);
  line-height: 1.65;
  color: #5f6b76;
}
.kb-line {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem 0.85rem;
  margin: 0.45rem 0 0;
  font-size: var(--text-md);
}
.pa-banner .text-link { margin-left: 0.7rem; }
.pa-meta .pa-check { display: flex; }
.hot { color: var(--err); }
.warn { color: var(--warn); }
.pa-stat {
  cursor: pointer;
  font: inherit;
  text-align: left;
  width: 100%;
}
.pa-stat.on { background: #f8fbff; }
.patch .pa-table .fit-job { width: 11.5rem; white-space: normal; }
.patch-job-cell {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.22rem;
}
.patch-group td {
  background: #f8f9fb;
  font-size: var(--text-xs);
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--muted);
  padding: 0.45rem 1.1rem;
}
.patch-group i {
  font-style: normal;
  margin-left: 0.28rem;
  color: #80868b;
}
.patch-job-group {
  margin: 0;
  padding: 0.55rem 1.1rem 0.35rem;
  font-size: var(--text-xs);
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--muted);
  background: #f8f9fb;
  border-bottom: 1px solid var(--line);
}
.patch-job-more {
  margin-left: 0.28rem;
  padding: 0;
  border: 0;
  background: none;
  color: var(--accent);
  font: inherit;
  font-size: var(--text-xs);
  font-weight: 600;
  cursor: pointer;
}
.patch-job-more:hover { text-decoration: underline; }
.patch-jobs { border-top: 1px solid var(--line); }
.patch-job {
  display: flex;
  align-items: center;
  gap: 0.85rem;
  padding: 0.85rem 1.1rem;
  border-bottom: 1px solid var(--line);
  cursor: pointer;
}
.patch-job:last-child { border-bottom: 0; }
.patch-job:hover { background: #f8fbff; }
.patch-job-main { min-width: 0; flex: 1; }
.patch-job-main strong {
  display: block;
  font-weight: 500;
  font-size: var(--text-lg);
}
.patch-job-end { text-align: right; flex-shrink: 0; }
.pa-st { cursor: pointer; }
</style>
