<template>
  <div class="pa-page">
    <PageHeader title="工作台" :sub="headSub">
      <router-link class="pa-btn" to="/patch">本月补丁</router-link>
      <router-link class="pa-btn" to="/jobs">全部任务</router-link>
      <button class="pa-btn" type="button" @click="load">刷新</button>
    </PageHeader>
    <div class="pa-stack">
      <p v-if="healthOk && !llmSet" class="pa-banner">
        尚未填写 API Key。<router-link to="/settings">去设置</router-link> 后才能自动生成报告。
      </p>
      <div class="pa-card">
        <p class="pa-kicker">开始</p>
        <div class="pa-links" style="margin-top:0.35rem">
          <router-link class="pa-btn primary" to="/analyze">补丁对照</router-link>
          <router-link class="pa-btn primary" to="/audit">内核审计</router-link>
          <router-link class="pa-btn" to="/patch">本月补丁</router-link>
        </div>
        <p class="hint" style="margin:0.55rem 0 0">补丁对照需要 CVE 或一对样本。只有一个 .sys 时用内核审计。</p>
      </div>
      <div class="pa-card flush">
        <div class="pa-stats">
          <button type="button" class="pa-stat" :class="{ err: inbox.need.length }" @click="goJobs('fail')">
            <span>需要处理</span><b>{{ inbox.need.length }}</b>
          </button>
          <button type="button" class="pa-stat" :class="{ err: inbox.kev.length }" @click="goJobs('all')">
            <span>已知在野</span><b>{{ inbox.kev.length }}</b>
          </button>
          <button type="button" class="pa-stat" :class="{ warn: inbox.bypass.length }" @click="goJobs('all')">
            <span>有绕过面</span><b>{{ inbox.bypass.length }}</b>
          </button>
          <button type="button" class="pa-stat run" @click="goJobs('live')">
            <span>分析中</span><b>{{ live.length }}</b>
          </button>
        </div>
      </div>
      <div v-if="inbox.need.length" class="pa-card flush">
        <div class="pa-card-head">
          <h3>需要处理</h3>
          <router-link class="pa-btn" to="/jobs?f=fail">全部</router-link>
        </div>
        <div class="pa-list">
          <JobRow v-for="j in inbox.need.slice(0, 6)" :key="j.id" :job="j" @open="open" />
        </div>
      </div>
      <div v-if="inbox.kev.length" class="pa-card flush">
        <h3 class="pa-card-title">已知在野（CISA KEV）</h3>
        <div class="pa-list">
          <JobRow v-for="j in inbox.kev.slice(0, 6)" :key="j.id" :job="j" @open="open" />
        </div>
      </div>
      <div v-if="inbox.bypass.length" class="pa-card flush">
        <h3 class="pa-card-title">补丁有绕过面</h3>
        <div class="pa-list">
          <JobRow v-for="j in inbox.bypass.slice(0, 6)" :key="j.id" :job="j" @open="open" />
        </div>
      </div>
      <div class="pa-card flush">
        <h3 class="pa-card-title">当前运行</h3>
        <div v-if="!live.length" class="empty">
          当前没有正在分析的任务。
          <div class="pa-links" style="justify-content:center;margin-top:0.7rem">
            <router-link class="pa-btn primary" to="/patch">去本月补丁</router-link>
            <router-link class="pa-btn" to="/analyze">上传样本</router-link>
            <router-link class="pa-btn" to="/audit">内核审计</router-link>
          </div>
        </div>
        <div v-else class="pa-list">
          <JobRow v-for="j in livePaged" :key="j.id" :job="j" @open="open" />
        </div>
        <Pager
          :total="live.length"
          :page="liveSafe"
          :count="livePageCount"
          :label="liveLabel"
          :buttons="liveButtons"
          @go="goLivePage"
        />
      </div>
      <div class="pa-card flush">
        <div class="pa-card-head">
          <h3>最近任务</h3>
          <router-link class="pa-btn" to="/jobs">全部</router-link>
        </div>
        <div v-if="!ranked.length" class="empty">暂无已完成任务。从本月补丁选 CVE，或上传样本。失败的在「需要处理」。</div>
        <div v-else class="pa-list">
          <JobRow v-for="j in recentPaged" :key="j.id" :job="j" @open="open" />
        </div>
        <Pager
          :total="ranked.length"
          :page="recentSafe"
          :count="recentCount"
          :label="recentLabel"
          :buttons="recentButtons"
          @go="goRecentPage"
        />
      </div>
      <p class="hint">{{ monthTitle }} · 监控 {{ watchText }} · {{ llmSet ? (llmModel || "模型已配置") : "未配置模型" }} · <router-link to="/settings">设置</router-link></p>
    </div>
  </div>
</template>
<script setup>
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import JobRow from "../components/JobRow.vue";
import PageHeader from "../components/PageHeader.vue";
import Pager from "../components/Pager.vue";
import { apiGet } from "../lib/api.js";
import { jobsStore, loadJobs } from "../lib/jobs.js";
import { parsePage, usePager } from "../lib/pager.js";
import { openReport } from "../lib/engine.js";

const route = useRoute();
const router = useRouter();
const jobs = computed(() => jobsStore.items);
const healthOk = ref(false);
const llmSet = ref(false);
const llmModel = ref("");
const llmProvider = ref("");
const llmKeyPreview = ref("");
const watchText = ref("—");
const monthTitle = ref("未拉取");
let daysLoaded = false;

const inbox = computed(() => {
  const list = jobs.value;
  const kev = list.filter(j => j.in_kev === 1 || j.in_kev === true);
  const bypass = list.filter(j => String(j.bypass_verdict || "") === "bypassable" && !(j.in_kev === 1 || j.in_kev === true));
  const need = list.filter(j => j.status === "failed" || j.status === "cancelled");
  return { kev, bypass, need };
});
const live = computed(() => jobs.value.filter(j => j.status === "running" || j.status === "pending"));
const ranked = computed(() => [...jobs.value]
  .filter(j => j.status === "completed")
  .sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || ""))));
const headSub = computed(() => {
  if (inbox.value.need.length) return `${inbox.value.need.length} 个任务需要处理。点一条打开决策页。`;
  if (inbox.value.kev.length) return `${inbox.value.kev.length} 个已知在野。优先下发检测。`;
  if (live.value.length) return `${live.value.length} 个任务正在分析。`;
  if (monthTitle.value && monthTitle.value !== "未拉取") return `${monthTitle.value} · 从本月补丁开始对照。`;
  return "从本月补丁选 CVE，或上传样本开始对照。";
});
const livePage = computed(() => parsePage(route.query.lp));
const recentPage = computed(() => parsePage(route.query.p));
const {
  pageCount: livePageCount,
  safePage: liveSafe,
  paged: livePaged,
  pageLabel: liveLabel,
  pageButtons: liveButtons,
} = usePager(live, livePage);
const {
  pageCount: recentCount,
  safePage: recentSafe,
  paged: recentPaged,
  pageLabel: recentLabel,
  pageButtons: recentButtons,
} = usePager(ranked, recentPage);

function patchHomeQuery(updates) {
  const q = { ...route.query };
  for (const [k, v] of Object.entries(updates)) {
    if (v == null || v === "" || v === 1 || v === "1") delete q[k];
    else q[k] = String(v);
  }
  router.replace({ path: "/app", query: q });
}
function goLivePage(n) {
  const next = Math.min(livePageCount.value, Math.max(1, n));
  if (next === livePage.value) return;
  patchHomeQuery({ lp: next });
}
function goRecentPage(n) {
  const next = Math.min(recentCount.value, Math.max(1, n));
  if (next === recentPage.value) return;
  patchHomeQuery({ p: next });
}

watch(livePageCount, n => {
  if (live.value.length && livePage.value > n) goLivePage(n);
});
watch(recentCount, n => {
  if (ranked.value.length && recentPage.value > n) goRecentPage(n);
});

let loadBusy = false;
async function load(heavy = true) {
  if (loadBusy) return;
  loadBusy = true;
  try {
    const reqs = [loadJobs({ silent: !heavy })];
    if (heavy) {
      reqs.push(apiGet("/health", { timeout: 4000 }), apiGet("/config/llm", { timeout: 4000 }), apiGet("/config/watch", { timeout: 4000 }));
      if (!daysLoaded) reqs.push(apiGet("/patch-tuesday", { timeout: 8000 }));
    }
    const [j, h, llm, w, days] = await Promise.allSettled(reqs);
    if (heavy) {
      healthOk.value = h.status === "fulfilled" && h.value?.status === "ok";
      if (llm.status === "fulfilled") {
        llmSet.value = !!llm.value?.api_key_set;
        llmModel.value = llm.value?.model || "";
        llmProvider.value = llm.value?.provider || "";
        llmKeyPreview.value = llm.value?.api_key_preview || "";
      } else {
        llmSet.value = false;
      }
      if (w.status === "fulfilled") {
        watchText.value = (w.value.enabled === false ? "关闭" : "开启") + (w.value.auto_kernel ? " · 自动分析内核" : "");
      }
      if (days && days.status === "fulfilled") {
        daysLoaded = true;
        const m = (days.value.months || [])[0];
        monthTitle.value = m ? (m.title || m.id) : "未拉取";
      }
    }
  } catch { /* ignore */ }
  finally { loadBusy = false; }
}

function goJobs(f) {
  router.push(f ? { path: "/jobs", query: { f } } : { path: "/jobs" });
}
function open(id) { openReport(id); }

onMounted(() => {
  load(true);
});
</script>
<style scoped>
.pa-stat {
  cursor: pointer;
  font: inherit;
  text-align: left;
  width: 100%;
}
.pa-stat:hover { background: #f8fbff; }
</style>
