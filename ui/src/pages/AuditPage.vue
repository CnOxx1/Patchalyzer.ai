<template>
  <div class="pa-page">
    <PageHeader title="内核审计" sub="上传单个驱动或内核模块，枚举用户入口并按缺陷类打分。没有补丁对照，结果是嫌疑与观察条件。">
      <router-link class="pa-btn" to="/analyze">补丁对照</router-link>
      <router-link class="pa-btn" to="/jobs?kind=audit&f=all">全部任务</router-link>
      <button class="pa-btn" type="button" :disabled="loading || refreshing" @click="refresh">{{ loading || refreshing ? "读取中…" : "刷新" }}</button>
    </PageHeader>
    <div class="pa-stack">
      <form class="pa-stack" @submit.prevent="submit">
        <div class="pa-card pa-form">
          <p class="pa-kicker">单文件样本</p>
          <label class="pa-drop" :class="{ has: sampleName }">
            <small>内核 / 驱动<span class="req">*</span></small>
            <span>{{ sampleName || "选择 .sys / .dll / .exe" }}</span>
            <input type="file" accept=".sys,.dll,.exe" @change="onFile" />
          </label>
          <label class="pa-field">
            <span>任务名称</span>
            <input v-model="title" placeholder="可留空，默认用文件名" />
          </label>
          <label class="pa-check">
            <input v-model="runLlm" type="checkbox" /> 启用 LLM 核对（关闭则只跑确定性扫描）
          </label>
          <p class="hint">会下载 PDB（若可），解析 IOCTL / FastIo / MajorFunction，再按缺失 Probe、缺失锁、生命周期、检查-使用窗口打分。不生成 exploit 或触发步骤。</p>
          <p v-if="errorText" class="hint" style="color:var(--err)">{{ errorText }}</p>
          <button class="pa-btn primary pa-go" type="submit" :disabled="busy || !sample">{{ busy ? "正在排队…" : "开始审计" }}</button>
        </div>
      </form>
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
            <span>全部</span><b>{{ auditJobs.length }}</b>
          </button>
        </div>
      </div>
      <div class="pa-card flush">
        <div class="pa-card-head">
          <h3>审计任务</h3>
          <span class="hint">{{ jobHint }}</span>
        </div>
        <div v-if="loading && !auditJobs.length" class="empty">正在读取任务…</div>
        <div v-else-if="!shownJobs.length" class="empty empty-hero">
          <strong>{{ emptyTitle }}</strong>
          <p>{{ emptyHint }}</p>
          <div v-if="auditJobs.length && jobFilter !== 'all'" class="pa-links" style="justify-content:center;margin-top:0.85rem">
            <button class="pa-btn" type="button" @click="jobFilter = 'all'">查看全部审计任务</button>
          </div>
        </div>
        <div v-else class="pa-list">
          <JobRow v-for="j in pagedJobs" :key="j.id" :job="j" @open="openJob" />
        </div>
        <Pager
          :total="shownJobs.length"
          :page="safePage"
          :count="pageCount"
          :label="pageLabel"
          :buttons="pageButtons"
          @go="goPage"
        />
      </div>
    </div>
  </div>
</template>
<script setup>
import { computed, onMounted, ref, watch } from "vue";
import JobRow from "../components/JobRow.vue";
import PageHeader from "../components/PageHeader.vue";
import Pager from "../components/Pager.vue";
import { isAuditJob, isLiveJob } from "../lib/api.js";
import { jobsStore, loadJobs, upsertJob } from "../lib/jobs.js";
import { usePager } from "../lib/pager.js";
import { openReport } from "../lib/engine.js";

const title = ref("");
const runLlm = ref(true);
const sample = ref(null);
const busy = ref(false);
const errorText = ref("");
const jobFilter = ref("all");
const page = ref(1);
const jobs = computed(() => jobsStore.items);
const loading = computed(() => jobsStore.loading);
const refreshing = computed(() => jobsStore.refreshing);
const sampleName = computed(() => sample.value?.name || "");
const auditJobs = computed(() =>
  jobs.value
    .filter(isAuditJob)
    .slice()
    .sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || ""))),
);
const liveN = computed(() => auditJobs.value.filter(isLiveJob).length);
const doneN = computed(() => auditJobs.value.filter(j => j.status === "completed").length);
const failN = computed(() => auditJobs.value.filter(j => j.status === "failed" || j.status === "cancelled").length);
const shownJobs = computed(() => {
  const rows = auditJobs.value;
  if (jobFilter.value === "live") return rows.filter(isLiveJob);
  if (jobFilter.value === "done") return rows.filter(j => j.status === "completed");
  if (jobFilter.value === "fail") return rows.filter(j => j.status === "failed" || j.status === "cancelled");
  const live = rows.filter(isLiveJob);
  const rest = rows.filter(j => !isLiveJob(j));
  return [...live, ...rest];
});
const { pageCount, safePage, paged: pagedJobs, pageLabel, pageButtons } = usePager(shownJobs, page);
const jobHint = computed(() => {
  if (loading.value && !auditJobs.value.length) return "读取任务…";
  if (liveN.value) return `${liveN.value} 个正在跑，离开页面也不会丢`;
  if (auditJobs.value.length) return `${auditJobs.value.length} 个任务保存在服务端`;
  return "上传后会出现在这里";
});
const emptyTitle = computed(() => {
  if (!auditJobs.value.length) return "还没有内核审计任务";
  if (jobFilter.value === "live") return "当前没有进行中的审计";
  if (jobFilter.value === "fail") return "没有失败或已取消的审计";
  if (jobFilter.value === "done") return "还没有完成的审计";
  return "没有符合筛选的任务";
});
const emptyHint = computed(() => {
  if (!auditJobs.value.length) return "上传样本后会列在这里。任务写在服务端，换页、刷新都还在。";
  return "换一个筛选，或再上传一份样本。";
});

function setJobFilter(f) {
  jobFilter.value = jobFilter.value === f && f !== "all" ? "all" : f;
}
function goPage(n) {
  page.value = Math.min(pageCount.value, Math.max(1, n));
}
function openJob(id) {
  openReport(id);
}
async function refresh() {
  await loadJobs({ force: true });
}
function onFile(e) {
  sample.value = e.target.files?.[0] || null;
}

watch(jobFilter, () => { page.value = 1; });
watch(pageCount, n => {
  if (shownJobs.value.length && page.value > n) page.value = n;
});

onMounted(() => {
  loadJobs({ silent: !!jobs.value.length });
});

async function submit() {
  errorText.value = "";
  if (!sample.value) {
    errorText.value = "请先选择一个内核或驱动文件";
    return;
  }
  const fd = new FormData();
  fd.append("title", title.value);
  fd.append("run_llm", runLlm.value ? "true" : "false");
  fd.append("sample", sample.value);
  busy.value = true;
  try {
    const res = await fetch("/api/jobs/audit", { method: "POST", body: fd });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      errorText.value = data.detail || data.message || `HTTP ${res.status}`;
      return;
    }
    const jobId = data.job_id || "";
    if (jobId) {
      upsertJob({
        id: jobId,
        title: title.value || sampleName.value,
        status: "pending",
        kind: "kernel_audit",
        created_at: new Date().toISOString(),
        old_label: sampleName.value,
      });
      openReport(jobId);
    }
  } catch (e) {
    errorText.value = e.message || String(e);
  } finally {
    busy.value = false;
  }
}
</script>
<style scoped>
.pa-stat {
  cursor: pointer;
  font: inherit;
  text-align: left;
  width: 100%;
}
.pa-stat.on { background: #f8fbff; }
.empty-hero { padding: 1.6rem 1.4rem; }
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
</style>
