<template>
  <div class="pa-page audit-case">
    <PageHeader :title="job?.title || '内核审计'" :sub="subLine">
      <router-link class="pa-btn" to="/audit">任务列表</router-link>
      <router-link class="pa-btn" to="/audit">再审计一份</router-link>
      <button class="pa-btn" type="button" :disabled="busy" @click="reload">刷新</button>
    </PageHeader>
    <div class="pa-stack">
      <p v-if="errorText" class="pa-banner bad">{{ errorText }}</p>
      <div v-if="live" class="pa-card">
        <p class="pa-kicker">进度</p>
        <p>{{ progress.message || "排队中…" }}</p>
        <div class="pa-progress"><i :style="{ width: (progress.percent || 8) + '%' }"></i></div>
      </div>
      <div v-if="job?.status === 'failed' || canResumeAudit" class="pa-card">
        <p class="pa-kicker">{{ job?.status === 'failed' ? '失败' : '未跟完' }}</p>
        <p>{{ job.error || audit.error || "部分入口未跟完（额度不足或模型失败）。可从断点继续，已完成的入口会跳过。" }}</p>
        <button class="pa-btn primary" type="button" :disabled="busy" @click="resume">从断点继续</button>
      </div>
      <div class="pa-card">
        <p class="pa-kicker">结论</p>
        <p>
          <span class="pa-st" :class="statusClass">{{ verdictLabel }}</span>
          <span class="hint" style="margin-left:0.6rem">{{ peLine }}</span>
        </p>
        <p class="hint">静态启发式，不是已确认漏洞。high / suspect 需在隔离 VM 里人工核对。</p>
      </div>
      <div class="pa-card flush">
        <h3 class="pa-card-title">用户入口</h3>
        <ul class="audit-list">
          <li>DeviceControl：<code>{{ dispatch.handler || "—" }}</code> 槽 {{ dispatch.limit ?? "—" }} · IOCTL {{ ioctlN }}</li>
          <li>Immediate：<code>{{ immediate.symbol || "—" }}</code> 已填 {{ immediate.filled ?? "—" }}</li>
          <li>FastIo 调用：{{ fastN }}</li>
          <li v-if="majorBits.length">MajorFunction：{{ majorBits.join(" · ") }}</li>
          <li v-else>MajorFunction：未从符号解析到 Create/Close 等入口</li>
        </ul>
      </div>
      <div class="pa-card flush">
        <h3 class="pa-card-title">入口 Agent</h3>
        <p v-if="!huntApis.length && !agents.length" class="empty">尚无用户入口拆分。表面图完成后会按 API 各跟一条链。</p>
        <p v-else class="hint">从 IOCTL / Immediate / FastIo 拆出 {{ huntApis.length || agents.length }} 条入口，每条一个 agent 跟链直到排除或证据断开。</p>
        <table v-if="agents.length" class="audit-table">
          <thead>
            <tr><th>入口</th><th>处理函数</th><th>结论</th><th>跟到</th><th>卡住</th></tr>
          </thead>
          <tbody>
            <tr v-for="a in agents" :key="a.id || a.handler">
              <td>{{ a.title || a.kind }}</td>
              <td><code>{{ a.handler }}</code></td>
              <td><span class="pa-st" :class="agentClass(a.verdict)">{{ agentLabel(a.verdict) }}</span></td>
              <td>{{ (a.followed || []).length }}</td>
              <td>{{ (a.blocked || []).length }}{{ a.error ? " · 失败" : "" }}</td>
            </tr>
          </tbody>
        </table>
        <ul v-else-if="huntApis.length" class="audit-list">
          <li v-for="a in huntApis" :key="a.id || a.handler">
            {{ a.title || a.kind }} → <code>{{ a.handler }}</code>
          </li>
        </ul>
      </div>
      <div class="pa-card flush">
        <h3 class="pa-card-title">缺陷类嫌疑</h3>
        <p v-if="!findings.length" class="empty">尚无 suspect。并不代表没有漏洞。</p>
        <table v-else class="audit-table">
          <thead>
            <tr><th>函数</th><th>类型</th><th>级别</th><th>状态</th><th>证据</th></tr>
          </thead>
          <tbody>
            <tr v-for="(f, i) in findings" :key="i">
              <td><code>{{ f.function }}</code></td>
              <td>{{ f.pattern }}</td>
              <td><span class="pa-pill" :class="sevClass(f.severity)">{{ f.severity }}</span></td>
              <td>{{ f.status }}</td>
              <td>{{ f.evidence }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="pa-card flush">
        <h3 class="pa-card-title">处理函数打分</h3>
        <p v-if="!scores.length" class="empty">表面图尚未给出处理函数。</p>
        <table v-else class="audit-table">
          <thead>
            <tr><th>函数</th><th>风险</th><th>方法</th><th>大小</th><th>原因</th></tr>
          </thead>
          <tbody>
            <tr v-for="r in scores.slice(0, 24)" :key="r.name">
              <td><code>{{ r.name }}</code></td>
              <td><span class="pa-pill" :class="riskClass(r.risk)">{{ r.risk }}</span></td>
              <td>{{ r.method || "—" }}</td>
              <td>{{ r.size || "—" }}</td>
              <td>{{ (r.why || []).join("; ") }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="pa-card flush">
        <h3 class="pa-card-title">隔离 VM 观察清单</h3>
        <ul v-if="obs.length" class="audit-list">
          <li v-for="(o, i) in obs" :key="i">
            <code>{{ o.function }}</code>
            <span v-if="o.bp"> {{ o.bp }}</span>
            — {{ o.watch }}（{{ o.why }}）
          </li>
        </ul>
        <p v-else class="empty">无观察点。</p>
      </div>
      <div class="pa-card">
        <div class="pa-card-head">
          <h3>报告</h3>
          <a v-if="job?.id && report" class="pa-btn" :href="`/api/jobs/${job.id}/audit.md`">下载 Markdown</a>
        </div>
        <div v-if="reportHtml" class="site-md report-md" v-html="reportHtml"></div>
        <p v-else class="empty">{{ live ? "报告将在审计结束后生成。" : "尚无报告。" }}</p>
      </div>
    </div>
  </div>
</template>
<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import PageHeader from "../components/PageHeader.vue";
import { apiGet, apiSend, isLiveJob, statusLabel } from "../lib/api.js";
import { onJobsLive, peekJob } from "../lib/jobs.js";
import { renderMarkdownHtml } from "../lib/markdown.js";

const route = useRoute();
const job = ref(null);
const errorText = ref("");
const busy = ref(false);
const reportHtml = ref("");
let stopLive = null;

const audit = computed(() => ((job.value?.result || {}).artifacts || {}).kernel_audit || {});
const art = computed(() => ((job.value?.result || {}).artifacts || {}));
const live = computed(() => isLiveJob(job.value));
const progress = computed(() => job.value?.progress || {});
const findings = computed(() => (audit.value.findings || []).filter(f => f.status === "suspect" || f.status === "similar"));
const agents = computed(() => audit.value.agents || (audit.value.llm_review || {}).agents || []);
const huntApis = computed(() => audit.value.hunt_apis || []);
const scores = computed(() => audit.value.scores || art.value.handler_scores || []);
const obs = computed(() => audit.value.observations || art.value.observations || []);
const surface = computed(() => audit.value.surface || art.value.surface_map || {});
const dispatch = computed(() => surface.value.dispatch || {});
const immediate = computed(() => surface.value.immediate || {});
const ioctlN = computed(() => (dispatch.value.ioctl || []).length);
const fastN = computed(() => ((surface.value.fastio || {}).callees || []).length);
const majorBits = computed(() => {
  const mj = surface.value.major_functions || {};
  return Object.entries(mj).map(([k, v]) => `${k}=${(v || {}).handler || ""}`);
});
const pe = computed(() => art.value.new_pe || art.value.old_pe || {});
const peLine = computed(() => {
  const p = pe.value;
  const bits = [p.original_filename, p.file_version, p.machine].filter(Boolean);
  return bits.join(" · ") || "样本信息稍后可见";
});
const verdictLabel = computed(() => {
  if (live.value) return statusLabel(job.value?.status);
  const v = audit.value.verdict || "none";
  return ({ likely: "高优先级嫌疑", suspects: "有同类嫌疑", none: "未给出嫌疑", unknown: "证据不足" })[v] || v;
});
const statusClass = computed(() => {
  if (live.value) return job.value?.status || "";
  const v = audit.value.verdict || "none";
  if (v === "likely") return "failed";
  if (v === "suspects") return "pending";
  if (v === "none") return "completed";
  return "";
});
const subLine = computed(() => {
  if (live.value && progress.value.message) return progress.value.message;
  return "单文件内核审计 · 不生成 exploit";
});
const report = computed(() => audit.value.report || art.value.llm_report || "");
const canResumeAudit = computed(() => {
  if (job.value?.status === "failed" || job.value?.status === "cancelled") return true;
  if (job.value?.status !== "completed") return false;
  const rows = agents.value || [];
  return !!(audit.value.error || art.value.llm_error || rows.some(a => a && a.error));
});

function sevClass(s) {
  if (s === "high") return "err";
  if (s === "medium") return "warn";
  return "ok";
}
function riskClass(s) {
  if (s === "high") return "err";
  if (s === "medium") return "warn";
  if (s === "hardened" || s === "buffered") return "ok";
  return "";
}
function agentLabel(v) {
  return ({ likely: "高优先级嫌疑", suspects: "有同类嫌疑", none: "已跟完未见提权面", unknown: "证据不足" })[v] || v || "—";
}
function agentClass(v) {
  if (v === "likely") return "failed";
  if (v === "suspects") return "pending";
  if (v === "none") return "completed";
  return "";
}

async function reload() {
  const id = String(route.params.id || "");
  if (!id) return;
  errorText.value = "";
  try {
    const cached = peekJob(id);
    if (cached && !job.value) job.value = cached;
    job.value = await apiGet(`/jobs/${id}`);
  } catch (e) {
    errorText.value = e.message || String(e);
  }
}

async function resume() {
  const id = String(route.params.id || "");
  if (!id) return;
  busy.value = true;
  try {
    await apiSend(`/jobs/${id}/resume`, { method: "POST", json: {} });
    await reload();
  } catch (e) {
    errorText.value = e.message || String(e);
  } finally {
    busy.value = false;
  }
}

watch(report, async (md) => {
  reportHtml.value = md ? await renderMarkdownHtml(md) : "";
});

onMounted(async () => {
  await reload();
  stopLive = onJobsLive((live, finished) => {
    const id = String(route.params.id || "");
    if (!id) return;
    if ((finished || []).some(f => f.id === id) || (live || []).some(j => j.id === id) || isLiveJob(job.value)) {
      reload();
    }
  });
});
onUnmounted(() => {
  if (stopLive) stopLive();
});
</script>
