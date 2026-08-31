<template>
  <div class="pa-page">
    <PageHeader title="上传分析" sub="填 CVE 即可成对下载样本。本地驱动可选，不必先上传漏洞文件。">
      <router-link class="pa-btn" to="/audit">改走内核审计</router-link>
      <router-link class="pa-btn" to="/app">返回工作台</router-link>
    </PageHeader>
    <div class="pa-stack">
      <form class="pa-stack" @submit.prevent="submit">
        <div class="pa-card pa-form">
          <p class="pa-kicker">样本与编号</p>
          <label class="pa-drop" :class="{ has: oldName }">
            <small>漏洞样本（可选）</small>
            <span>{{ oldName || "选择 .sys / .dll / .exe，或留空由后端下载" }}</span>
            <input type="file" accept=".sys,.dll,.exe" @change="e => oldFile = e.target.files[0]" />
          </label>
          <label class="pa-field">
            <span>CVE 编号<span class="req">*</span></span>
            <input v-model="cve" required placeholder="CVE-2026-68820" />
          </label>
          <div class="pa-grid2">
            <label class="pa-field">
              <span>组件文件名</span>
              <input v-model="filename" placeholder="可空，如 afd.sys" />
            </label>
            <label class="pa-field">
              <span>任务名称</span>
              <input v-model="title" placeholder="可留空，默认用 CVE" />
            </label>
          </div>
          <details class="pa-adv">
            <summary>高级：手动指定修复版</summary>
            <p class="hint">若自动下载失败，可在此上传修复版 / 更早版本。</p>
            <div class="pa-links">
              <label class="pa-drop" :class="{ has: newName }">
                <small>修复版</small>
                <span>{{ newName || "选择文件" }}</span>
                <input type="file" accept=".sys,.dll,.exe" @change="e => newFile = e.target.files[0]" />
              </label>
              <label class="pa-drop" :class="{ has: midName }">
                <small>更早版本</small>
                <span>{{ midName || "可选" }}</span>
                <input type="file" accept=".sys,.dll,.exe" @change="e => midFile = e.target.files[0]" />
              </label>
            </div>
            <div class="pa-grid2" style="margin-top:0.55rem">
              <input v-model="oldLabel" placeholder="漏洞版标签" />
              <input v-model="newLabel" placeholder="修复版标签" />
              <input v-model="midLabel" placeholder="更早版本标签" />
            </div>
          </details>
          <details class="pa-adv">
            <summary>高级：专家编制</summary>
            <label class="pa-check">
              <input v-model="runLlm" type="checkbox" /> 启用 LLM Agent
            </label>
            <div v-show="runLlm">
              <div class="pa-presets" style="margin:0.7rem 0 0.55rem">
                <button type="button" class="pa-chip" :class="{ on: presetOn('all') }" @click="setPreset('all')">全选</button>
                <button type="button" class="pa-chip" :class="{ on: presetOn('core') }" @click="setPreset('core')">核心解读</button>
                <button type="button" class="pa-chip" :class="{ on: presetOn('soc') }" @click="setPreset('soc')">检测与报告</button>
                <button type="button" class="pa-chip" :class="{ on: presetOn('report') }" @click="setPreset('report')">只要报告</button>
                <button type="button" class="pa-chip" @click="setPreset('none')">全不选</button>
              </div>
              <div class="pa-agents">
                <label v-for="a in AGENTS" :key="a.id">
                  <input type="checkbox" :value="a.id" v-model="enabled" />
                  <span>{{ a.title }}<small>{{ a.hint }}</small></span>
                </label>
              </div>
              <div class="pa-radio-row" style="margin-top:0.75rem">
                <label><input type="radio" value="auto" v-model="routing" /> 自动编制</label>
                <label><input type="radio" value="manual" v-model="routing" /> 手动编制</label>
              </div>
              <p class="hint">默认自动编制：工具跑完后按证据裁剪专家。PE / PDB / 反汇编始终运行。</p>
            </div>
            <p v-show="!runLlm" class="hint">关闭后只跑确定性工具，不生成 LLM 报告。</p>
          </details>
          <p class="hint">不上传样本时，会从 MSRC KB + Winbindex 下载同分支「漏洞版 → 修复版」。点开始后进入任务看进度。若只有一个驱动文件、没有补丁对照，请用 <router-link to="/audit">内核审计</router-link>。</p>
          <p v-if="errorText" class="hint" style="color:var(--err)">{{ errorText }}</p>
          <button class="pa-btn primary pa-go" type="submit" :disabled="busy">{{ busy ? "正在排队…" : "开始分析" }}</button>
        </div>
      </form>
    </div>
  </div>
</template>
<script setup>
import { computed, onMounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import { AGENTS, AGENT_PRESETS } from "../lib/api.js";
import { openReport } from "../lib/engine.js";
import { upsertJob } from "../lib/jobs.js";

const AGENT_KEY = "patchalyzer.enabled_agents";
const ROUTE_KEY = "patchalyzer.routing_mode";

const cve = ref("");
const filename = ref("");
const title = ref("");
const runLlm = ref(true);
const enabled = ref([...AGENT_PRESETS.all]);
const routing = ref("auto");
const oldFile = ref(null);
const newFile = ref(null);
const midFile = ref(null);
const oldLabel = ref("");
const newLabel = ref("");
const midLabel = ref("");
const busy = ref(false);
const errorText = ref("");

const oldName = computed(() => oldFile.value?.name || "");
const newName = computed(() => newFile.value?.name || "");
const midName = computed(() => midFile.value?.name || "");

function setPreset(k) { enabled.value = [...(AGENT_PRESETS[k] || [])]; }
function presetOn(k) {
  const want = AGENT_PRESETS[k] || [];
  if (want.length !== enabled.value.length) return false;
  return want.every(id => enabled.value.includes(id));
}

onMounted(() => {
  try {
    const raw = JSON.parse(localStorage.getItem(AGENT_KEY) || "null");
    if (Array.isArray(raw)) enabled.value = raw;
    const r = localStorage.getItem(ROUTE_KEY);
    if (r === "manual" || r === "auto") routing.value = r;
  } catch { /* ignore */ }
});

async function submit() {
  errorText.value = "";
  try { localStorage.setItem(AGENT_KEY, JSON.stringify(enabled.value)); } catch { /* ignore */ }
  try { localStorage.setItem(ROUTE_KEY, routing.value); } catch { /* ignore */ }
  const fd = new FormData();
  fd.append("title", title.value);
  fd.append("cve", cve.value);
  if (filename.value) fd.append("filename", filename.value);
  fd.append("old_label", oldLabel.value);
  fd.append("new_label", newLabel.value);
  fd.append("mid_label", midLabel.value);
  fd.append("run_llm", runLlm.value ? "true" : "false");
  fd.append("agents_set", "1");
  fd.append("enabled_agents", runLlm.value ? enabled.value.join(",") : "");
  fd.append("routing_mode", routing.value);
  if (oldFile.value) fd.append("old_file", oldFile.value);
  if (newFile.value) fd.append("new_file", newFile.value);
  if (midFile.value) fd.append("mid_file", midFile.value);
  busy.value = true;
  try {
    const res = await fetch("/api/jobs", { method: "POST", body: fd });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      errorText.value = data.detail || data.message || `HTTP ${res.status}`;
      return;
    }
    const jobId = data.job_id || "";
    if (jobId) {
      upsertJob({
        id: jobId,
        title: title.value || cve.value,
        cve: cve.value,
        status: "pending",
        created_at: new Date().toISOString(),
        old_label: filename.value || oldLabel.value,
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
