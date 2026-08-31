<template>
  <div id="job-modal" class="drawer">
    <div class="drawer-inner vt-report">
      <header class="report-hero">
        <div class="report-hero-top">
          <button id="modal-close" class="pa-btn" type="button">← 返回</button>
          <div class="report-actions">
            <button id="regen-report" class="pa-btn primary" type="button">重新生成报告</button>
            <button class="pa-btn" type="button" :disabled="pubBusy" @click="publish">
              {{ postSlug ? "更新博客" : "发布到博客" }}
            </button>
            <a v-if="postSlug" class="pa-btn" :href="`/blog/${postSlug}`" target="_blank" rel="noopener">查看博客</a>
            <span v-if="pubHint" class="pub-hint">{{ pubHint }}</span>
            <div class="export-wrap">
              <button type="button" id="export-report" class="pa-btn">导出 ▾</button>
              <div id="export-menu" class="export-menu hidden">
                <div class="export-picker-head">
                  <span>导出哪些章节</span>
                  <div class="export-presets">
                    <button type="button" data-export-preset="all">全选</button>
                    <button type="button" data-export-preset="core">核心解读</button>
                    <button type="button" data-export-preset="soc">检测运营</button>
                    <button type="button" data-export-preset="none">全不选</button>
                  </div>
                </div>
                <div id="export-sections" class="export-sections"></div>
                <p class="export-picker-hint">默认导出运营关心的章节。未勾选的不会写入 PDF / HTML / Markdown。</p>
                <div class="export-formats">
                  <button type="button" data-export="pdf">PDF（含公式）</button>
                  <button type="button" data-export="html">HTML（含公式）</button>
                  <button type="button" data-export="md">Markdown</button>
                </div>
                <div class="export-extras">
                  <a id="download-ioc" target="_blank">IOC JSON</a>
                  <a id="download-threat" target="_blank">威胁情报 JSON</a>
                  <a id="download-bypass" target="_blank">绕过面 JSON</a>
                  <a id="download-residual" target="_blank">残留漏洞 JSON</a>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class="report-hero-main">
          <div class="detect-ring" id="detect-ring" aria-hidden="true">
            <svg viewBox="0 0 96 96" width="72" height="72">
              <circle class="ring-bg" cx="48" cy="48" r="40"/>
              <circle class="ring-fg" id="ring-fg" cx="48" cy="48" r="40"/>
            </svg>
            <div class="ring-label">
              <strong id="ring-value">—</strong>
              <span id="ring-sub">状态</span>
            </div>
          </div>
          <div class="report-meta">
            <p class="pa-kicker">任务结论</p>
            <h2 id="modal-title"></h2>
            <p class="report-sub" id="modal-sub"></p>
            <div class="hash-row">
              <span class="hash-label">任务</span>
              <code id="modal-job-id"></code>
              <button type="button" class="copy-btn" id="copy-job-id" title="复制任务链接">复制链接</button>
            </div>
            <div class="tag-row" id="modal-tags"></div>
          </div>
        </div>
      </header>
      <div class="modal-tabs-wrap">
        <div class="tab-tier tab-tier-primary">
          <div class="modal-tabs vt-tabs">
            <button
              v-for="g in PRIMARY_GROUPS"
              :key="g.id"
              type="button"
              class="modal-group"
              :data-group="g.id"
              :class="{ active: group === g.id }"
              @click="setGroup(g.id)"
            >{{ g.label }}</button>
          </div>
        </div>
        <div v-if="subTabs.length" class="tab-tier tab-tier-sub" :data-group-panel="group">
          <div class="modal-tabs vt-tabs">
            <button
              v-for="t in subTabs"
              :key="t.id"
              type="button"
              class="modal-tab"
              :data-panel="t.id"
              :class="{ active: panel === t.id }"
              @click="setTab(t.id)"
            >{{ t.label }}</button>
          </div>
        </div>
      </div>
      <div class="drawer-body">
        <div id="panel-community" class="modal-panel graph-panel" :class="{ active: panel === 'community' }"></div>
        <div id="panel-summary" class="modal-panel" :class="{ active: panel === 'summary' }"></div>
        <div id="panel-chain" class="modal-panel" :class="{ active: panel === 'chain' }"></div>
        <div id="panel-fullreport" class="modal-panel" :class="{ active: panel === 'fullreport' }"></div>
        <div id="panel-ioc" class="modal-panel" :class="{ active: panel === 'ioc' }"></div>
        <div id="panel-threat" class="modal-panel" :class="{ active: panel === 'threat' }"></div>
        <div id="panel-bypass" class="modal-panel" :class="{ active: panel === 'bypass' }"></div>
        <div id="panel-residual" class="modal-panel" :class="{ active: panel === 'residual' }"></div>
        <div id="panel-huntlab" class="modal-panel" :class="{ active: panel === 'huntlab' }"></div>
        <div id="panel-control" class="modal-panel" :class="{ active: panel === 'control' }"></div>
        <div id="panel-timeline" class="modal-panel" :class="{ active: panel === 'timeline' }"></div>
        <div id="panel-bytediff" class="modal-panel" :class="{ active: panel === 'bytediff' }"></div>
        <div id="panel-symbols" class="modal-panel" :class="{ active: panel === 'symbols' }"></div>
        <div id="panel-disasm" class="modal-panel" :class="{ active: panel === 'disasm' }"></div>
        <div id="panel-cfg" class="modal-panel" :class="{ active: panel === 'cfg' }"></div>
        <div id="panel-feature" class="modal-panel" :class="{ active: panel === 'feature' }"></div>
        <div id="panel-verify" class="modal-panel" :class="{ active: panel === 'verify' }"></div>
      </div>
    </div>
  </div>
</template>
<script setup>
import { computed, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { GROUP_DEFAULT, PRIMARY_GROUPS, SUB_TABS, panelGroup } from "../lib/caseTabs.js";
import { apiGet, apiSend } from "../lib/api.js";

const route = useRoute();
const router = useRouter();
const panel = computed(() => String(route.query.tab || "summary"));
const group = computed(() => panelGroup(panel.value));
const subTabs = computed(() => SUB_TABS[group.value] || []);
const pubBusy = ref(false);
const postSlug = ref("");
const pubHint = ref("");

async function loadBlog() {
  const id = String(route.params.id || "");
  postSlug.value = "";
  if (!id) return;
  try {
    const data = await apiGet(`/jobs/${id}/blog`);
    postSlug.value = data.post?.slug || "";
  } catch {
    postSlug.value = "";
  }
}

async function publish() {
  const id = String(route.params.id || "");
  if (!id || pubBusy.value) return;
  pubBusy.value = true;
  pubHint.value = "";
  try {
    const post = await apiSend(`/jobs/${id}/blog`, { json: { status: "published" } });
    postSlug.value = post.slug || "";
    pubHint.value = post.slug ? `已发布到 /blog/${post.slug}` : "已发布";
  } catch (e) {
    pubHint.value = e.message || "发布失败";
  } finally {
    pubBusy.value = false;
  }
}

watch(() => String(route.params.id || ""), loadBlog, { immediate: true });

function setTab(name) {
  const q = { ...route.query };
  if (!name || name === "summary") delete q.tab;
  else q.tab = name;
  router.replace({ name: "job", params: { id: String(route.params.id) }, query: q });
}
function setGroup(g) {
  if (group.value === g) return;
  setTab(GROUP_DEFAULT[g] || "summary");
}
</script>
<style scoped>
.pub-hint {
  align-self: center;
  font-size: var(--text-sm);
  color: var(--muted);
  max-width: 16rem;
}
</style>
