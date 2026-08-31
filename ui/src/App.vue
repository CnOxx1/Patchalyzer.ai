<template>
  <router-view v-if="isPublic" />
  <div v-else class="pa-shell" :class="{ 'has-report': isCase }">
    <aside class="pa-side">
      <div class="pa-brand">
        <span class="pa-mark" aria-hidden="true"></span>
        <div>
          <h1>Patchalyzer.ai</h1>
          <p>补丁对照 · 检测运营</p>
        </div>
      </div>
      <nav class="pa-nav">
        <router-link to="/app" active-class="" exact-active-class="router-link-active" @click="onNav">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 11.5 12 4l8 7.5V20a1 1 0 0 1-1 1h-5v-6H10v6H5a1 1 0 0 1-1-1z"/></svg>
          <span>工作台</span>
        </router-link>
        <router-link to="/patch" @click="onNav">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="5" width="16" height="15" rx="2"/><path d="M8 3v4M16 3v4M4 10h16"/></svg>
          <span>本月补丁</span>
        </router-link>
        <router-link to="/analyze" @click="onNav">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 4v16M4 12h16"/></svg>
          <span>上传分析</span>
        </router-link>
        <router-link to="/audit" @click="onNav">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3-3"/></svg>
          <span>内核审计</span>
        </router-link>
        <router-link to="/jobs" @click="onNav">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 7h12M8 12h12M8 17h8"/><circle cx="4.5" cy="7" r="1.2" fill="currentColor" stroke="none"/><circle cx="4.5" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="4.5" cy="17" r="1.2" fill="currentColor" stroke="none"/></svg>
          <span>任务</span>
          <i v-if="ui.liveCount" class="pa-dot"></i>
        </router-link>
        <router-link to="/publish" @click="onNav">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5V6a2 2 0 0 1 2-2h9l5 5v10.5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/><path d="M14 4v5h5M8 13h8M8 17h6"/></svg>
          <span>发布</span>
        </router-link>
        <router-link v-if="admin" to="/users" @click="onNav">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>
          <span>用户管理</span>
        </router-link>
        <router-link to="/settings" @click="onNav">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>
          <span>设置</span>
        </router-link>
      </nav>
      <div v-if="auth.user" class="pa-account">
        <router-link class="pa-account-who" to="/account" @click="onNav">
          <strong>{{ auth.user.display_name || auth.user.username }}</strong>
          <span>{{ auth.user.role === "admin" ? "管理员" : "普通用户" }}</span>
        </router-link>
        <router-link class="pa-account-out" to="/">官网</router-link>
        <button class="pa-account-out" type="button" @click="signOut">退出</button>
      </div>
    </aside>
    <div class="pa-main">
      <main class="pa-body" :class="{ 'case-body': isCase }">
        <router-view />
      </main>
    </div>
  </div>
</template>
<script setup>
import { computed, onMounted, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { auth, isAdmin, logout } from "./lib/auth.js";
import { peekJob, startJobsPoller, stopJobsPoller } from "./lib/jobs.js";
import { isAuditJob } from "./lib/api.js";
import { ui } from "./lib/store.js";
import { closeReport, loadEngine } from "./lib/engine.js";

const route = useRoute();
const router = useRouter();
const isPublic = computed(() => route.matched.some(r => r.meta.public));
const isCase = computed(() => route.name === "job");
const admin = computed(() => isAdmin());

function onNav() {
  if (ui.reportOpen) closeReport();
}

async function signOut() {
  if (ui.reportOpen) closeReport();
  await logout();
  router.replace("/");
}

watch(
  () => ({ name: route.name, id: route.params.id, tab: route.query.tab }),
  async (cur, prev) => {
    if (cur.name === "job" && cur.id && prev?.name === "job" && String(prev.id) === String(cur.id)) {
      const m = await loadEngine();
      const tab = Array.isArray(cur.tab) ? cur.tab[0] : cur.tab;
      await m.activatePanel?.(tab || "summary");
      return;
    }
    if (prev?.name === "job" && cur.name !== "job") {
      const m = await loadEngine();
      m.closeJobModal?.();
    }
  },
);

onMounted(() => {
  window.__paOpenSettings = () => router.push("/settings");
  window.__paCloseSettings = () => {};
  window.__paGotoJobs = () => router.push("/jobs");
  window.__paCloseCase = () => {
    if (window.history.state && window.history.state.back != null) {
      router.back();
      return;
    }
    const id = String(route.params.id || "");
    const job = id ? peekJob(id) : null;
    router.push(isAuditJob(job) ? "/audit" : "/jobs");
  };
  window.__paOpenJob = (id, panel) => {
    const loc = { name: "job", params: { id: String(id) } };
    if (panel) loc.query = { tab: String(panel) };
    const cur = router.currentRoute.value;
    if (cur.name === "job" && cur.params.id === String(id) && String(cur.query.tab || "") === String(panel || "")) {
      loadEngine().then(m => m.openJobModal(String(id), panel));
      return;
    }
    router.push(loc);
  };
  window.__paSetCaseTab = panel => {
    const cur = router.currentRoute.value;
    if (cur.name !== "job") return;
    const next = !panel || panel === "summary" ? "" : String(panel);
    if (String(cur.query.tab || "") === next) return;
    const q = { ...cur.query };
    if (next) q.tab = next;
    else delete q.tab;
    router.replace({ name: "job", params: cur.params, query: q });
  };
  const idle = window.requestIdleCallback || (fn => setTimeout(fn, 400));
  idle(() => loadEngine());
});

watch(
  () => auth.user,
  u => {
    if (u) startJobsPoller();
    else stopJobsPoller();
  },
  { immediate: true },
);
</script>
