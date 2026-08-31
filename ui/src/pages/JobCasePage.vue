<template>
  <AuditCase v-if="isAudit" />
  <ReportDrawer v-else-if="ready" />
</template>
<script setup>
import { computed, nextTick, onMounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import AuditCase from "./AuditCase.vue";
import ReportDrawer from "../components/ReportDrawer.vue";
import { apiGet, isAuditJob } from "../lib/api.js";
import { peekJob } from "../lib/jobs.js";
import { loadEngine } from "../lib/engine.js";

const route = useRoute();
const kind = ref("");
const ready = ref(false);
const isAudit = computed(() => kind.value === "kernel_audit");

async function resolveKind() {
  const id = String(route.params.id || "");
  kind.value = "";
  ready.value = false;
  if (!id) return;
  const cached = peekJob(id);
  if (isAuditJob(cached)) {
    kind.value = "kernel_audit";
    return;
  }
  try {
    const job = await apiGet(`/jobs/${id}?lite=1`);
    kind.value = isAuditJob(job) ? "kernel_audit" : (job.kind || "patch_diff");
  } catch {
    kind.value = isAuditJob(cached) ? "kernel_audit" : (cached?.kind || "patch_diff");
  }
}

async function openPatchCase() {
  const id = String(route.params.id || "");
  if (!id) return;
  await nextTick();
  const m = await loadEngine();
  const tab = Array.isArray(route.query.tab) ? route.query.tab[0] : route.query.tab;
  await m.openJobModal(id, tab);
}

async function boot() {
  await resolveKind();
  if (isAudit.value) return;
  ready.value = true;
  await openPatchCase();
}

onMounted(boot);
watch(() => String(route.params.id || ""), (id, prev) => {
  if (id && prev && id !== prev) boot();
});
</script>
