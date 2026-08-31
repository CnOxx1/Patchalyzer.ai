<template>
  <article class="pa-row flat" @click="$emit('open', job.id)">
    <div class="pa-row-main">
      <strong>{{ job.title }}</strong>
      <div class="hint">{{ line }}</div>
      <div v-if="showBar" class="pa-progress"><i :style="{ width: pct + '%' }"></i></div>
    </div>
    <div class="pa-row-end">
      <span class="pa-st" :class="job.status">{{ statusLabel(job.status) }}</span>
      <div class="pa-pills" v-if="pills.length">
        <span v-for="p in pills" :key="p.t" class="pa-pill" :class="p.k">{{ p.t }}</span>
      </div>
    </div>
  </article>
</template>
<script setup>
import { computed } from "vue";
import { isAuditJob, isLiveJob, jobPills, jobVersionLine, relativeTime, statusLabel } from "../lib/api.js";
const props = defineProps({ job: { type: Object, required: true } });
defineEmits(["open"]);
const pills = computed(() => jobPills(props.job));
const live = computed(() => isLiveJob(props.job));
const showBar = computed(() => live.value && (props.job.progress?.percent != null || props.job.progress?.message));
const pct = computed(() => props.job.progress?.percent ?? 8);
const line = computed(() => {
  const j = props.job;
  if (live.value && j.progress?.message) return j.progress.message;
  const ver = jobVersionLine(j);
  const fallback = isAuditJob(j) ? "单文件审计" : "样本对照中";
  return `${ver || fallback} · ${relativeTime(j.created_at)}`;
});
</script>
