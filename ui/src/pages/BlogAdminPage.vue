<template>
  <div class="pa-page">
    <PageHeader title="发布管理" sub="把已完成任务的报告发到官网研究博客，或改标题、下架、删除。">
      <a class="pa-btn" href="/blog" target="_blank" rel="noopener">打开前台</a>
      <button class="pa-btn" type="button" :disabled="loading" @click="load">{{ loading ? "读取中…" : "刷新" }}</button>
    </PageHeader>
    <div class="pa-stack">
      <p v-if="notice" class="pa-banner" :class="{ bad: noticeBad }">{{ notice }}</p>
      <div class="pa-card pa-form">
        <h3 class="pa-card-title" style="padding:0 0 0.4rem">从任务发布</h3>
        <p class="muted" style="margin:0 0 0.7rem">填写已完成任务 ID，会写入官网 /blog。同一任务再次发布会覆盖原文。</p>
        <div class="user-grid">
          <label class="pa-field">
            <span>任务 ID</span>
            <input v-model="jobId" placeholder="例如 760a1cb3a78a" />
          </label>
          <label class="pa-field">
            <span>标题（可选）</span>
            <input v-model="jobTitle" placeholder="默认用任务标题" />
          </label>
        </div>
        <div class="pa-links">
          <button class="pa-btn primary" type="button" :disabled="saving" @click="publishJob">{{ saving ? "发布中…" : "发布到博客" }}</button>
        </div>
      </div>
      <div class="pa-card flush">
        <div v-if="loading && !items.length" class="empty">正在读取…</div>
        <div v-else-if="!items.length" class="empty">还没有文章。在任务页点「发布到博客」，或用上面的任务 ID。</div>
        <table v-else class="pa-table">
          <thead>
            <tr>
              <th>标题</th>
              <th class="fit-sm">状态</th>
              <th class="fit">CVE</th>
              <th class="fit-time">更新</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in items" :key="p.id">
              <td>
                <strong>{{ p.title }}</strong>
                <div class="muted">/blog/{{ p.slug }}</div>
              </td>
              <td class="fit-sm">
                <span class="pa-st" :class="p.status === 'published' ? 'completed' : 'pending'">{{ p.status === "published" ? "已发布" : "草稿" }}</span>
              </td>
              <td class="fit">{{ p.cve || "—" }}</td>
              <td class="fit-time muted">{{ relativeTime(p.updated_at || p.published_at) }}</td>
              <td class="user-act">
                <a v-if="p.status === 'published'" class="text-link" :href="`/blog/${p.slug}`" target="_blank" rel="noopener">查看</a>
                <button class="text-link" type="button" @click="toggle(p)">{{ p.status === "published" ? "下架" : "上架" }}</button>
                <button class="text-link" type="button" @click="remove(p)">删除</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
<script setup>
import { onMounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import { apiGet, apiSend, relativeTime } from "../lib/api.js";

const items = ref([]);
const loading = ref(false);
const saving = ref(false);
const notice = ref("");
const noticeBad = ref(false);
const jobId = ref("");
const jobTitle = ref("");

function flash(msg, bad = false) {
  notice.value = msg;
  noticeBad.value = bad;
}

async function load() {
  loading.value = true;
  try {
    const data = await apiGet("/blog?limit=80");
    items.value = data.items || [];
    flash("");
  } catch (e) {
    flash(e.message || "读取失败", true);
  } finally {
    loading.value = false;
  }
}

async function publishJob() {
  const id = jobId.value.trim();
  if (!id) {
    flash("请填写任务 ID", true);
    return;
  }
  saving.value = true;
  try {
    const body = { status: "published" };
    if (jobTitle.value.trim()) body.title = jobTitle.value.trim();
    const post = await apiSend(`/jobs/${id}/blog`, { json: body });
    flash(`已发布：/blog/${post.slug}`);
    jobId.value = "";
    jobTitle.value = "";
    await load();
  } catch (e) {
    flash(e.message || "发布失败", true);
  } finally {
    saving.value = false;
  }
}

async function toggle(p) {
  const next = p.status === "published" ? "draft" : "published";
  try {
    await apiSend(`/blog/${p.id}`, { method: "PATCH", json: { status: next } });
    await load();
  } catch (e) {
    flash(e.message || "更新失败", true);
  }
}

async function remove(p) {
  if (!confirm(`删除「${p.title}」？此前台将不再显示。`)) return;
  try {
    await apiSend(`/blog/${p.id}`, { method: "DELETE" });
    await load();
  } catch (e) {
    flash(e.message || "删除失败", true);
  }
}

onMounted(load);
</script>
<style scoped>
.muted { color: var(--muted); font-size: var(--text-sm); }
.user-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.7rem;
}
.user-act { display: flex; gap: 0.7rem; justify-content: flex-end; }
@media (max-width: 720px) {
  .user-grid { grid-template-columns: 1fr; }
}
</style>
