<template>
  <div class="site-wrap blog-wide">
    <header class="blog-head">
      <p class="site-kicker">研究</p>
      <h2>文章</h2>
      <p>已发布的补丁分析报告。列表只展示标题与内容介绍，点进去阅读全文。</p>
    </header>
    <p v-if="loading" class="site-empty">正在读取…</p>
    <p v-else-if="!posts.length" class="site-empty">暂无已发布文章。</p>
    <div v-else class="blog-feed">
      <router-link v-for="p in posts" :key="p.id" class="blog-card" :to="`/blog/${p.slug}`">
        <div class="blog-card-meta">
          <span v-if="p.cve">{{ p.cve }}</span>
          <span v-if="p.published_at">{{ fmt(p.published_at) }}</span>
          <span v-if="p.author_name">{{ p.author_name }}</span>
        </div>
        <h3>{{ p.title }}</h3>
        <p class="blog-card-intro">{{ p.excerpt || "点击阅读全文。" }}</p>
        <span class="blog-card-more">阅读全文</span>
      </router-link>
    </div>
  </div>
</template>
<script setup>
import { onMounted, ref } from "vue";
import { apiGet, fmtDate } from "../lib/api.js";

const posts = ref([]);
const loading = ref(true);

function fmt(iso) {
  return iso ? fmtDate(iso) : "";
}

onMounted(async () => {
  try {
    const data = await apiGet("/public/blog?limit=50");
    posts.value = data.items || [];
  } catch {
    posts.value = [];
  } finally {
    loading.value = false;
  }
});
</script>
