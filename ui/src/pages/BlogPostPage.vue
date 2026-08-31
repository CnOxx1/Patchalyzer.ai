<template>
  <div class="site-wrap blog-wide">
    <p v-if="error" class="site-empty">{{ error }}</p>
    <p v-else-if="loading" class="site-empty">正在读取报告…</p>
    <article v-else-if="post" class="blog-paper">
      <header class="blog-paper-head">
        <router-link class="blog-back" to="/blog">← 全部文章</router-link>
        <p v-if="post.cve" class="site-kicker">{{ post.cve }}</p>
        <h2>{{ post.title }}</h2>
        <p class="blog-meta">
          <span v-if="post.author_name">{{ post.author_name }}</span>
          <span v-if="post.published_at">{{ fmtDate(post.published_at) }}</span>
        </p>
        <p v-if="post.excerpt" class="blog-lede">{{ post.excerpt }}</p>
      </header>
      <div class="site-md report-md" v-html="html"></div>
    </article>
  </div>
</template>
<script setup>
import { onMounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { apiGet, fmtDate } from "../lib/api.js";
import { renderMarkdownHtml } from "../lib/markdown.js";

const route = useRoute();
const post = ref(null);
const html = ref("");
const loading = ref(true);
const error = ref("");

async function load() {
  loading.value = true;
  error.value = "";
  post.value = null;
  html.value = "";
  try {
    const data = await apiGet(`/public/blog/${encodeURIComponent(route.params.slug)}`);
    post.value = data;
    document.title = `${data.title} · Patchalyzer.ai`;
    html.value = await renderMarkdownHtml(data.body_md || "");
  } catch (e) {
    error.value = e.message || "文章不存在";
    document.title = "研究 · Patchalyzer.ai";
  } finally {
    loading.value = false;
  }
}

onMounted(load);
watch(() => route.params.slug, load);
</script>
