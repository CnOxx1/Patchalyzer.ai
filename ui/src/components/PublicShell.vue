<template>
  <div class="site-shell">
    <header class="site-top">
      <router-link class="site-brand" to="/">
        <span class="pa-mark" aria-hidden="true"></span>
        <div>
          <h1>Patchalyzer.ai</h1>
          <p>Windows 补丁对照分析</p>
        </div>
      </router-link>
      <nav class="site-nav">
        <router-link to="/#product">产品</router-link>
        <router-link to="/#method">方法</router-link>
        <router-link to="/blog">研究</router-link>
        <router-link v-if="auth.user" class="site-btn primary" to="/app">进入工作台</router-link>
        <router-link v-else class="site-btn primary" to="/login">登录</router-link>
      </nav>
    </header>
    <div class="site-main">
      <router-view />
    </div>
    <footer class="site-foot">
      <div class="site-wrap foot-inner">
        <div>
          <strong>Patchalyzer.ai</strong>
          <p>Windows 补丁对照 · 检测运营</p>
        </div>
        <nav>
          <router-link to="/#product">产品</router-link>
          <router-link to="/#method">方法</router-link>
          <router-link to="/blog">研究</router-link>
          <router-link to="/login">登录</router-link>
        </nav>
        <span class="foot-note">报告不含 exploit / PoC</span>
      </div>
    </footer>
  </div>
</template>
<script setup>
import { onMounted } from "vue";
import { auth, ensureAuth } from "../lib/auth.js";
import "../styles/site.css";

onMounted(() => {
  ensureAuth();
});
</script>
