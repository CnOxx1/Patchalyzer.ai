<template>
  <div class="login-shell">
    <div class="login-panel">
      <aside class="login-hero">
        <div class="login-hero-brand">
          <span class="pa-mark login-mark" aria-hidden="true"></span>
          <div>
            <h1>Patchalyzer.ai</h1>
            <p>Windows 补丁对照分析</p>
          </div>
        </div>
        <ul class="login-points">
          <li>
            <span>01</span>
            <div>
              <strong>补丁日 CVE</strong>
              <p>浏览月度公告，标记已分析项</p>
            </div>
          </li>
          <li>
            <span>02</span>
            <div>
              <strong>驱动成对对照</strong>
              <p>从 Winbindex / 上传样本做 diff</p>
            </div>
          </li>
          <li>
            <span>03</span>
            <div>
              <strong>报告与狩猎</strong>
              <p>根因、IOC 与补丁完整性</p>
            </div>
          </li>
        </ul>
      </aside>
      <section class="login-main">
        <form class="login-form" @submit.prevent="submit">
          <header class="login-head">
            <h2>登录</h2>
            <p>使用分配的账号进入分析工作台。</p>
            <p class="login-site-link"><router-link to="/">返回官网</router-link> · <router-link to="/blog">研究博客</router-link></p>
          </header>
          <p v-if="error" class="login-error" role="alert">{{ error }}</p>
          <label class="login-field" :class="{ bad: fieldErr.username }">
            <span>用户名</span>
            <input
              ref="userEl"
              v-model="username"
              name="username"
              autocomplete="username"
              placeholder="请输入用户名"
              :disabled="busy"
              @keydown="clearField('username')"
            />
          </label>
          <label class="login-field" :class="{ bad: fieldErr.password }">
            <span>密码</span>
            <div class="login-pw">
              <input
                ref="pwEl"
                v-model="password"
                name="password"
                :type="showPw ? 'text' : 'password'"
                autocomplete="current-password"
                placeholder="请输入密码"
                :disabled="busy"
                @keydown="onPwKey"
              />
              <button class="login-eye" type="button" tabindex="-1" :aria-label="showPw ? '隐藏密码' : '显示密码'" @click="showPw = !showPw">
                {{ showPw ? "隐藏" : "显示" }}
              </button>
            </div>
            <small v-if="capsOn" class="login-hint">大写锁定已打开</small>
          </label>
          <button class="pa-btn primary login-btn" type="submit" :disabled="busy">
            <i v-if="busy" class="login-spin" aria-hidden="true"></i>
            {{ busy ? "正在登录…" : "进入工作台" }}
          </button>
        </form>
      </section>
    </div>
  </div>
</template>
<script setup>
import { nextTick, onMounted, reactive, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { login } from "../lib/auth.js";

const route = useRoute();
const router = useRouter();
const username = ref("");
const password = ref("");
const error = ref("");
const busy = ref(false);
const showPw = ref(false);
const capsOn = ref(false);
const fieldErr = reactive({ username: false, password: false });
const userEl = ref(null);
const pwEl = ref(null);

function clearField(name) {
  fieldErr[name] = false;
  if (error.value) error.value = "";
}

function onPwKey(e) {
  clearField("password");
  if (e.getModifierState) capsOn.value = e.getModifierState("CapsLock");
}

async function submit() {
  error.value = "";
  fieldErr.username = !username.value.trim();
  fieldErr.password = !password.value;
  if (fieldErr.username || fieldErr.password) {
    error.value = "请输入用户名和密码";
    return;
  }
  busy.value = true;
  try {
    await login(username.value, password.value);
    const next = String(route.query.next || "/");
    router.replace(next.startsWith("/") && next !== "/login" && next !== "/" ? next : "/app");
  } catch (e) {
    error.value = e.message || "登录失败";
    password.value = "";
    await nextTick();
    pwEl.value?.focus();
  } finally {
    busy.value = false;
  }
}

onMounted(() => userEl.value?.focus());
</script>
<style scoped>
.login-shell {
  min-height: 100%;
  display: grid;
  place-items: center;
  padding: 1.5rem;
  background:
    radial-gradient(900px 420px at 12% 0%, rgba(26, 115, 232, 0.16), transparent 58%),
    var(--bg);
}
.login-panel {
  width: min(52rem, 100%);
  min-height: 28rem;
  display: grid;
  grid-template-columns: 22rem minmax(0, 1fr);
  background: #fff;
  border: 1px solid var(--line);
  border-radius: 18px;
  box-shadow: 0 22px 60px rgba(22, 24, 29, 0.1);
  overflow: hidden;
}
.login-hero {
  background: var(--sidebar);
  color: var(--sidebar-ink);
  padding: 1.7rem 1.45rem 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 1.6rem;
}
.login-hero-brand {
  display: flex;
  align-items: center;
  gap: 0.8rem;
}
.login-mark { width: 40px; height: 40px; }
.login-hero-brand h1 {
  margin: 0;
  font-size: var(--text-xl);
  font-weight: 700;
  letter-spacing: 0.01em;
  color: #fff;
}
.login-hero-brand p {
  margin: 0.12rem 0 0;
  color: var(--sidebar-dim);
  font-size: var(--text-sm);
}
.login-points {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.login-points li {
  display: flex;
  gap: 0.75rem;
  align-items: flex-start;
}
.login-points span {
  font-family: var(--mono);
  font-size: var(--text-xs);
  color: #8ab4f8;
  padding-top: 0.18rem;
  width: 1.5rem;
  flex-shrink: 0;
}
.login-points strong {
  display: block;
  font-size: var(--text-md);
  font-weight: 600;
  color: #fff;
}
.login-points p {
  margin: 0.12rem 0 0;
  font-size: var(--text-sm);
  color: var(--sidebar-dim);
  line-height: 1.45;
}
.login-main {
  display: grid;
  place-items: center;
  padding: 2rem 2.1rem;
}
.login-form {
  width: min(22rem, 100%);
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
}
.login-head h2 {
  margin: 0;
  font-size: var(--text-2xl);
  font-weight: 600;
  letter-spacing: -0.02em;
}
.login-head p {
  margin: 0.35rem 0 0.4rem;
  color: var(--muted);
  font-size: var(--text-md);
}
.login-site-link {
  margin: 0 !important;
  font-size: var(--text-sm) !important;
}
.login-error {
  margin: 0;
  padding: 0.55rem 0.7rem;
  background: #fdecea;
  border: 1px solid #f5c6c2;
  border-radius: 8px;
  color: #8a1f1f;
  font-size: var(--text-sm);
}
.login-field {
  display: flex;
  flex-direction: column;
  gap: 0.32rem;
}
.login-field > span {
  font-size: var(--text-sm);
  font-weight: 600;
  color: var(--muted);
}
.login-field input {
  width: 100%;
  border: 1px solid var(--line-strong);
  background: #fff;
  padding: 0.62rem 0.75rem;
  border-radius: 8px;
  font-size: var(--text-lg);
}
.login-field input:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(26, 115, 232, 0.12);
}
.login-field.bad input {
  border-color: #e8a0a0;
  background: #fff8f7;
}
.login-pw { position: relative; }
.login-pw input { padding-right: 3.4rem; }
.login-eye {
  position: absolute;
  right: 0.35rem;
  top: 50%;
  transform: translateY(-50%);
  border: 0;
  background: none;
  color: var(--accent);
  font: inherit;
  font-size: var(--text-sm);
  font-weight: 500;
  padding: 0.25rem 0.4rem;
  cursor: pointer;
}
.login-eye:hover { text-decoration: underline; }
.login-hint {
  color: var(--warn);
  font-size: var(--text-xs);
}
.login-btn {
  width: 100%;
  margin-top: 0.35rem;
  height: 2.6rem;
  font-size: var(--text-lg);
}
.login-spin {
  width: 0.9rem;
  height: 0.9rem;
  border: 2px solid rgba(255, 255, 255, 0.35);
  border-top-color: #fff;
  border-radius: 50%;
  animation: login-spin 0.7s linear infinite;
}
@keyframes login-spin { to { transform: rotate(360deg); } }
@media (max-width: 820px) {
  .login-panel { grid-template-columns: 1fr; min-height: 0; }
  .login-hero { padding: 1.25rem 1.3rem 1.15rem; gap: 1rem; }
  .login-points { display: none; }
  .login-main { padding: 1.4rem 1.3rem 1.6rem; }
}
</style>
