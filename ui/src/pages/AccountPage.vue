<template>
  <div class="pa-page">
    <PageHeader title="我的账号" :sub="sub">
      <button class="pa-btn" type="button" @click="logoutAndLeave">退出登录</button>
    </PageHeader>
    <div class="pa-stack">
      <p v-if="notice" class="pa-banner" :class="{ bad: noticeBad }">{{ notice }}</p>
      <div class="pa-card pa-form">
        <h3 class="pa-card-title" style="padding:0 0 0.4rem">资料</h3>
        <div class="acct-grid">
          <label class="pa-field">
            <span>用户名</span>
            <input :value="auth.user?.username" disabled />
          </label>
          <label class="pa-field">
            <span>角色</span>
            <input :value="auth.user?.role === 'admin' ? '管理员' : '普通用户'" disabled />
          </label>
          <label class="pa-field full">
            <span>显示名</span>
            <input v-model="displayName" />
          </label>
        </div>
        <div class="pa-links">
          <button class="pa-btn primary" type="button" :disabled="saving" @click="saveProfile">保存显示名</button>
        </div>
      </div>
      <div class="pa-card pa-form">
        <h3 class="pa-card-title" style="padding:0 0 0.4rem">修改密码</h3>
        <div class="acct-grid">
          <label class="pa-field full">
            <span>当前密码</span>
            <input v-model="oldPw" type="password" autocomplete="current-password" />
          </label>
          <label class="pa-field">
            <span>新密码</span>
            <input v-model="newPw" type="password" autocomplete="new-password" />
          </label>
          <label class="pa-field">
            <span>再输入一次</span>
            <input v-model="newPw2" type="password" autocomplete="new-password" />
          </label>
        </div>
        <div class="pa-links">
          <button class="pa-btn primary" type="button" :disabled="saving" @click="savePassword">更新密码</button>
        </div>
      </div>
    </div>
  </div>
</template>
<script setup>
import { computed, ref } from "vue";
import { useRouter } from "vue-router";
import PageHeader from "../components/PageHeader.vue";
import { apiSend } from "../lib/api.js";
import { auth, logout } from "../lib/auth.js";

const router = useRouter();
const displayName = ref(auth.user?.display_name || "");
const oldPw = ref("");
const newPw = ref("");
const newPw2 = ref("");
const saving = ref(false);
const notice = ref("");
const noticeBad = ref(false);
const sub = computed(() => `${auth.user?.username || ""} · ${auth.user?.role === "admin" ? "管理员" : "普通用户"}`);

function flash(msg, bad = false) {
  notice.value = msg;
  noticeBad.value = bad;
}

async function saveProfile() {
  saving.value = true;
  try {
    const data = await apiSend(`/users/${auth.user.id}`, {
      method: "PUT",
      json: { display_name: displayName.value },
    });
    auth.user = { ...auth.user, ...data };
    flash("显示名已保存");
  } catch (e) {
    flash(e.message, true);
  } finally {
    saving.value = false;
  }
}

async function savePassword() {
  if (newPw.value !== newPw2.value) {
    flash("两次输入的新密码不一致", true);
    return;
  }
  saving.value = true;
  try {
    await apiSend(`/users/${auth.user.id}`, {
      method: "PUT",
      json: { old_password: oldPw.value, password: newPw.value },
    });
    oldPw.value = "";
    newPw.value = "";
    newPw2.value = "";
    flash("密码已更新");
  } catch (e) {
    flash(e.message, true);
  } finally {
    saving.value = false;
  }
}

async function logoutAndLeave() {
  await logout();
  router.replace("/login");
}
</script>
<style scoped>
.acct-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem 1rem;
}
.acct-grid .full { grid-column: 1 / -1; }
@media (max-width: 720px) {
  .acct-grid { grid-template-columns: 1fr; }
}
</style>
