<template>
  <div class="pa-page">
    <PageHeader title="用户管理" sub="管理员可以创建账号、停用和重置密码。不能删除或停用最后一个管理员。">
      <button class="pa-btn" type="button" :disabled="loading" @click="load">{{ loading ? "读取中…" : "刷新" }}</button>
    </PageHeader>
    <div class="pa-stack">
      <p v-if="notice" class="pa-banner" :class="{ bad: noticeBad }">{{ notice }}</p>
      <div class="pa-card pa-form">
        <h3 class="pa-card-title" style="padding:0 0 0.4rem">新建用户</h3>
        <div class="user-grid">
          <label class="pa-field">
            <span>用户名</span>
            <input v-model="form.username" placeholder="字母开头，3–32 位" autocomplete="off" />
          </label>
          <label class="pa-field">
            <span>显示名</span>
            <input v-model="form.display_name" placeholder="可选" />
          </label>
          <label class="pa-field">
            <span>密码</span>
            <input v-model="form.password" type="password" placeholder="至少 8 位" autocomplete="new-password" />
          </label>
          <label class="pa-field">
            <span>角色</span>
            <select v-model="form.role">
              <option value="user">普通用户</option>
              <option value="admin">管理员</option>
            </select>
          </label>
        </div>
        <div class="pa-links">
          <button class="pa-btn primary" type="button" :disabled="saving" @click="create">{{ saving ? "创建中…" : "创建账号" }}</button>
        </div>
      </div>
      <div class="pa-card flush">
        <div v-if="loading && !users.length" class="empty">正在读取用户…</div>
        <div v-else-if="!users.length" class="empty">还没有用户。</div>
        <table v-else class="pa-table">
          <thead>
            <tr>
              <th class="fit">用户名</th>
              <th class="fit">显示名</th>
              <th class="fit-sm">角色</th>
              <th class="fit-sm">状态</th>
              <th class="fit-time">创建</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in users" :key="u.id">
              <td class="fit"><strong>{{ u.username }}</strong></td>
              <td class="fit">{{ u.display_name }}</td>
              <td class="fit-sm">{{ u.role === "admin" ? "管理员" : "用户" }}</td>
              <td class="fit-sm">
                <span class="pa-st" :class="u.disabled ? 'cancelled' : 'completed'">{{ u.disabled ? "已停用" : "正常" }}</span>
              </td>
              <td class="fit-time muted">{{ relativeTime(u.created_at) }}</td>
              <td class="user-act">
                <button v-if="u.id !== meId" class="text-link" type="button" @click="startReset(u)">重置密码</button>
                <button v-if="u.id !== meId" class="text-link" type="button" @click="toggleDisabled(u)">{{ u.disabled ? "启用" : "停用" }}</button>
                <button v-if="u.id !== meId" class="text-link" type="button" @click="remove(u)">删除</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="resetUser" class="pa-card pa-form">
        <h3 class="pa-card-title" style="padding:0 0 0.4rem">重置密码 · {{ resetUser.username }}</h3>
        <div class="user-grid">
          <label class="pa-field">
            <span>新密码</span>
            <input v-model="resetPw" type="password" autocomplete="new-password" />
          </label>
          <label class="pa-field">
            <span>再输入一次</span>
            <input v-model="resetPw2" type="password" autocomplete="new-password" />
          </label>
        </div>
        <div class="pa-links">
          <button class="pa-btn primary" type="button" :disabled="saving" @click="confirmReset">保存新密码</button>
          <button class="pa-btn" type="button" @click="resetUser = null">取消</button>
        </div>
      </div>
    </div>
  </div>
</template>
<script setup>
import { onMounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import { apiGet, apiSend, relativeTime } from "../lib/api.js";
import { auth } from "../lib/auth.js";

const users = ref([]);
const loading = ref(false);
const saving = ref(false);
const notice = ref("");
const noticeBad = ref(false);
const form = ref({ username: "", display_name: "", password: "", role: "user" });
const resetUser = ref(null);
const resetPw = ref("");
const resetPw2 = ref("");
const meId = auth.user?.id;

function flash(msg, bad = false) {
  notice.value = msg;
  noticeBad.value = bad;
}

async function load() {
  loading.value = true;
  try {
    users.value = await apiGet("/users");
    flash("");
  } catch (e) {
    flash(e.message, true);
  } finally {
    loading.value = false;
  }
}

async function create() {
  saving.value = true;
  try {
    await apiSend("/users", {
      json: {
        username: form.value.username,
        display_name: form.value.display_name,
        password: form.value.password,
        role: form.value.role,
      },
    });
    form.value = { username: "", display_name: "", password: "", role: "user" };
    flash("已创建账号");
    await load();
  } catch (e) {
    flash(e.message, true);
  } finally {
    saving.value = false;
  }
}

function startReset(u) {
  resetUser.value = u;
  resetPw.value = "";
  resetPw2.value = "";
}

async function confirmReset() {
  if (resetPw.value !== resetPw2.value) {
    flash("两次输入的密码不一致", true);
    return;
  }
  saving.value = true;
  try {
    await apiSend(`/users/${resetUser.value.id}`, { method: "PUT", json: { password: resetPw.value } });
    flash(`已重置 ${resetUser.value.username} 的密码，其现有登录会失效`);
    resetUser.value = null;
  } catch (e) {
    flash(e.message, true);
  } finally {
    saving.value = false;
  }
}

async function toggleDisabled(u) {
  const next = !u.disabled;
  const verb = next ? "停用" : "启用";
  if (!window.confirm(`确定${verb} ${u.username}？`)) return;
  try {
    await apiSend(`/users/${u.id}`, { method: "PUT", json: { disabled: next } });
    flash(`已${verb} ${u.username}`);
    await load();
  } catch (e) {
    flash(e.message, true);
  }
}

async function remove(u) {
  if (!window.confirm(`确定删除 ${u.username}？此操作不可恢复。`)) return;
  try {
    await apiSend(`/users/${u.id}`, { method: "DELETE" });
    flash(`已删除 ${u.username}`);
    if (resetUser.value?.id === u.id) resetUser.value = null;
    await load();
  } catch (e) {
    flash(e.message, true);
  }
}

onMounted(load);
</script>
<style scoped>
.user-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
  gap: 0.75rem 1rem;
}
.user-act {
  display: flex;
  flex-wrap: wrap;
  gap: 0.65rem 0.9rem;
  justify-content: flex-end;
}
</style>
