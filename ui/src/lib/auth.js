import { reactive } from "vue";
import { apiGet, apiSend } from "./api.js";

export const auth = reactive({
  ready: false,
  user: null,
});

export function isAdmin() {
  return auth.user?.role === "admin";
}

export async function ensureAuth() {
  if (auth.ready) return !!auth.user;
  try {
    const data = await apiGet("/auth/me");
    auth.user = data.user || null;
  } catch {
    auth.user = null;
  } finally {
    auth.ready = true;
  }
  return !!auth.user;
}

export async function login(username, password) {
  const data = await apiSend("/auth/login", { json: { username, password } });
  auth.user = data.user || null;
  auth.ready = true;
  return auth.user;
}

export async function logout() {
  try {
    await apiSend("/auth/logout");
  } catch {
    /* already expired */
  }
  auth.user = null;
}
