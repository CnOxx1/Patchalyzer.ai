import { createRouter, createWebHistory } from "vue-router";
import { setUnauthorizedHandler } from "./lib/api.js";
import { auth, ensureAuth, isAdmin } from "./lib/auth.js";

function safeNext(raw, fallback = "/app") {
  const next = String(raw || fallback);
  if (!next.startsWith("/") || next.startsWith("//") || next === "/login") return fallback;
  if (next === "/") return fallback;
  return next;
}

const router = createRouter({
  history: createWebHistory(),
  scrollBehavior(to) {
    if (to.hash) return { el: to.hash, top: 72 };
    return { top: 0 };
  },
  routes: [
    { path: "/login", name: "login", component: () => import("./pages/LoginPage.vue"), meta: { public: true } },
    {
      path: "/",
      component: () => import("./components/PublicShell.vue"),
      meta: { public: true },
      children: [
        { path: "", name: "site", component: () => import("./pages/LandingPage.vue") },
        { path: "blog", name: "blog", component: () => import("./pages/BlogListPage.vue") },
        { path: "blog/:slug", name: "blog-post", component: () => import("./pages/BlogPostPage.vue") },
      ],
    },
    { path: "/app", name: "home", component: () => import("./pages/HomePage.vue") },
    { path: "/analyze", name: "analyze", component: () => import("./pages/AnalyzePage.vue") },
    { path: "/audit", name: "audit", component: () => import("./pages/AuditPage.vue") },
    { path: "/patch", name: "patch", component: () => import("./pages/PatchPage.vue") },
    { path: "/jobs", name: "jobs", component: () => import("./pages/JobsPage.vue") },
    { path: "/jobs/:id", name: "job", component: () => import("./pages/JobCasePage.vue") },
    { path: "/research", redirect: "/jobs" },
    { path: "/publish", name: "publish", component: () => import("./pages/BlogAdminPage.vue") },
    { path: "/settings", name: "settings", component: () => import("./pages/SettingsPage.vue") },
    { path: "/users", name: "users", component: () => import("./pages/UsersPage.vue"), meta: { admin: true } },
    { path: "/account", name: "account", component: () => import("./pages/AccountPage.vue") },
  ],
});

router.beforeEach(async to => {
  if (to.meta.public) {
    await ensureAuth();
    if (to.name === "login" && auth.user) {
      return safeNext(to.query.next);
    }
    return true;
  }
  const ok = await ensureAuth();
  if (!ok) return { path: "/login", query: { next: to.fullPath } };
  if (to.meta.admin && !isAdmin()) return { path: "/app" };
  return true;
});

router.afterEach(to => {
  const titles = {
    site: "Patchalyzer.ai",
    blog: "研究 · Patchalyzer.ai",
    login: "登录 · Patchalyzer.ai",
    home: "工作台 · Patchalyzer.ai",
    audit: "内核审计 · Patchalyzer.ai",
    publish: "发布管理 · Patchalyzer.ai",
  };
  if (to.name !== "blog-post") {
    document.title = titles[to.name] || "Patchalyzer.ai";
  }
});

setUnauthorizedHandler(() => {
  auth.user = null;
  const cur = router.currentRoute.value;
  if (cur.meta?.public || cur.name === "login") return;
  router.replace({ path: "/login", query: { next: cur.fullPath } });
});

export default router;
