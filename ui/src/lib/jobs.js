import { reactive } from "vue";
import { apiGet, isLiveJob } from "./api.js";
import { ui } from "./store.js";

const KEY = "pa.jobs.v1";

export const jobsStore = reactive({
  items: [],
  loaded: false,
  loading: false,
  refreshing: false,
  error: "",
});

function readCache() {
  try {
    const data = JSON.parse(sessionStorage.getItem(KEY) || "");
    return Array.isArray(data?.items) ? data.items : [];
  } catch {
    return [];
  }
}

function writeCache(items) {
  try {
    sessionStorage.setItem(KEY, JSON.stringify({ items, at: Date.now() }));
  } catch {
    /* quota / private mode */
  }
}

function syncLiveCount() {
  ui.liveCount = jobsStore.items.filter(isLiveJob).length;
}

const cached = readCache();
if (cached.length) {
  jobsStore.items = cached;
  jobsStore.loaded = true;
  syncLiveCount();
}

let inflight = null;
let poller = 0;
let source = null;
const liveListeners = new Set();
const seenFinished = new Set();

export function peekJob(id) {
  return jobsStore.items.find(j => j.id === id) || null;
}

export function onJobsLive(fn) {
  liveListeners.add(fn);
  return () => liveListeners.delete(fn);
}

export function hasLiveJobs() {
  return jobsStore.items.some(isLiveJob);
}

export function upsertJob(job) {
  if (!job?.id) return;
  jobsStore.items = [job, ...jobsStore.items.filter(j => j.id !== job.id)];
  writeCache(jobsStore.items);
  syncLiveCount();
}

function mergeLive(live) {
  const byId = Object.create(null);
  for (const j of live || []) {
    if (j?.id) byId[j.id] = j;
  }
  const wasLive = jobsStore.items.filter(isLiveJob).map(j => j.id);
  jobsStore.items = jobsStore.items.map(j => (byId[j.id] ? { ...j, ...byId[j.id] } : j));
  for (const j of live || []) {
    if (!jobsStore.items.some(x => x.id === j.id)) upsertJob(j);
  }
  const still = new Set((live || []).map(j => j.id));
  writeCache(jobsStore.items);
  syncLiveCount();
  return wasLive.some(id => !still.has(id));
}

export function loadJobs({ force = false, silent = false } = {}) {
  if (inflight && !force) return inflight;
  const showBlock = !jobsStore.loaded && !jobsStore.items.length;
  if (showBlock) jobsStore.loading = true;
  else if (!silent) jobsStore.refreshing = true;
  inflight = (async () => {
    try {
      const data = await apiGet("/jobs", { timeout: 8000 });
      jobsStore.items = Array.isArray(data) ? data : [];
      jobsStore.loaded = true;
      jobsStore.error = "";
      writeCache(jobsStore.items);
      syncLiveCount();
    } catch (e) {
      if (!jobsStore.items.length) jobsStore.error = e.message || "读取任务失败";
    } finally {
      jobsStore.loading = false;
      jobsStore.refreshing = false;
      inflight = null;
    }
  })();
  return inflight;
}

function emitLive(live, finished) {
  for (const fn of liveListeners) {
    try { fn(live || [], finished || []); } catch { /* listener */ }
  }
}

function onEventPayload(payload) {
  const live = Array.isArray(payload?.live) ? payload.live : [];
  const dropped = mergeLive(live);
  const fresh = [];
  for (const f of payload?.finished || []) {
    const key = `${f.id}:${f.status}`;
    if (!f?.id || seenFinished.has(key)) continue;
    seenFinished.add(key);
    fresh.push(f);
  }
  if (dropped || fresh.length) loadJobs({ silent: true, force: true });
  emitLive(live, fresh);
}

function connectEvents() {
  if (source || typeof EventSource === "undefined") return;
  source = new EventSource("/api/jobs/events", { withCredentials: true });
  source.addEventListener("jobs", ev => {
    try { onEventPayload(JSON.parse(ev.data || "{}")); } catch { /* ignore */ }
  });
  source.onerror = () => {
    /* EventSource reconnects; fall back poll keeps list moving if the stream dies */
  };
}

export function startJobsPoller() {
  loadJobs({ silent: true });
  connectEvents();
  if (poller) return;
  poller = window.setInterval(() => {
    if (document.hidden) return;
    if (source && source.readyState === EventSource.OPEN) return;
    if (hasLiveJobs()) loadJobs({ silent: true });
  }, 5000);
}

export function stopJobsPoller() {
  if (poller) {
    clearInterval(poller);
    poller = 0;
  }
  if (source) {
    source.close();
    source = null;
  }
}

if (typeof window !== "undefined") {
  window.__paPeekJob = peekJob;
  window.__paOnJobsLive = onJobsLive;
}
