let enginePromise;

export function loadEngine() {
  if (!enginePromise) enginePromise = import("../legacy/engine.js");
  return enginePromise;
}

export async function openReport(jobId, panel) {
  if (window.__paOpenJob) {
    window.__paOpenJob(jobId, panel);
    return;
  }
  const m = await loadEngine();
  return m.openJobModal(jobId, panel);
}

export async function pollJob(jobId, toJobs = false) {
  const m = await loadEngine();
  return m.pollJob(jobId, toJobs);
}

export async function closeReport() {
  const m = await loadEngine();
  return m.closeJobModal?.();
}
