let loading;

export function ensureMarkdownLibs() {
  if (globalThis.marked && globalThis.mermaid && globalThis.renderMathInElement) {
    return Promise.resolve();
  }
  if (!loading) {
    loading = Promise.all([
      import("marked"),
      import("mermaid"),
      import("katex/contrib/auto-render"),
    ]).then(([markedMod, mermaidMod, katexMod]) => {
      const marked = markedMod.marked || markedMod.default || markedMod;
      const mermaid = mermaidMod.default || mermaidMod;
      const renderMath = katexMod.default || katexMod;
      globalThis.marked = marked;
      globalThis.mermaid = mermaid;
      globalThis.renderMathInElement = renderMath;
      mermaid.initialize?.({ startOnLoad: false, securityLevel: "strict" });
    });
  }
  return loading;
}

export async function renderMarkdownHtml(markdown) {
  const markedMod = await import("marked");
  const marked = markedMod.marked || markedMod.default || markedMod;
  return marked.parse(markdown || "", { async: false, gfm: true, breaks: true });
}
