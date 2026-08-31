import { computed, unref } from "vue";

export const PAGE_SIZE = 20;

export function parsePage(raw) {
  const n = Number(raw || 1);
  return Number.isInteger(n) && n >= 1 ? n : 1;
}

export function pageButtonList(total, cur) {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const set = new Set([1, total, cur - 1, cur, cur + 1]);
  if (cur <= 3) { set.add(2); set.add(3); set.add(4); }
  if (cur >= total - 2) { set.add(total - 3); set.add(total - 2); set.add(total - 1); }
  return [...set].filter(n => n >= 1 && n <= total).sort((a, b) => a - b);
}

export function usePager(rows, page, size = PAGE_SIZE) {
  const pageCount = computed(() => Math.max(1, Math.ceil(unref(rows).length / size)));
  const safePage = computed(() => Math.min(unref(page), pageCount.value));
  const paged = computed(() => {
    const list = unref(rows);
    const start = (safePage.value - 1) * size;
    return list.slice(start, start + size);
  });
  const pageLabel = computed(() => {
    const n = unref(rows).length;
    if (!n) return "0 条";
    const start = (safePage.value - 1) * size + 1;
    const end = Math.min(n, safePage.value * size);
    return `${start}–${end} / ${n} 条`;
  });
  const pageButtons = computed(() => pageButtonList(pageCount.value, safePage.value));
  return { PAGE_SIZE: size, pageCount, safePage, paged, pageLabel, pageButtons };
}
