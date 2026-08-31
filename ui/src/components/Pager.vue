<template>
  <nav v-if="total > size" class="pa-pager" aria-label="分页">
    <span>{{ label }}</span>
    <div class="pa-pager-btns">
      <button type="button" class="pa-btn" :disabled="page <= 1" @click="$emit('go', page - 1)">上一页</button>
      <template v-for="(n, i) in buttons" :key="n">
        <span v-if="i && n - buttons[i - 1] > 1" class="pa-pager-gap">…</span>
        <button type="button" class="pa-pager-num" :class="{ on: n === page }" @click="$emit('go', n)">{{ n }}</button>
      </template>
      <button type="button" class="pa-btn" :disabled="page >= count" @click="$emit('go', page + 1)">下一页</button>
    </div>
  </nav>
</template>
<script setup>
import { PAGE_SIZE } from "../lib/pager.js";

defineProps({
  total: { type: Number, required: true },
  page: { type: Number, required: true },
  count: { type: Number, required: true },
  label: { type: String, default: "" },
  buttons: { type: Array, default: () => [] },
  size: { type: Number, default: PAGE_SIZE },
});
defineEmits(["go"]);
</script>
