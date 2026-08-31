<template>
  <div class="pa-head">
    <div>
      <h2>{{ title }}</h2>
      <p>{{ sub }}</p>
    </div>
    <div class="pa-head-actions">
      <slot />
    </div>
  </div>
</template>
<script setup>
defineProps({
  title: { type: String, required: true },
  sub: { type: String, default: "" },
});
</script>
