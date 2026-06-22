<script lang="ts" setup>
import { computed } from 'vue';

const props = withDefaults(
  defineProps<{
    dotCount?: number;
    endColor?: string;
    startColor?: string;
  }>(),
  {
    dotCount: 12,
    endColor: '#1e9a7e',
    startColor: '#98d2c7',
  },
);

const actualDotCount = computed(() => Math.max(0, Math.min(props.dotCount, 12)));

function hexToRgb(hex: string) {
  const useHex = hex.replace('#', '');
  const r = Number.parseInt(useHex.slice(0, 2), 16) || 0;
  const g = Number.parseInt(useHex.slice(2, 4), 16) || 0;
  const b = Number.parseInt(useHex.slice(4, 6), 16) || 0;
  return [r, g, b] as const;
}

function getRoundStyle(index: number) {
  const count = Math.max(actualDotCount.value, 1);
  const pos = count === 1 ? 0 : index / (count - 1);
  const [sr, sg, sb] = hexToRgb(props.startColor);
  const [er, eg, eb] = hexToRgb(props.endColor);
  const r = Math.round(sr + (er - sr) * pos);
  const g = Math.round(sg + (eg - sg) * pos);
  const b = Math.round(sb + (eb - sb) * pos);
  return { backgroundColor: `rgb(${r}, ${g}, ${b})` };
}
</script>

<template>
  <div class="progress-dot-wrap">
    <div v-for="i in actualDotCount" :key="i" class="dot" :style="getRoundStyle(i - 1)" />
  </div>
</template>

<style scoped>
.progress-dot-wrap {
  align-items: center;
  display: flex;
  gap: 4px;
}
.dot {
  border-radius: 999px;
  height: 9px;
  width: 9px;
}
</style>
