<script lang="ts" setup>
import { NButton, NSpace } from 'naive-ui';

import type { LedgerOption } from '../types';

defineOptions({ name: 'LedgerFamilyTabs' });

defineProps<{
  active: string;
  options: readonly LedgerOption[];
}>();

const emit = defineEmits<{
  change: [value: string];
}>();
</script>

<template>
  <NSpace wrap class="ledger-family-tabs" :size="8">
    <NButton
      v-for="item in options"
      :key="item.value"
      round
      size="small"
      class="ledger-family-tabs__button"
      :type="active === item.value ? 'primary' : 'default'"
      :secondary="active === item.value"
      @click="emit('change', item.value)"
    >
      {{ item.label }}
    </NButton>
  </NSpace>
</template>

<style scoped>
.ledger-family-tabs__button {
  min-width: 84px;
}
</style>
