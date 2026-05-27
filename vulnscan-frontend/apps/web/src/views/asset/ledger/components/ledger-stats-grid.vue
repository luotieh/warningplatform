<script lang="ts" setup>
import { NCard, NGrid, NGridItem } from 'naive-ui';

import type { LedgerStats } from '../types';

defineOptions({ name: 'LedgerStatsGrid' });

defineProps<{
  stats: LedgerStats;
}>();

const cards = [
  { key: 'total', label: '资产总数' },
  { key: 'active', label: '在线资产' },
  { key: 'keyAssets', label: '重点资产' },
  { key: 'riskHigh', label: '高风险资产' },
  { key: 'withVulns', label: '存在漏洞' },
] as const;
</script>

<template>
  <NGrid cols="1 s:2 m:3 l:5" :x-gap="16" :y-gap="16" responsive="screen" class="ledger-stats">
    <NGridItem v-for="card in cards" :key="card.key">
      <NCard size="small" class="ledger-stats__card">
        <div class="ledger-stats__label">{{ card.label }}</div>
        <div class="ledger-stats__value">{{ stats[card.key] }}</div>
      </NCard>
    </NGridItem>
  </NGrid>
</template>

<style scoped>
.ledger-stats__card {
  border-radius: 14px;
}

.ledger-stats__card :deep(.n-card__content) {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  text-align: center;
}

.ledger-stats__label {
  color: var(--n-text-color-3);
  font-size: 13px;
}

.ledger-stats__value {
  color: var(--n-text-color-1);
  font-size: 28px;
  font-weight: 700;
  line-height: 1;
}
</style>
