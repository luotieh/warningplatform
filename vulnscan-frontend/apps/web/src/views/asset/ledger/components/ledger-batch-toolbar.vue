<script lang="ts" setup>
import { NButton, NCard, NSpace, NTag } from 'naive-ui';

defineOptions({ name: 'LedgerBatchToolbar' });

defineProps<{
  selectedCount: number;
}>();

const emit = defineEmits<{
  edit: [];
  monitor: [];
  scan: [];
  verify: [];
}>();
</script>

<template>
  <NCard size="small" embedded>
    <div class="ledger-batch-toolbar">
      <NSpace align="center">
        <span class="ledger-batch-toolbar__title">批量操作</span>
        <NTag type="info" :bordered="false">已选择 {{ selectedCount }} 项资产</NTag>
      </NSpace>

      <NSpace>
        <NButton :disabled="selectedCount === 0" @click="emit('edit')">批量编辑</NButton>
        <NButton :disabled="selectedCount === 0" @click="emit('monitor')">发送监测</NButton>
        <NButton :disabled="selectedCount === 0" @click="emit('verify')">下发核验</NButton>
        <NButton :disabled="selectedCount === 0" @click="emit('scan')">批量扫描</NButton>
      </NSpace>
    </div>
  </NCard>
</template>

<style scoped>
.ledger-batch-toolbar__title {
  font-weight: 600;
}

.ledger-batch-toolbar {
  align-items: center;
  display: flex;
  gap: 12px;
  justify-content: space-between;
}

@media (max-width: 960px) {
  .ledger-batch-toolbar {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
