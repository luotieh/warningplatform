<script lang="ts" setup>
import { NButton, NCard, NPopconfirm, NSpace, NTag } from 'naive-ui';

defineOptions({ name: 'LedgerBatchToolbar' });

defineProps<{
  selectedCount: number;
  deleting?: boolean;
}>();

const emit = defineEmits<{
  edit: [];
  monitor: [];
  scan: [];
  verify: [];
  delete: [];
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
        <NPopconfirm
          :disabled="selectedCount === 0"
          @positive-click="emit('delete')"
        >
          <template #trigger>
            <NButton type="error" :disabled="selectedCount === 0" :loading="deleting">
              批量删除
            </NButton>
          </template>
          确认删除已选的 {{ selectedCount }} 条资产？此操作不可恢复。
        </NPopconfirm>
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
