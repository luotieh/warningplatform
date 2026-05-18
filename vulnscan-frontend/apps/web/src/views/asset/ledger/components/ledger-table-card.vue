<script lang="ts" setup>
import type { DataTableColumns, DropdownOption, PaginationProps } from 'naive-ui';

import type { Asset } from '#/api/asset';
import { LEDGER_TABLE_SCROLL_X } from '../constants';
import { NButton, NCard, NDataTable, NDropdown, NEmpty, NSpace, NTag } from 'naive-ui';

defineOptions({ name: 'LedgerTableCard' });

defineProps<{
  columns: DataTableColumns<Asset>;
  data: Asset[];
  loading?: boolean;
  pagination: PaginationProps;
  checkedRowKeys: string[];
}>();

const emit = defineEmits<{
  refresh: [];
  create: [];
  import: [];
  export: [format: 'csv' | 'xlsx'];
  batchAction: [key: string];
  'update:checkedRowKeys': [keys: string[]];
}>();

const batchOptions: DropdownOption[] = [
  { label: '批量扫描', key: 'scan' },
  { label: '发送监测', key: 'monitor' },
  { label: '下发核验', key: 'verify' },
  { label: '批量编辑', key: 'edit' },
  { type: 'divider', key: 'divider' },
  { label: '批量删除', key: 'delete' },
];

const exportOptions: DropdownOption[] = [
  { label: '导出 XLSX', key: 'xlsx' },
  { label: '导出 CSV', key: 'csv' },
];
</script>

<template>
  <NCard size="small" class="ledger-table-card">
    <template #header>
      <div class="ledger-table-card__header">
        <NSpace align="center">
          <span class="ledger-table-card__title">资产列表</span>
          <NTag v-if="checkedRowKeys.length > 0" :bordered="false" type="info">
            已选择 {{ checkedRowKeys.length }} 项
          </NTag>
        </NSpace>

        <NSpace>
          <NButton type="primary" @click="emit('create')">新增资产</NButton>
          <NButton @click="emit('import')">导入</NButton>
          <NDropdown :options="exportOptions" @select="(key) => emit('export', key as 'csv' | 'xlsx')">
            <NButton>导出</NButton>
          </NDropdown>
          <NDropdown :options="batchOptions" @select="(key) => emit('batchAction', String(key))">
            <NButton :disabled="checkedRowKeys.length === 0">批量操作</NButton>
          </NDropdown>
          <NButton quaternary @click="emit('refresh')">刷新</NButton>
        </NSpace>
      </div>
    </template>

    <NDataTable
      remote
      size="small"
      :bordered="false"
      :scroll-x="LEDGER_TABLE_SCROLL_X"
      :columns="columns"
      :data="data"
      :loading="loading"
      :pagination="pagination"
      :checked-row-keys="checkedRowKeys"
      :row-key="(row: Asset) => row.id"
      @update:checked-row-keys="(keys) => emit('update:checkedRowKeys', keys.map(String))"
    >
      <template #empty>
        <NEmpty description="暂无资产数据" />
      </template>
    </NDataTable>
  </NCard>
</template>

<style scoped>
/** 与栅格列 minmax(0,1fr) 配合，避免宽表把主列撑出视口 */
.ledger-table-card {
  max-width: 100%;
  min-width: 0;
}

.ledger-table-card__title {
  font-weight: 600;
}

.ledger-table-card__header {
  align-items: center;
  display: flex;
  gap: 12px;
  justify-content: space-between;
  width: 100%;
}

@media (max-width: 960px) {
  .ledger-table-card__header {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
