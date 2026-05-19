<script lang="ts" setup>
import type { UploadFileInfo } from 'naive-ui';
import type { DataTableColumns } from 'naive-ui';

import { computed } from 'vue';

import { NAlert, NButton, NDataTable, NModal, NSpace, NUpload } from 'naive-ui';

import type {
  ImportFailedRowPayload,
  ImportIssuePayload,
} from '#/api/helpers';

import {
  buildImportErrorTableRows,
  importErrorSummary,
  type ImportRowErrorGroup,
} from '../import-errors';

defineOptions({ name: 'LedgerImportModal' });

const props = defineProps<{
  show: boolean;
  loading?: boolean;
  templateDownloading?: boolean;
  errorMessage?: string;
  errorIssues?: ImportIssuePayload[];
  errorFailedRows?: ImportFailedRowPayload[];
  errorCount?: number;
}>();

const emit = defineEmits<{
  close: [];
  submit: [];
  'download-template': [];
  'update:show': [value: boolean];
  change: [payload: { file: UploadFileInfo }];
}>();

const errorRows = computed(() =>
  buildImportErrorTableRows(
    props.errorFailedRows ?? [],
    props.errorIssues ?? [],
  ),
);

const hasErrorTable = computed(() => errorRows.value.length > 0);

const errorSummary = computed(() => {
  if (hasErrorTable.value) {
    const count = props.errorCount ?? props.errorIssues?.length ?? 0;
    return importErrorSummary(count, errorRows.value.length);
  }
  return props.errorMessage ?? '';
});

const modalWidth = computed(() =>
  hasErrorTable.value
    ? 'min(960px, calc(100vw - 32px))'
    : 'min(560px, calc(100vw - 32px))',
);

const columns: DataTableColumns<ImportRowErrorGroup> = [
  {
    title: '行号',
    key: 'row',
    width: 76,
    align: 'center',
    render: (row) => `第 ${row.row} 行`,
  },
  {
    title: '系统名称',
    key: 'name',
    width: 140,
    ellipsis: { tooltip: true },
    render: (row) => row.name || '—',
  },
  {
    title: '单位名称',
    key: 'organizeName',
    width: 140,
    ellipsis: { tooltip: true },
    render: (row) => row.organizeName || '—',
  },
  {
    title: '访问地址',
    key: 'address',
    width: 180,
    ellipsis: { tooltip: true },
    render: (row) => row.address || '—',
  },
  {
    title: '资产分类',
    key: 'assetFamily',
    width: 100,
    ellipsis: { tooltip: true },
    render: (row) => row.assetFamily || '—',
  },
  {
    title: '错误原因',
    key: 'summary',
    minWidth: 220,
    ellipsis: { tooltip: { style: { maxWidth: '480px' } } },
  },
];
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    title="导入资产"
    :style="{ width: modalWidth }"
    @update:show="(value) => emit('update:show', value)"
  >
    <NSpace vertical :size="16">
      <NAlert
        v-if="errorSummary"
        type="error"
        :show-icon="true"
        title="导入失败"
      >
        {{ errorSummary }}
      </NAlert>

      <div v-if="hasErrorTable" class="ledger-import__error-table-wrap">
        <NDataTable
          class="ledger-import__error-table"
          :columns="columns"
          :data="errorRows"
          :bordered="true"
          size="small"
          :single-line="false"
          :scroll-x="900"
          :max-height="400"
          :row-class-name="() => 'ledger-import-error-row'"
        />
      </div>

      <div class="ledger-import__tip">
        模板已收敛为必要字段。像端口、协议、服务等可探测补全的信息，不再要求在模板里手工重复填写。
      </div>
      <div class="ledger-import__tip">
        先下载模板，按说明填写后上传；导入完成后，仍可通过探测和扫描继续补齐资产详情。
      </div>

      <NUpload
        :default-upload="false"
        :max="1"
        accept=".xlsx,.xls,.csv"
        @change="(payload) => emit('change', payload)"
      >
        <NButton>选择文件</NButton>
      </NUpload>
    </NSpace>

    <template #footer>
      <NSpace justify="space-between">
        <NButton :loading="templateDownloading" @click="emit('download-template')">
          下载模板
        </NButton>
        <NSpace>
          <NButton @click="emit('close')">取消</NButton>
          <NButton type="primary" :loading="loading" @click="emit('submit')">
            开始导入
          </NButton>
        </NSpace>
      </NSpace>
    </template>
  </NModal>
</template>

<style scoped>
.ledger-import__tip {
  color: var(--n-text-color-2);
  font-size: 13px;
  line-height: 1.6;
}

.ledger-import__error-table-wrap {
  border: 1px solid var(--n-border-color);
  border-radius: 8px;
  overflow: hidden;
}

.ledger-import__error-table :deep(.ledger-import-error-row td) {
  background: rgba(208, 48, 80, 0.08);
  color: var(--n-error-color);
}

.ledger-import__error-table :deep(.ledger-import-error-row:hover td) {
  background: rgba(208, 48, 80, 0.12);
}

.ledger-import__error-table :deep(.n-data-table-th) {
  background: var(--n-action-color);
}
</style>
