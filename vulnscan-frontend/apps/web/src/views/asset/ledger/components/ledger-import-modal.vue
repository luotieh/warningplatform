<script lang="ts" setup>
import type { UploadFileInfo } from 'naive-ui';

import { NButton, NModal, NSpace, NUpload } from 'naive-ui';

defineOptions({ name: 'LedgerImportModal' });

defineProps<{
  show: boolean;
  loading?: boolean;
  templateDownloading?: boolean;
}>();

const emit = defineEmits<{
  close: [];
  submit: [];
  'download-template': [];
  'update:show': [value: boolean];
  change: [payload: { file: UploadFileInfo }];
}>();
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    title="导入资产"
    style="width: min(560px, calc(100vw - 32px))"
    @update:show="(value) => emit('update:show', value)"
  >
    <NSpace vertical :size="16">
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
        <NButton :loading="templateDownloading" @click="emit('download-template')">下载模板</NButton>
        <NSpace>
          <NButton @click="emit('close')">取消</NButton>
          <NButton type="primary" :loading="loading" @click="emit('submit')">开始导入</NButton>
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
</style>
