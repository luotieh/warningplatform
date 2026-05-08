<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import { computed, h } from 'vue';

import {
  NAlert,
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NTag,
} from 'naive-ui';

const props = defineProps<{ result: any }>();
const r = computed(() => props.result || {});

const allFindings = computed(() => r.value.findings || []);
const realFindings = computed(() =>
  allFindings.value.filter((f: any) => !f.soft_404),
);
const soft404Findings = computed(() =>
  allFindings.value.filter((f: any) => f.soft_404),
);

function formatSize(bytes: number) {
  if (!bytes || bytes <= 0) return '-';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

const findingCols: DataTableColumns<any> = [
  {
    key: 'path',
    title: '文件路径',
    width: 220,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('span', { class: 'font-mono text-xs text-red-500' }, row.path || '-'),
  },
  {
    key: 'url',
    title: '完整URL',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render: (row) =>
      h(
        'a',
        {
          href: row.url,
          target: '_blank',
          class: 'font-mono text-xs text-blue-500 hover:underline',
        },
        row.url || '-',
      ),
  },
  {
    key: 'status',
    title: '状态码',
    width: 80,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        {
          type: row.status === 200 ? 'error' : 'default',
          size: 'small',
          bordered: false,
        },
        { default: () => String(row.status ?? '-') },
      ),
  },
  {
    key: 'size',
    title: '文件大小',
    width: 100,
    align: 'center',
    render: (row) => formatSize(row.size),
  },
];

const soft404Cols: DataTableColumns<any> = [
  ...findingCols,
  {
    key: 'soft_404_reason',
    title: '排除原因',
    minWidth: 200,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('span', { class: 'text-xs text-gray-500' }, row.soft_404_reason || '-'),
  },
];
</script>

<template>
  <div class="space-y-3">
    <NCard size="small" title="敏感文件检测结果">
      <NDescriptions :column="4" bordered size="small">
        <NDescriptionsItem label="检测结果">
          <NTag
            :type="r.has_hit ? 'error' : 'success'"
            size="small"
            :bordered="false"
          >
            {{ r.has_hit ? '⚠ 发现敏感文件' : '未发现敏感文件' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="目标URL">
          <span class="font-mono break-all text-xs">{{ r.url || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="探测路径数">
          {{ r.total_probed ?? '-' }}
        </NDescriptionsItem>
        <NDescriptionsItem label="真实发现 / 软404排除">
          <span class="font-mono">
            <span class="font-bold text-red-500">{{ realFindings.length }}</span>
            <span class="mx-1 text-gray-400">/</span>
            <span class="text-gray-500">{{ soft404Findings.length }}</span>
          </span>
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard
      v-if="realFindings.length > 0"
      size="small"
      :title="`确认的敏感文件（${realFindings.length} 个）`"
    >
      <NDataTable
        :columns="findingCols"
        :data="realFindings"
        size="small"
        :max-height="300"
      />
    </NCard>

    <NCard
      v-if="soft404Findings.length > 0"
      size="small"
    >
      <template #header>
        <span class="text-gray-500">疑似软404（{{ soft404Findings.length }} 个，已自动排除）</span>
      </template>
      <NAlert type="info" class="mb-2" :show-icon="false">
        以下文件返回了 HTTP 200，但响应内容与随机路径的错误页面一致或多个文件大小相同，极可能是网站统一处理的自定义错误页面。
      </NAlert>
      <NDataTable
        :columns="soft404Cols"
        :data="soft404Findings"
        size="small"
        :max-height="200"
      />
    </NCard>

    <NEmpty
      v-if="!r.has_hit && allFindings.length === 0"
      description="未发现敏感文件"
      class="py-8"
    />
  </div>
</template>
