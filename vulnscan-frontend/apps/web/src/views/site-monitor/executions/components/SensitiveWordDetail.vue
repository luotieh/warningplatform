<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import { computed, h } from 'vue';

import {
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NTag,
} from 'naive-ui';

const props = defineProps<{ result: any }>();
const r = computed(() => props.result || {});

type TagType = 'default' | 'error' | 'info' | 'primary' | 'success' | 'warning';

function sevTag(s: string): TagType {
  const m: Record<string, TagType> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'info',
  };
  return m[s] || 'info';
}

function sevLabel(s: string) {
  const m: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
  };
  return m[s] || s || '-';
}

const matches = computed(() => r.value.matches || []);

const matchCols: DataTableColumns<any> = [
  {
    key: 'word',
    title: '敏感词',
    width: 140,
    render: (row) =>
      h('span', { class: 'font-bold text-red-500' }, row.word || '-'),
  },
  {
    key: 'category',
    title: '分类',
    width: 120,
  },
  {
    key: 'severity',
    title: '严重程度',
    width: 100,
    render: (row) =>
      h(
        NTag,
        { type: sevTag(row.severity), size: 'small', bordered: false },
        { default: () => sevLabel(row.severity) },
      ),
  },
  {
    key: 'count',
    title: '命中次数',
    width: 90,
    align: 'center',
    render: (row) =>
      h(
        'span',
        { class: 'font-mono font-bold' },
        String(row.count ?? 0),
      ),
  },
  {
    key: 'context',
    title: '上下文',
    minWidth: 260,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('span', { class: 'text-xs text-gray-600' }, row.context || '-'),
  },
];
</script>

<template>
  <div class="space-y-3">
    <NCard size="small" title="敏感词检测结果">
      <NDescriptions :column="4" bordered size="small">
        <NDescriptionsItem label="检测结果">
          <NTag
            :type="r.has_hit ? 'error' : 'success'"
            size="small"
            :bordered="false"
          >
            {{ r.has_hit ? '⚠ 发现敏感词' : '未发现敏感词' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="目标URL">
          <span class="font-mono break-all text-xs">{{ r.url || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="命中敏感词">
          <span class="font-mono font-bold">
            {{ matches.length }} 个
          </span>
        </NDescriptionsItem>
        <NDescriptionsItem label="总命中次数">
          <span class="font-mono">{{ r.total_matches ?? 0 }} 次</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="页面文本长度">
          {{ r.text_length ?? '-' }} 字符
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard
      v-if="matches.length > 0"
      size="small"
      :title="`命中详情（${matches.length} 项）`"
    >
      <NDataTable
        :columns="matchCols"
        :data="matches"
        size="small"
        :max-height="400"
      />
    </NCard>

    <NEmpty
      v-if="!r.has_hit && matches.length === 0"
      description="未检测到敏感词"
      class="py-8"
    />
  </div>
</template>
