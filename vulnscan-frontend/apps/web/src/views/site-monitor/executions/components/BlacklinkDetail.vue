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

const blacklinks = computed(() => r.value.blacklink_matches || []);
const backdoors = computed(() => r.value.backdoor_findings || []);

const blacklinkCols: DataTableColumns<any> = [
  {
    key: 'url',
    title: '链接地址',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('span', { class: 'font-mono text-xs' }, row.url || '-'),
  },
  {
    key: 'domain',
    title: '域名',
    width: 180,
    ellipsis: { tooltip: true },
  },
  {
    key: 'hidden',
    title: '隐藏链接',
    width: 90,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        {
          type: row.hidden ? 'error' : 'default',
          size: 'small',
          bordered: false,
        },
        { default: () => (row.hidden ? '是' : '否') },
      ),
  },
  {
    key: 'pattern',
    title: '匹配规则',
    width: 160,
    ellipsis: { tooltip: true },
    render: (row) => row.pattern || '-',
  },
];

const backdoorCols: DataTableColumns<any> = [
  {
    key: 'path',
    title: '后门路径',
    width: 200,
    ellipsis: { tooltip: true },
  },
  {
    key: 'src',
    title: '资源地址',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('span', { class: 'font-mono text-xs' }, row.src || '-'),
  },
  {
    key: 'context',
    title: '上下文',
    width: 120,
    render: (row) => row.context || '-',
  },
];
</script>

<template>
  <div class="space-y-3">
    <NCard size="small" title="暗链检测结果">
      <NDescriptions :column="4" bordered size="small">
        <NDescriptionsItem label="检测结果">
          <NTag
            :type="r.has_black ? 'error' : 'success'"
            size="small"
            :bordered="false"
          >
            {{ r.has_black ? '⚠ 发现暗链/后门' : '未发现异常' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="目标URL">
          <span class="font-mono break-all text-xs">{{ r.url || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="页面链接总数">
          {{ r.total_links ?? '-' }}
        </NDescriptionsItem>
        <NDescriptionsItem label="外部链接">
          {{ r.external_links ?? '-' }}
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard
      v-if="blacklinks.length > 0"
      size="small"
      :title="`暗链命中（${blacklinks.length} 条）`"
    >
      <NDataTable
        :columns="blacklinkCols"
        :data="blacklinks"
        size="small"
        :max-height="400"
      />
    </NCard>

    <NCard
      v-if="backdoors.length > 0"
      size="small"
      :title="`后门文件命中（${backdoors.length} 条）`"
    >
      <NDataTable
        :columns="backdoorCols"
        :data="backdoors"
        size="small"
        :max-height="400"
      />
    </NCard>

    <NEmpty
      v-if="!r.has_black && blacklinks.length === 0 && backdoors.length === 0"
      description="未发现暗链或后门"
      class="py-8"
    />
  </div>
</template>
