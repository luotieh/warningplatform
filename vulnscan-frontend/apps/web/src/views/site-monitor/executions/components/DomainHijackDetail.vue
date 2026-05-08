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

const dnsResults = computed(() => {
  const raw = r.value.dns_results || {};
  return Object.entries(raw).map(([resolver, ips]) => ({
    resolver,
    ips: Array.isArray(ips) ? (ips as string[]).join(', ') : String(ips),
    count: Array.isArray(ips) ? (ips as string[]).length : 0,
  }));
});

const dnsCols: DataTableColumns<any> = [
  { key: 'resolver', title: 'DNS服务器', width: 160 },
  {
    key: 'ips',
    title: '解析结果',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('span', { class: 'font-mono text-xs' }, row.ips || '-'),
  },
  {
    key: 'count',
    title: 'IP数量',
    width: 80,
    align: 'center',
  },
];
</script>

<template>
  <div class="space-y-3">
    <NCard size="small" title="域名劫持检测">
      <NDescriptions :column="3" bordered size="small">
        <NDescriptionsItem label="检测结果">
          <NTag
            :type="r.hijacked ? 'error' : 'success'"
            size="small"
            :bordered="false"
          >
            {{ r.hijacked ? '⚠ 疑似域名劫持' : '正常' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="目标URL">
          <span class="font-mono break-all text-xs">{{ r.url || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem v-if="r.http_status" label="HTTP状态">
          <span class="font-mono">{{ r.http_status }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem v-if="r.reason" label="原因" :span="3">
          <span class="text-sm text-red-500">{{ r.reason }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem v-if="r.parking_ip" label="停靠IP">
          <span class="font-mono text-red-500">{{ r.parking_ip }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem v-if="r.warning" label="警告" :span="3">
          <span class="text-sm text-yellow-500">{{ r.warning }}</span>
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard v-if="r.skipped" size="small" title="跳过检测">
      <div class="text-sm text-gray-500">
        {{ r.reason || '当前目标为IP地址，跳过DNS检测' }}
      </div>
    </NCard>

    <NCard
      v-if="dnsResults.length > 0"
      size="small"
      :title="`多DNS解析对比（${dnsResults.length} 个DNS）`"
    >
      <NDataTable
        :columns="dnsCols"
        :data="dnsResults"
        size="small"
        :max-height="300"
      />
    </NCard>

    <NEmpty
      v-if="!r.hijacked && !r.skipped && dnsResults.length === 0"
      description="无域名劫持风险"
      class="py-8"
    />
  </div>
</template>
