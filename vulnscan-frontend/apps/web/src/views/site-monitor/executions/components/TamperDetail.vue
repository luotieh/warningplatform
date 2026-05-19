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

const props = defineProps<{ executionId?: string; result: any }>();

const r = computed(() => props.result || {});
const diffs = computed(
  () => r.value.diffs || r.value.diff?.diffs || [],
);
const baselineUpdate = computed(() => r.value.baseline_update || null);
const isFirstRun = computed(
  () =>
    r.value.is_first_run === true ||
    baselineUpdate.value?.action === 'init',
);

const evidence = computed(() => r.value.evidence || null);

const showCompareEvidence = computed(() => {
  const ev = evidence.value;
  if (!ev) return false;
  return Boolean(ev.baseline_html || ev.current_html);
});

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

function diffTypeLabel(t: string) {
  const m: Record<string, string> = {
    content_hash: '内容Hash变化',
    title: '标题变化',
    status_code: 'HTTP状态码变化',
    text_length: '文本长度异常',
    injected_elements: '注入元素',
  };
  return m[t] || t;
}

const diffCols: DataTableColumns<any> = [
  {
    key: 'type',
    title: '变化类型',
    width: 160,
    render: (row) => diffTypeLabel(row.type),
  },
  {
    key: 'baseline',
    title: '基线值',
    minWidth: 160,
    ellipsis: { tooltip: true },
    render: (row) => {
      if (row.type === 'injected_elements') return '-';
      return String(row.baseline ?? '-');
    },
  },
  {
    key: 'current',
    title: '当前值',
    minWidth: 160,
    ellipsis: { tooltip: true },
    render: (row) => {
      if (row.type === 'injected_elements')
        return `${(row.elements || []).length} 个可疑元素`;
      return String(row.current ?? '-');
    },
  },
  {
    key: 'severity',
    title: '严重程度',
    width: 100,
    render: (row) => {
      if (row.type === 'injected_elements')
        return h(NTag, { type: 'error', size: 'small', bordered: false }, { default: () => '严重' });
      if (row.ratio != null && row.ratio > 0.5)
        return h(NTag, { type: 'error', size: 'small', bordered: false }, { default: () => '高危' });
      return h(NTag, { type: 'warning', size: 'small', bordered: false }, { default: () => '中危' });
    },
  },
];

const injectedElements = computed(() => {
  const inj = diffs.value.find((d: any) => d.type === 'injected_elements');
  return inj?.elements || [];
});

const injectedCols: DataTableColumns<any> = [
  { key: 'type', title: '类型', width: 120 },
  {
    key: 'src',
    title: '资源地址',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('span', { class: 'font-mono text-xs' }, row.src || '-'),
  },
  {
    key: 'domain',
    title: '域名',
    width: 180,
    ellipsis: { tooltip: true },
  },
];
</script>

<template>
  <div class="space-y-3">
    <NCard size="small" title="篡改检测结果">
      <NDescriptions :column="4" bordered size="small">
        <NDescriptionsItem label="是否篡改">
          <NTag
            :type="r.tampered ? 'error' : 'success'"
            size="small"
            :bordered="false"
          >
            {{ r.tampered ? '⚠ 检测到篡改' : '未检测到篡改' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem v-if="r.severity" label="严重程度">
          <NTag :type="sevTag(r.severity)" size="small" :bordered="false">
            {{ sevLabel(r.severity) }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="HTTP状态">
          <span class="font-mono">{{ r.status_code ?? '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="页面标题">
          {{ r.title || '-' }}
        </NDescriptionsItem>
        <NDescriptionsItem label="目标URL" :span="4">
          <span class="font-mono break-all text-xs">{{ r.url || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="内容Hash">
          <span class="font-mono text-xs">{{ r.content_hash || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="文本长度">
          {{ r.visible_text_length ?? '-' }} 字符
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard
      v-if="showCompareEvidence"
      size="small"
      :title="isFirstRun ? '基线内容（首次建立）' : '篡改对比证据'"
    >
      <p v-if="!isFirstRun" class="mb-2 text-xs text-gray-500">
        左侧为上一次基线内容（<span class="text-red-600">删除</span> 标记为本次移除部分）；
        右侧为本次抓取内容（<span class="text-green-600">新增</span> 标记为本次新增部分）。
      </p>
      <p v-else class="mb-2 text-xs text-gray-500">
        首次运行已保存以下全文作为后续篡改对比基线。
      </p>
      <p v-if="evidence?.truncated" class="mb-2 text-xs text-amber-600">
        内容较长，展示已截断。
      </p>
      <div
        class="grid gap-3"
        :class="isFirstRun ? 'grid-cols-1' : 'grid-cols-1 lg:grid-cols-2'"
      >
        <div v-if="!isFirstRun || evidence?.baseline_html">
          <div class="mb-1 text-xs font-medium text-gray-600">
            {{ isFirstRun ? '基线全文' : '上一次（基线）' }}
          </div>
          <div
            class="tp-evidence-scroll tp-evidence rounded border border-gray-200 bg-gray-50 p-3 text-sm leading-relaxed text-gray-800"
            v-html="evidence?.baseline_html || ''"
          />
        </div>
        <div v-if="!isFirstRun">
          <div class="mb-1 text-xs font-medium text-gray-600">
            这一次（当前）
          </div>
          <div
            class="tp-evidence-scroll tp-evidence rounded border border-gray-200 bg-gray-50 p-3 text-sm leading-relaxed text-gray-800"
            v-html="evidence?.current_html || ''"
          />
        </div>
      </div>
    </NCard>

    <NCard v-if="isFirstRun && !showCompareEvidence" size="small" title="首次运行">
      <div class="text-sm text-gray-500">
        首次运行，已建立基线。后续监测将以此为基准进行对比。
      </div>
      <NDescriptions
        v-if="baselineUpdate"
        :column="2"
        bordered
        size="small"
        class="mt-2"
      >
        <NDescriptionsItem label="基线Hash">
          <span class="font-mono text-xs">
            {{ baselineUpdate.content_hash || '-' }}
          </span>
        </NDescriptionsItem>
        <NDescriptionsItem label="基线标题">
          {{ baselineUpdate.title || '-' }}
        </NDescriptionsItem>
        <NDescriptionsItem label="基线状态码">
          {{ baselineUpdate.status_code ?? '-' }}
        </NDescriptionsItem>
        <NDescriptionsItem label="基线文本长度">
          {{ baselineUpdate.visible_text_length ?? '-' }} 字符
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard
      v-if="diffs.length > 0"
      size="small"
      :title="`变化详情（${diffs.length} 项）`"
    >
      <NDataTable
        :columns="diffCols"
        :data="diffs"
        size="small"
        :max-height="300"
      />
    </NCard>

    <NCard
      v-if="injectedElements.length > 0"
      size="small"
      :title="`可疑注入元素（${injectedElements.length} 项）`"
    >
      <NDataTable
        :columns="injectedCols"
        :data="injectedElements"
        size="small"
        :max-height="300"
      />
    </NCard>

    <NEmpty
      v-if="!r.tampered && !isFirstRun && diffs.length === 0"
      description="未检测到篡改"
      class="py-8"
    />
  </div>
</template>

<style scoped>
.tp-evidence-scroll {
  max-height: min(70vh, 520px);
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
}

.tp-evidence :deep(.tp-del) {
  background: #fee2e2;
  color: #b91c1c;
  text-decoration: line-through;
}

.tp-evidence :deep(.tp-ins) {
  background: #dcfce7;
  color: #15803d;
  font-weight: 600;
}
</style>
