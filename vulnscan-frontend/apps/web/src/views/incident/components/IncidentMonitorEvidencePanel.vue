<script lang="ts" setup>
import type { MonitorExecution } from '#/api/sitemonitor';

import { computed } from 'vue';

import { NAlert, NCard, NCollapse, NCollapseItem, NEmpty, NInput, NSpin } from 'naive-ui';

import AvailabilityDetail from '../../site-monitor/executions/components/AvailabilityDetail.vue';
import BlacklinkDetail from '../../site-monitor/executions/components/BlacklinkDetail.vue';
import DomainHijackDetail from '../../site-monitor/executions/components/DomainHijackDetail.vue';
import SensitiveFileDetail from '../../site-monitor/executions/components/SensitiveFileDetail.vue';
import SensitiveWordDetail from '../../site-monitor/executions/components/SensitiveWordDetail.vue';
import TamperDetail from '../../site-monitor/executions/components/TamperDetail.vue';

const props = defineProps<{
  execution: MonitorExecution | null;
  result: any;
  loading?: boolean;
  error?: string;
  textDetailFallback?: string;
}>();

const dimension = computed(() => props.execution?.dimension);
const executionId = computed(() => props.execution?.id || '');

const hasVisualEvidence = computed(() => {
  if (!props.result || !dimension.value) return false;
  if (dimension.value === 'tamper') {
    const ev = props.result.evidence;
    return Boolean(ev?.baseline_html || ev?.current_html || props.result.diffs?.length);
  }
  if (dimension.value === 'sensitive_word') {
    return Boolean(
      props.result.matches?.length || props.result.page_evidence_html,
    );
  }
  return true;
});
</script>

<template>
  <NSpin :show="loading">
    <NAlert v-if="error" type="warning" class="mb-3" :bordered="false">
      {{ error }}。已回退展示文本版证据。
    </NAlert>

    <template v-if="execution && result && hasVisualEvidence">
      <p class="text-muted-foreground mb-3 text-xs">
        以下与「站点监测 → 执行记录」中相同的可视化证据（左右对比、颜色标注）。
      </p>
      <AvailabilityDetail
        v-if="dimension === 'availability'"
        :result="result"
        class="mb-3"
      />
      <TamperDetail
        v-else-if="dimension === 'tamper'"
        :result="result"
        :execution-id="executionId"
        class="mb-3"
      />
      <BlacklinkDetail
        v-else-if="dimension === 'blacklink'"
        :result="result"
        class="mb-3"
      />
      <SensitiveWordDetail
        v-else-if="dimension === 'sensitive_word'"
        :result="result"
        class="mb-3"
      />
      <SensitiveFileDetail
        v-else-if="dimension === 'sensitive_file'"
        :result="result"
        class="mb-3"
      />
      <DomainHijackDetail
        v-else-if="dimension === 'domain_hijack'"
        :result="result"
        class="mb-3"
      />
    </template>

    <NEmpty
      v-else-if="execution && !loading && !hasVisualEvidence"
      description="该次执行无结构化可视化证据"
      class="py-6"
    />

    <NCard
      v-if="textDetailFallback"
      size="small"
      class="mt-3"
      title="文本版证据（通报 / PDF 导出）"
    >
      <NCollapse>
        <NCollapseItem name="text" title="展开查看纯文本详细证据">
          <pre class="incident-text-detail-pre">{{ textDetailFallback }}</pre>
        </NCollapseItem>
      </NCollapse>
    </NCard>
  </NSpin>
</template>

<style scoped>
.incident-text-detail-pre {
  margin: 0;
  max-height: 360px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.65;
}
</style>
