<script lang="ts" setup>
import type { MonitorExecution } from '#/api/sitemonitor';
import type { SecurityIncident } from '#/api/incident';

import { computed } from 'vue';

import { NAlert, NCard, NEmpty, NSpin, NTag } from 'naive-ui';

import { buildIncidentOverviewStats, type OverviewHighlight } from './incident-overview-stats';

const props = defineProps<{
  incident: SecurityIncident;
  formatTime: (t?: string) => string;
  monitorExecution?: MonitorExecution | null;
  monitorResult?: Record<string, any> | null;
  monitorLoading?: boolean;
  monitorError?: string;
  isMonitorSource?: boolean;
}>();

const overview = computed(() =>
  buildIncidentOverviewStats(props.incident, {
    monitorExecution: props.monitorExecution,
    monitorResult: props.monitorResult,
    formatTime: props.formatTime,
  }),
);

function tagType(h?: OverviewHighlight) {
  if (h === 'error') return 'error';
  if (h === 'success') return 'success';
  if (h === 'warning') return 'warning';
  if (h === 'info') return 'info';
  return 'default';
}
</script>

<template>
  <NCard title="统计概览" size="small">
    <NSpin :show="monitorLoading">
      <NAlert
        v-if="monitorError && isMonitorSource"
        type="warning"
        class="mb-3"
        :bordered="false"
      >
        监测数据加载失败：{{ monitorError }}
      </NAlert>

      <div v-if="overview.targetUrl" class="overview-url mb-4">
        <span class="overview-section-label">监测目标</span>
        <div class="overview-url__value">{{ overview.targetUrl }}</div>
      </div>

      <section v-if="overview.primary.length" class="overview-section">
        <div class="overview-section-label">事件摘要</div>
        <div class="overview-grid">
          <div
            v-for="(item, idx) in overview.primary"
            :key="`p-${idx}`"
            class="overview-cell"
          >
            <span class="overview-cell__label">{{ item.label }}</span>
            <NTag
              v-if="item.highlight"
              :type="tagType(item.highlight)"
              size="small"
              :bordered="false"
            >
              {{ item.value }}
            </NTag>
            <span
              v-else
              class="overview-cell__value"
              :class="{ 'overview-cell__value--mono': item.mono }"
            >{{ item.value }}</span>
          </div>
        </div>
      </section>

      <section v-if="overview.monitor.length" class="overview-section">
        <div class="overview-section-label">监测结果</div>
        <div class="overview-grid">
          <div
            v-for="(item, idx) in overview.monitor"
            :key="`m-${idx}`"
            class="overview-cell"
          >
            <span class="overview-cell__label">{{ item.label }}</span>
            <NTag
              v-if="item.highlight"
              :type="tagType(item.highlight)"
              size="small"
              :bordered="false"
            >
              {{ item.value }}
            </NTag>
            <span
              v-else
              class="overview-cell__value"
              :class="{ 'overview-cell__value--mono': item.mono }"
            >{{ item.value }}</span>
          </div>
        </div>
      </section>

      <section v-if="overview.vuln.length" class="overview-section">
        <div class="overview-section-label">漏洞信息</div>
        <div class="overview-grid">
          <div
            v-for="(item, idx) in overview.vuln"
            :key="`v-${idx}`"
            class="overview-cell"
          >
            <span class="overview-cell__label">{{ item.label }}</span>
            <NTag
              v-if="item.highlight"
              :type="tagType(item.highlight)"
              size="small"
              :bordered="false"
            >
              {{ item.value }}
            </NTag>
            <span v-else class="overview-cell__value">{{ item.value }}</span>
          </div>
        </div>
      </section>

      <section v-if="overview.asset.length" class="overview-section">
        <div class="overview-section-label">资产信息</div>
        <div class="overview-grid">
          <div
            v-for="(item, idx) in overview.asset"
            :key="`a-${idx}`"
            class="overview-cell"
          >
            <span class="overview-cell__label">{{ item.label }}</span>
            <span
              class="overview-cell__value"
              :class="{ 'overview-cell__value--mono': item.mono }"
            >{{ item.value }}</span>
          </div>
        </div>
      </section>

      <NEmpty
        v-if="
          !overview.primary.length &&
            !overview.monitor.length &&
            !overview.asset.length &&
            !overview.vuln.length &&
            !monitorLoading
        "
        description="暂无可用统计数据"
        class="py-6"
      />
    </NSpin>
  </NCard>
</template>

<style scoped>
.overview-section {
  margin-bottom: 16px;
}
.overview-section:last-child {
  margin-bottom: 0;
}
.overview-section-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--n-text-color-3);
  margin-bottom: 10px;
}
.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 10px;
}
.overview-cell {
  padding: 10px 12px;
  border-radius: 6px;
  border: 1px solid var(--n-border-color);
  background: var(--n-color);
  min-height: 64px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 6px;
}
.overview-cell__label {
  font-size: 12px;
  color: var(--n-text-color-3);
}
.overview-cell__value {
  font-size: 14px;
  font-weight: 500;
  word-break: break-word;
}
.overview-cell__value--mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  font-weight: 400;
}
.overview-url {
  padding: 10px 12px;
  border-radius: 6px;
  background: var(--n-color-modal);
  border: 1px solid var(--n-border-color);
}
.overview-url__value {
  margin-top: 6px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  word-break: break-all;
  line-height: 1.5;
}
</style>
