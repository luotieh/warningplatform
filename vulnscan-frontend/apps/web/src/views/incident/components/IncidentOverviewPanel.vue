<script lang="ts" setup>
import type { MonitorExecution } from '#/api/sitemonitor';
import type { SecurityIncident } from '#/api/incident';

import { computed } from 'vue';

import { NAlert, NCard, NEmpty, NSpin } from 'naive-ui';

import {
  buildIncidentOverviewStats,
  type OverviewStatItem,
} from './incident-overview-stats';

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

function cellClass(item: OverviewStatItem) {
  return [
    'overview-cell',
    item.highlight ? `overview-cell--${item.highlight}` : '',
  ];
}

function valueClass(item: OverviewStatItem) {
  return [
    'overview-cell__value',
    item.mono ? 'overview-cell__value--mono' : '',
    item.highlight ? `overview-cell__value--${item.highlight}` : '',
  ];
}
</script>

<template>
  <NCard title="统计概览" size="small" class="incident-overview-card">
    <NSpin :show="monitorLoading">
      <NAlert
        v-if="monitorError && isMonitorSource"
        type="warning"
        class="overview-alert"
        :bordered="false"
      >
        监测数据加载失败：{{ monitorError }}
      </NAlert>

      <div v-if="overview.targetUrl" class="overview-url">
        <span class="overview-section-title">监测目标</span>
        <div class="overview-url__value">{{ overview.targetUrl }}</div>
      </div>

      <section v-if="overview.primary.length" class="overview-section">
        <div class="overview-section-title">事件摘要</div>
        <div class="overview-grid">
          <div
            v-for="(item, idx) in overview.primary"
            :key="`p-${idx}`"
            :class="cellClass(item)"
          >
            <span class="overview-cell__label">{{ item.label }}</span>
            <span :class="valueClass(item)">{{ item.value }}</span>
          </div>
        </div>
      </section>

      <section v-if="overview.monitor.length" class="overview-section">
        <div class="overview-section-title">监测结果</div>
        <div class="overview-grid">
          <div
            v-for="(item, idx) in overview.monitor"
            :key="`m-${idx}`"
            :class="cellClass(item)"
          >
            <span class="overview-cell__label">{{ item.label }}</span>
            <span :class="valueClass(item)">{{ item.value }}</span>
          </div>
        </div>
      </section>

      <section v-if="overview.vuln.length" class="overview-section">
        <div class="overview-section-title">漏洞信息</div>
        <div class="overview-grid">
          <div
            v-for="(item, idx) in overview.vuln"
            :key="`v-${idx}`"
            :class="cellClass(item)"
          >
            <span class="overview-cell__label">{{ item.label }}</span>
            <span :class="valueClass(item)">{{ item.value }}</span>
          </div>
        </div>
      </section>

      <section v-if="overview.asset.length" class="overview-section">
        <div class="overview-section-title">资产信息</div>
        <div class="overview-grid">
          <div
            v-for="(item, idx) in overview.asset"
            :key="`a-${idx}`"
            class="overview-cell"
          >
            <span class="overview-cell__label">{{ item.label }}</span>
            <span :class="valueClass(item)">{{ item.value }}</span>
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
        class="overview-empty"
      />
    </NSpin>
  </NCard>
</template>

<style scoped>
.incident-overview-card :deep(.n-card__content) {
  padding-top: 12px;
}

.overview-alert {
  margin-bottom: 12px;
}

.overview-section {
  margin-bottom: 16px;
}

.overview-section:last-child {
  margin-bottom: 0;
}

.overview-section-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--n-text-color);
  margin-bottom: 10px;
}

.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 10px;
}

.overview-cell {
  padding: 10px 12px;
  border-radius: 8px;
  border: 1px solid var(--n-border-color);
  background: var(--n-action-color);
  min-height: 60px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 6px;
  transition: border-color 0.2s ease;
}

.overview-cell__label {
  font-size: 12px;
  line-height: 1.4;
  color: var(--n-text-color-3);
}

.overview-cell__value {
  font-size: 14px;
  font-weight: 500;
  line-height: 1.45;
  color: var(--n-text-color);
  word-break: break-word;
}

.overview-cell__value--mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  font-weight: 400;
}

.overview-cell__value--error {
  color: var(--n-error-color);
  font-weight: 600;
}

.overview-cell__value--success {
  color: var(--n-success-color);
  font-weight: 600;
}

.overview-cell__value--warning {
  color: var(--n-warning-color);
  font-weight: 600;
}

.overview-cell__value--info {
  color: var(--n-info-color);
  font-weight: 600;
}

.overview-cell--error {
  border-color: color-mix(in srgb, var(--n-error-color) 28%, var(--n-border-color));
  background: color-mix(in srgb, var(--n-error-color) 6%, var(--n-action-color));
}

.overview-cell--success {
  border-color: color-mix(in srgb, var(--n-success-color) 28%, var(--n-border-color));
  background: color-mix(in srgb, var(--n-success-color) 6%, var(--n-action-color));
}

.overview-cell--warning {
  border-color: color-mix(in srgb, var(--n-warning-color) 28%, var(--n-border-color));
  background: color-mix(in srgb, var(--n-warning-color) 6%, var(--n-action-color));
}

.overview-cell--info {
  border-color: color-mix(in srgb, var(--n-info-color) 22%, var(--n-border-color));
  background: color-mix(in srgb, var(--n-info-color) 5%, var(--n-action-color));
}

.overview-url {
  margin-bottom: 16px;
  padding: 12px 14px;
  border-radius: 8px;
  background: var(--n-action-color);
  border: 1px solid var(--n-border-color);
}

.overview-url__value {
  margin-top: 8px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.55;
  color: var(--n-text-color-2);
  word-break: break-all;
}

.overview-empty {
  padding: 24px 0;
}
</style>
