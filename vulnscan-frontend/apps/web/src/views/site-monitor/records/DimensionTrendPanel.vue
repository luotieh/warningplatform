<script lang="ts" setup>
import type { TaskTrendResp } from '#/api/sitemonitor';

import { computed, ref, watch } from 'vue';

import { BarChart, LineChart } from 'echarts/charts';
import {
  GridComponent,
  LegendComponent,
  TooltipComponent,
} from 'echarts/components';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import VChart from 'vue-echarts';

import dayjs from 'dayjs';
import { NCol, NEmpty, NRow, NSelect, NSpin, NStatistic } from 'naive-ui';

import { getPathTaskTrend } from '#/api/sitemonitor';

const dimLabelMap: Record<string, string> = {
  availability: '可用性',
  tamper: '篡改监测',
  blacklink: '暗链监测',
  sensitive_word: '敏感词',
  sensitive_file: '敏感文件',
  domain_hijack: '域名劫持',
};

const dimOrder = [
  'availability',
  'tamper',
  'blacklink',
  'sensitive_word',
  'sensitive_file',
  'domain_hijack',
];

const ALL_COLOR_NORMAL = '#22c55e';
const ALL_COLOR_ISSUE = '#dc2626';
const ALL_COLOR_FAILED = '#9ca3af';

use([CanvasRenderer, LineChart, BarChart, GridComponent, TooltipComponent, LegendComponent]);

const props = defineProps<{
  pathTaskId: string;
  dimension: string;
  dimLabel: string;
  dimColor: string;
  filters: {
    hasIssue: string;
    disposition: string;
    status: string;
    dateRange: [number, number] | null;
  };
}>();

const trendHours = ref(24);
const trendLoading = ref(false);
const trendData = ref<TaskTrendResp | null>(null);

const trendHoursOptions = [
  { label: '近24小时', value: 24 },
  { label: '近3天', value: 72 },
  { label: '近7天', value: 168 },
  { label: '近30天', value: 720 },
];

function trendParams() {
  const p: Record<string, string | number> = {
    hours: trendHours.value,
    dimension: props.dimension === 'all' ? 'all' : props.dimension,
  };
  if (props.filters.hasIssue) p.has_issue = props.filters.hasIssue;
  if (props.filters.disposition) p.disposition = props.filters.disposition;
  if (props.filters.status) p.status = props.filters.status;
  if (props.filters.dateRange?.[0]) {
    p.time_start = dayjs(props.filters.dateRange[0]).format('YYYY-MM-DD HH:mm:ss');
  }
  if (props.filters.dateRange?.[1]) {
    p.time_end = dayjs(props.filters.dateRange[1]).format('YYYY-MM-DD HH:mm:ss');
  }
  return p;
}

async function loadTrend() {
  if (!props.pathTaskId) return;
  trendLoading.value = true;
  try {
    const res = await getPathTaskTrend(props.pathTaskId, trendParams());
    trendData.value = (res as any)?.data ?? res;
  } catch {
    trendData.value = null;
  } finally {
    trendLoading.value = false;
  }
}

watch(
  () => [props.pathTaskId, props.dimension, props.filters, trendHours.value],
  () => loadTrend(),
  { deep: true, immediate: true },
);

defineExpose({ reload: loadTrend });

const points = computed(() => trendData.value?.points || []);
const summary = computed(() => trendData.value?.summary || {});

const issueRate = computed(() => {
  const total = summary.value.total_checks ?? 0;
  const issue = summary.value.issue_count ?? 0;
  if (!total) return 0;
  return Math.round((issue / total) * 1000) / 10;
});

const dimAggregates = computed(() => {
  const map: Record<
    string,
    { total: number; issue: number; normal: number; failed: number }
  > = {};
  for (const p of points.value) {
    const d = p.dimension || 'unknown';
    if (!map[d]) map[d] = { total: 0, issue: 0, normal: 0, failed: 0 };
    map[d].total++;
    if (p.has_issue) map[d].issue++;
    else if (p.status === 'failed') map[d].failed++;
    else map[d].normal++;
  }
  return dimOrder
    .filter((k) => map[k]?.total)
    .map((k) => ({
      key: k,
      label: dimLabelMap[k] || k,
      ...map[k]!,
    }));
});

const hourlyBuckets = computed(() => {
  const map = new Map<string, { total: number; issue: number; failed: number }>();
  for (const p of points.value) {
    const key = p.time.length >= 13 ? p.time.slice(0, 13) : p.time;
    if (!map.has(key)) map.set(key, { total: 0, issue: 0, failed: 0 });
    const b = map.get(key)!;
    b.total++;
    if (p.has_issue) b.issue++;
    if (p.status === 'failed') b.failed++;
  }
  return [...map.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([time, v]) => ({ time, ...v }));
});

const hasChartData = computed(
  () =>
    props.dimension === 'all'
      ? dimAggregates.value.length > 0
      : points.value.length > 0,
);

/** 全部：各维度堆叠横向条（灰 + 红 + 深灰） */
const allDimStackOption = computed(() => {
  if (props.dimension !== 'all' || !dimAggregates.value.length) return null;
  const rows = dimAggregates.value;
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: {
      data: ['正常', '发现问题', '执行失败'],
      bottom: 0,
      textStyle: { fontSize: 11, color: '#6b7280' },
    },
    color: [ALL_COLOR_NORMAL, ALL_COLOR_ISSUE, ALL_COLOR_FAILED],
    grid: { left: 88, right: 24, top: 8, bottom: 36, containLabel: true },
    xAxis: { type: 'value', minInterval: 1, name: '次' },
    yAxis: {
      type: 'category',
      data: rows.map((d) => d.label),
      axisLabel: { fontSize: 11 },
    },
    series: [
      {
        name: '正常',
        type: 'bar',
        stack: 'total',
        data: rows.map((d) => d.normal),
        itemStyle: { color: ALL_COLOR_NORMAL },
      },
      {
        name: '发现问题',
        type: 'bar',
        stack: 'total',
        data: rows.map((d) => d.issue),
        itemStyle: { color: ALL_COLOR_ISSUE },
      },
      {
        name: '执行失败',
        type: 'bar',
        stack: 'total',
        data: rows.map((d) => d.failed),
        itemStyle: { color: ALL_COLOR_FAILED },
      },
    ],
  };
});

/** 单维度：按小时堆叠柱（绿/红/灰） */
const timeStackOption = computed(() => {
  if (props.dimension === 'availability' || props.dimension === 'all') return null;
  const buckets = hourlyBuckets.value;
  if (!buckets.length) return null;
  const rotate = buckets.length > 12 ? 35 : 0;
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { data: ['正常', '发现问题', '执行失败'], bottom: 0, textStyle: { fontSize: 11 } },
    grid: { left: 8, right: 12, top: 16, bottom: rotate ? 48 : 32, containLabel: true },
    xAxis: {
      type: 'category',
      data: buckets.map((b) => b.time),
      axisLabel: { fontSize: 10, rotate, interval: buckets.length > 24 ? 'auto' : 0 },
    },
    yAxis: { type: 'value', minInterval: 1, name: '次' },
    series: [
      {
        name: '正常',
        type: 'bar',
        stack: 'total',
        data: buckets.map((b) => Math.max(0, b.total - b.issue - b.failed)),
        itemStyle: { color: '#22c55e' },
      },
      {
        name: '发现问题',
        type: 'bar',
        stack: 'total',
        data: buckets.map((b) => b.issue),
        itemStyle: { color: '#ef4444' },
      },
      {
        name: '执行失败',
        type: 'bar',
        stack: 'total',
        data: buckets.map((b) => b.failed),
        itemStyle: { color: '#94a3b8' },
      },
    ],
  };
});

const availPct = computed(() => summary.value.availability_pct ?? 0);

const availPctClass = computed(() => {
  const v = availPct.value;
  if (v >= 99) return 'avail-rate--ok';
  if (v >= 95) return 'avail-rate--warn';
  return 'avail-rate--bad';
});

/** 可用性：绿/黄/红状态条 */
const availTimelineOption = computed(() => {
  if (props.dimension !== 'availability' || !points.value.length) return null;
  const rotate = points.value.length > 16 ? 35 : 0;
  return {
    tooltip: {
      trigger: 'axis',
      formatter: (params: any) => {
        const idx = params[0]?.dataIndex;
        const p = points.value[idx];
        if (!p) return '';
        if (p.available === false) return `${p.time}<br/>不可用`;
        if (p.has_issue) return `${p.time}<br/>有问题`;
        return `${p.time}<br/>正常`;
      },
    },
    grid: { left: 4, right: 8, top: 4, bottom: rotate ? 28 : 16, containLabel: true },
    xAxis: {
      type: 'category',
      data: points.value.map((p) => p.time),
      axisLabel: { show: false },
      axisTick: { show: false },
    },
    yAxis: { type: 'value', show: false, max: 1 },
    series: [
      {
        type: 'bar',
        data: points.value.map((p) => ({
          value: 1,
          itemStyle: {
            color:
              p.available === false ? '#ef4444' : p.has_issue ? '#f59e0b' : '#22c55e',
          },
        })),
        barMaxWidth: 4,
        barCategoryGap: '2%',
      },
    ],
  };
});

/** 可用性：解析 / DNS / 连接 / TLS / 首字节 分段耗时 */
const availTimingLineOption = computed(() => {
  if (props.dimension !== 'availability' || !points.value.length) return null;
  const rotate = points.value.length > 16 ? 35 : 0;
  const times = points.value.map((p) => p.time);
  const ms = (p: (typeof points.value)[0], key: keyof (typeof points.value)[0]) =>
    Number(p[key] ?? 0) || 0;

  return {
    tooltip: {
      trigger: 'axis',
      formatter: (params: any) => {
        if (!Array.isArray(params) || !params.length) return '';
        const lines = [params[0].axisValue];
        for (const item of params) {
          lines.push(`${item.marker}${item.seriesName}: ${item.value} ms`);
        }
        return lines.join('<br/>');
      },
    },
    legend: {
      type: 'scroll',
      data: ['解析', 'DNS', '连接', 'TLS', '首字节'],
      bottom: 4,
      left: 'center',
      orient: 'horizontal',
      itemWidth: 14,
      itemHeight: 8,
      itemGap: 18,
      width: '92%',
      padding: [4, 8, 4, 8],
      textStyle: { fontSize: 11 },
      pageIconSize: 10,
      pageTextStyle: { fontSize: 10 },
    },
    grid: {
      left: 52,
      right: 20,
      top: 12,
      bottom: rotate ? 78 : 58,
      containLabel: true,
    },
    xAxis: {
      type: 'category',
      data: times,
      axisLabel: { fontSize: 10, rotate, interval: times.length > 24 ? 'auto' : 0 },
    },
    yAxis: { type: 'value', name: 'ms', minInterval: 1, axisLabel: { fontSize: 10 } },
    series: [
      {
        name: '解析',
        type: 'line',
        data: points.value.map((p) => ms(p, 'dns_ms')),
        smooth: true,
        showSymbol: points.value.length <= 24,
        itemStyle: { color: '#3b82f6' },
        lineStyle: { width: 1.5 },
      },
      {
        name: 'DNS',
        type: 'line',
        data: points.value.map((p) => ms(p, 'dns_ms')),
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#22c55e' },
        lineStyle: { width: 1.5 },
      },
      {
        name: '连接',
        type: 'line',
        data: points.value.map((p) => ms(p, 'tcp_connect_ms')),
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#eab308' },
        lineStyle: { width: 1.5 },
      },
      {
        name: 'TLS',
        type: 'line',
        data: points.value.map((p) => ms(p, 'tls_handshake_ms')),
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#a855f7' },
        lineStyle: { width: 1.5 },
      },
      {
        name: '首字节',
        type: 'line',
        data: points.value.map((p) => ms(p, 'ttfb_ms')),
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#ef4444' },
        lineStyle: { width: 1.5 },
      },
    ],
  };
});
</script>

<template>
  <div class="dimension-trend-panel mb-4" :style="{ '--dim-color': dimColor }">
    <NSpin :show="trendLoading" size="small">
      <div class="panel-head">
        <div>
          <div class="panel-title">{{ dimLabel }}概览</div>
          <div class="panel-desc">
            <template v-if="dimension === 'all'">
              各维度检测构成：绿色为正常，红色为发现问题，灰色为执行失败
            </template>
            <template v-else-if="dimension === 'availability'">
              可用性概览：状态条与分段响应时间趋势
            </template>
            <template v-else>
              展示检测时间分布：正常、发现问题、执行失败（与上方筛选条件一致）
            </template>
          </div>
        </div>
        <NSelect
          v-model:value="trendHours"
          :options="trendHoursOptions"
          size="small"
          style="width: 120px"
        />
      </div>

      <template v-if="hasChartData">
        <div v-if="dimension === 'availability'" class="avail-summary mb-3">
          <div class="avail-summary__rate">
            <div class="avail-summary__rate-label">可用率</div>
            <div class="avail-rate" :class="availPctClass">
              {{ availPct.toFixed(1) }}%
            </div>
          </div>
          <NStatistic label="检测次数" :value="summary.total_checks ?? 0" tabular-nums />
          <NStatistic label="平均耗时" tabular-nums>
            <span class="font-mono">{{ (summary.avg_response_ms ?? 0).toFixed(0) }} ms</span>
          </NStatistic>
          <NStatistic label="最大耗时" tabular-nums>
            <span class="font-mono">{{ (summary.max_response_ms ?? 0).toFixed(0) }} ms</span>
          </NStatistic>
          <NStatistic label="最小耗时" tabular-nums>
            <span class="font-mono">{{ (summary.min_response_ms ?? 0).toFixed(0) }} ms</span>
          </NStatistic>
          <NStatistic label="发现问题" tabular-nums>
            <span :class="(summary.issue_count ?? 0) > 0 ? 'text-red-500' : 'text-green-500'">
              {{ summary.issue_count ?? 0 }}
            </span>
          </NStatistic>
        </div>
        <NRow v-else :gutter="12" class="mb-3 stat-row">
          <NCol :span="4">
            <NStatistic label="检测次数" :value="summary.total_checks ?? 0" tabular-nums />
          </NCol>
          <NCol :span="4">
            <NStatistic label="发现问题" tabular-nums>
              <span :class="(summary.issue_count ?? 0) > 0 ? 'text-red-500' : 'text-green-500'">
                {{ summary.issue_count ?? 0 }}
              </span>
            </NStatistic>
          </NCol>
          <NCol :span="4">
            <NStatistic label="成功" tabular-nums>
              <span class="text-green-600">{{ summary.success_count ?? 0 }}</span>
            </NStatistic>
          </NCol>
          <NCol :span="4">
            <NStatistic label="失败" tabular-nums>
              <span class="text-red-500">{{ summary.failed_count ?? 0 }}</span>
            </NStatistic>
          </NCol>
          <NCol :span="4">
            <NStatistic label="问题率" tabular-nums>
              <span :class="issueRate > 0 ? 'text-red-500' : 'text-green-500'">{{ issueRate }}%</span>
            </NStatistic>
          </NCol>
        </NRow>

        <template v-if="dimension === 'all'">
          <div v-if="allDimStackOption" class="chart-block">
            <div class="chart-caption">各维度检测构成</div>
            <VChart :option="allDimStackOption" class="chart-lg" autoresize />
          </div>
        </template>

        <template v-else-if="dimension === 'availability'">
          <div v-if="availTimelineOption" class="chart-block">
            <div class="chart-caption">可用性状态（绿=正常 黄=有问题 红=不可用）</div>
            <VChart :option="availTimelineOption" class="chart-status" autoresize />
          </div>
          <div v-if="availTimingLineOption" class="chart-block chart-block--timing">
            <div class="chart-caption">响应时间趋势</div>
            <VChart :option="availTimingLineOption" class="chart-timing" autoresize />
          </div>
        </template>

        <template v-else>
          <div v-if="timeStackOption" class="chart-block">
            <div class="chart-caption">检测时间分布（按小时）</div>
            <VChart :option="timeStackOption" class="chart-md" autoresize />
          </div>
        </template>
      </template>

      <NEmpty v-else :description="`当前筛选条件下暂无${dimLabel}数据`" />
    </NSpin>
  </div>
</template>

<style scoped>
.dimension-trend-panel {
  padding: 14px 16px;
  background: var(--n-color-embedded);
  border-radius: 8px;
  border-left: 3px solid var(--dim-color);
  overflow: visible;
}

.panel-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.panel-title {
  font-size: 14px;
  font-weight: 600;
}

.panel-desc {
  margin-top: 4px;
  font-size: 12px;
  color: var(--n-text-color-3);
  line-height: 1.5;
}

.stat-highlight {
  font-size: 18px;
  font-weight: 600;
}

.chart-block {
  margin-bottom: 12px;
  overflow: visible;
}

.chart-block--timing {
  overflow: visible;
  padding-bottom: 6px;
}

.chart-caption {
  margin-bottom: 6px;
  font-size: 12px;
  font-weight: 500;
  color: var(--n-text-color-2);
}

.avail-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: 20px 28px;
}

.avail-summary__rate-label {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 4px;
}

.avail-rate {
  font-size: 28px;
  font-weight: 700;
  line-height: 1.1;
}

.avail-rate--ok {
  color: #22c55e;
}

.avail-rate--warn {
  color: #eab308;
}

.avail-rate--bad {
  color: #ef4444;
}

.avail-summary :deep(.n-statistic-label) {
  font-size: 12px;
}

.avail-summary :deep(.n-statistic-value) {
  font-size: 16px;
  font-weight: 600;
}

.chart-status {
  height: 48px;
  width: 100%;
}

.chart-md {
  height: 240px;
  width: 100%;
}

.chart-timing {
  height: 300px;
  width: 100%;
  min-height: 300px;
  overflow: visible;
}

.chart-lg {
  height: 280px;
  width: 100%;
}
</style>
