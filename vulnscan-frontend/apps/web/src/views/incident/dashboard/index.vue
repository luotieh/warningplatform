<script lang="ts" setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue';

import { EchartsUI, useEcharts } from '@vben/plugins/echarts';
import type { EchartsUIType } from '@vben/plugins/echarts';
import {
  NCard,
  NDataTable,
  NEmpty,
  NGrid,
  NGridItem,
  NSpin,
  NStatistic,
  useThemeVars,
} from 'naive-ui';

import {
  getChartByLevel,
  getChartByTrend,
  getChartByType,
  getDashboardStats,
  getSLAOverview,
  type ChartLevelItem,
  type ChartTrendItem,
  type ChartTypeItem,
  type DashboardStats,
  type SLAOverview,
} from '#/api/incident';

defineOptions({ name: 'IncidentDashboard' });

const themeVars = useThemeVars();
const loading = ref(true);
const stats = ref<DashboardStats | null>(null);
const typeData = ref<ChartTypeItem[]>([]);
const levelData = ref<ChartLevelItem[]>([]);
const trendData = ref<ChartTrendItem[]>([]);
const slaOverview = ref<SLAOverview | null>(null);

const typeChartRef = ref<EchartsUIType>();
const levelChartRef = ref<EchartsUIType>();
const trendChartRef = ref<EchartsUIType>();
const { renderEcharts: renderTypeChart } = useEcharts(typeChartRef);
const { renderEcharts: renderLevelChart } = useEcharts(levelChartRef);
const { renderEcharts: renderTrendChart } = useEcharts(trendChartRef);

const typePalette = ['#2080f0', '#18a058', '#f0a020', '#d03050', '#8b5cf6', '#64748b'];

const typeColumns = [
  { title: '事件类型', key: 'type', minWidth: 150 },
  { title: '数量', key: 'count', width: 100 },
  { title: '占比', key: 'percentage', width: 100 },
];

const levelColumns = [
  { title: '等级', key: 'label', minWidth: 100 },
  { title: '数量', key: 'count', width: 100 },
  { title: '占比', key: 'percentage', width: 100 },
];

const trendColumns = [
  { title: '时间', key: 'period', minWidth: 100 },
  { title: '新增', key: 'created', width: 80 },
  { title: '已关闭', key: 'closed', width: 80 },
  { title: '待处理', key: 'pending', width: 80 },
];

const summaryCards = computed(() => {
  const s = stats.value;
  if (!s) return [];
  return [
    { label: '事件总数', value: s.total ?? 0, color: '#64748b' },
    { label: '待审核', value: s.pending_audit ?? 0, color: '#f0a020' },
    { label: '整改中', value: s.in_remediation ?? 0, color: '#2080f0' },
    { label: '已关闭', value: s.closed ?? 0, color: '#18a058' },
    { label: '超期', value: s.overdue ?? 0, color: '#d03050' },
  ];
});

const hasTypeChart = computed(() => typeData.value.some((item) => item.count > 0));
const hasLevelChart = computed(() => levelData.value.some((item) => item.count > 0));
const hasTrendChart = computed(() => trendData.value.length > 0);
const hasSlaData = computed(() => {
  const sla = slaOverview.value;
  return Boolean(sla && sla.total > 0);
});

function normalizeSLA(raw: Record<string, unknown> | null | undefined): SLAOverview | null {
  if (!raw) return null;
  const total = Number(raw.total ?? raw.total_tracked ?? 0);
  const within = Number(raw.within_sla ?? raw.normal_count ?? 0);
  const breached = Number(raw.breached ?? raw.breached_count ?? 0);
  let breachRate = Number(raw.breach_rate);
  if (Number.isNaN(breachRate) && total > 0) {
    breachRate = breached / total;
  }
  return { total, within_sla: within, breached, breach_rate: breachRate };
}

function normalizeStats(raw: Record<string, unknown>): DashboardStats {
  return {
    total: Number(raw.total ?? 0),
    pending_audit: Number(raw.pending_audit ?? 0),
    in_remediation: Number(raw.in_remediation ?? raw.remediating_count ?? 0),
    closed: Number(raw.closed ?? raw.closed_count ?? 0),
    overdue: Number(raw.overdue ?? raw.overdue_count ?? 0),
    today_total: Number(raw.today_total ?? 0),
    urgent_count: Number(raw.urgent_count ?? 0),
    remediation_rate: Number(raw.remediation_rate ?? 0),
  };
}

function renderCharts() {
  const textColor = themeVars.value.textColor2;
  const borderColor = themeVars.value.borderColor;
  const axisColor = themeVars.value.textColor3;

  if (hasTypeChart.value) {
    const pieData = typeData.value
      .filter((item) => item.count > 0)
      .map((item) => ({ name: item.type || '未分类', value: item.count }));
    renderTypeChart({
      color: typePalette,
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: { bottom: 0, textStyle: { color: textColor } },
      series: [
        {
          type: 'pie',
          radius: ['42%', '66%'],
          center: ['50%', '44%'],
          label: { color: textColor, formatter: '{b}\n{c}' },
          itemStyle: { borderColor, borderWidth: 2 },
          data: pieData,
        },
      ],
    });
  }

  if (hasLevelChart.value) {
    renderLevelChart({
      color: ['#2080f0'],
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      grid: { left: 48, right: 16, top: 24, bottom: 40 },
      xAxis: {
        type: 'category',
        data: levelData.value.map((item) => item.label),
        axisLine: { lineStyle: { color: borderColor } },
        axisLabel: { color: axisColor },
      },
      yAxis: {
        type: 'value',
        minInterval: 1,
        splitLine: { lineStyle: { color: borderColor } },
        axisLabel: { color: axisColor },
      },
      series: [
        {
          type: 'bar',
          barMaxWidth: 40,
          data: levelData.value.map((item) => item.count),
          itemStyle: { borderRadius: [6, 6, 0, 0] },
        },
      ],
    });
  }

  if (hasTrendChart.value) {
    renderTrendChart({
      tooltip: { trigger: 'axis' },
      legend: {
        bottom: 0,
        textStyle: { color: textColor },
        data: ['新增', '已关闭', '待处理'],
      },
      grid: { left: 48, right: 16, top: 24, bottom: 56 },
      xAxis: {
        type: 'category',
        data: trendData.value.map((item) => item.period),
        axisLine: { lineStyle: { color: borderColor } },
        axisLabel: { color: axisColor },
      },
      yAxis: {
        type: 'value',
        minInterval: 1,
        splitLine: { lineStyle: { color: borderColor } },
        axisLabel: { color: axisColor },
      },
      series: [
        {
          name: '新增',
          type: 'line',
          smooth: true,
          data: trendData.value.map((item) => item.created),
          itemStyle: { color: '#2080f0' },
        },
        {
          name: '已关闭',
          type: 'line',
          smooth: true,
          data: trendData.value.map((item) => item.closed),
          itemStyle: { color: '#18a058' },
        },
        {
          name: '待处理',
          type: 'line',
          smooth: true,
          data: trendData.value.map((item) => item.pending),
          itemStyle: { color: '#f0a020' },
        },
      ],
    });
  }
}

async function fetchData() {
  loading.value = true;
  try {
    const [s, t, lv, tr, sla] = await Promise.allSettled([
      getDashboardStats(),
      getChartByType(),
      getChartByLevel(),
      getChartByTrend(),
      getSLAOverview(),
    ]);
    if (s.status === 'fulfilled') {
      stats.value = normalizeStats((s.value ?? {}) as Record<string, unknown>);
    }
    if (t.status === 'fulfilled') typeData.value = t.value ?? [];
    if (lv.status === 'fulfilled') levelData.value = lv.value ?? [];
    if (tr.status === 'fulfilled') trendData.value = tr.value ?? [];
    if (sla.status === 'fulfilled') {
      slaOverview.value = normalizeSLA(sla.value as Record<string, unknown>);
    }
    await nextTick();
    renderCharts();
  } finally {
    loading.value = false;
  }
}

watch(
  () => themeVars.value,
  () => {
    if (!loading.value) {
      nextTick(renderCharts);
    }
  },
  { deep: true },
);

onMounted(fetchData);
</script>

<template>
  <div class="incident-dashboard">
    <NSpin :show="loading">
      <NCard title="统计概览" size="small" class="mb-4">
        <NGrid v-if="summaryCards.length" :cols="5" :x-gap="12" responsive="screen" item-responsive>
          <NGridItem v-for="card in summaryCards" :key="card.label" span="5 m:1">
            <div class="summary-cell">
              <span class="summary-dot" :style="{ background: card.color }" />
              <NStatistic :label="card.label" :value="card.value" tabular-nums />
            </div>
          </NGridItem>
        </NGrid>
        <NEmpty v-else description="暂无事件统计数据" class="py-8" />
      </NCard>

      <NGrid :cols="2" :x-gap="12" :y-gap="12" responsive="screen" class="mb-4">
        <NGridItem span="2 m:1">
          <NCard title="事件类型分布" size="small">
            <div v-if="hasTypeChart" class="chart-wrap">
              <EchartsUI ref="typeChartRef" height="280px" />
            </div>
            <NDataTable
              v-if="hasTypeChart"
              class="mt-3"
              :columns="typeColumns"
              :data="typeData"
              :bordered="false"
              size="small"
              :max-height="160"
            />
            <NEmpty v-else description="暂无类型分布数据" class="py-10" />
          </NCard>
        </NGridItem>
        <NGridItem span="2 m:1">
          <NCard title="事件等级分布" size="small">
            <div v-if="hasLevelChart" class="chart-wrap">
              <EchartsUI ref="levelChartRef" height="280px" />
            </div>
            <NDataTable
              v-if="hasLevelChart"
              class="mt-3"
              :columns="levelColumns"
              :data="levelData"
              :bordered="false"
              size="small"
              :max-height="160"
            />
            <NEmpty v-else description="暂无等级分布数据" class="py-10" />
          </NCard>
        </NGridItem>
      </NGrid>

      <NCard title="事件趋势（近 7 日）" size="small" class="mb-4">
        <div v-if="hasTrendChart" class="chart-wrap trend-chart">
          <EchartsUI ref="trendChartRef" height="300px" />
        </div>
        <NDataTable
          v-if="hasTrendChart"
          class="mt-3"
          :columns="trendColumns"
          :data="trendData"
          :bordered="false"
          size="small"
          :max-height="200"
        />
        <NEmpty v-else description="暂无趋势数据" class="py-10" />
      </NCard>

      <NCard v-if="hasSlaData" title="SLA 概览" size="small">
        <NGrid :cols="4" :x-gap="12" responsive="screen" item-responsive>
          <NGridItem span="4 m:1">
            <NStatistic label="SLA 跟踪总数" :value="slaOverview!.total" tabular-nums />
          </NGridItem>
          <NGridItem span="4 m:1">
            <NStatistic label="达标数" :value="slaOverview!.within_sla" tabular-nums />
          </NGridItem>
          <NGridItem span="4 m:1">
            <NStatistic label="违约数" :value="slaOverview!.breached" tabular-nums />
          </NGridItem>
          <NGridItem span="4 m:1">
            <NStatistic label="违约率" tabular-nums>
              {{ ((slaOverview!.breach_rate ?? 0) * 100).toFixed(1) }}%
            </NStatistic>
          </NGridItem>
        </NGrid>
      </NCard>
    </NSpin>
  </div>
</template>

<style scoped>
.incident-dashboard {
  padding: 16px;
}
.summary-cell {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 12px;
  border: 1px solid var(--n-border-color);
  border-radius: 8px;
  background: var(--n-color);
}
.summary-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-top: 6px;
  flex-shrink: 0;
}
.chart-wrap {
  min-height: 280px;
}
.trend-chart {
  min-height: 300px;
}
.mb-4 {
  margin-bottom: 16px;
}
.mt-3 {
  margin-top: 12px;
}
</style>
