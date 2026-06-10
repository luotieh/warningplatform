<script lang="ts" setup>
import { computed, h, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';

import { EchartsUI, useEcharts } from '@vben/plugins/echarts';
import type { EchartsUIType } from '@vben/plugins/echarts';
import type { DataTableColumns } from 'naive-ui';
import {
  NButton,
  NCard,
  NDataTable,
  NEmpty,
  NGrid,
  NGridItem,
  NSelect,
  NSpace,
  NSpin,
  NStatistic,
  NTag,
  useMessage,
} from 'naive-ui';

import {
  downloadIncidentReport,
  getAIAnalysis,
  getMultiDimAnalysis,
  getOverdueList,
  getRemediationStats,
  getTrendPrediction,
  type AIAnalysisSummary,
  type MultiDimItem,
  type RemediationStats,
  type SecurityIncident,
  type TrendPrediction,
} from '#/api/incident';

defineOptions({ name: 'IncidentReports' });

const message = useMessage();
const loading = ref(true);
const downloading = ref(false);

const isDark = ref(document.documentElement.classList.contains('dark'));
let themeObserver: MutationObserver | null = null;

onMounted(() => {
  themeObserver = new MutationObserver(() => {
    const nowDark = document.documentElement.classList.contains('dark');
    if (nowDark !== isDark.value) {
      isDark.value = nowDark;
    }
  });
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
});

onUnmounted(() => {
  themeObserver?.disconnect();
});

const remediation = ref<RemediationStats | null>(null);
const overdueItems = ref<SecurityIncident[]>([]);
const dimensionData = ref<MultiDimItem[]>([]);
const trendData = ref<TrendPrediction | null>(null);
const aiData = ref<AIAnalysisSummary | null>(null);

const dimension = ref<'incident_type' | 'level' | 'source' | 'status'>('level');
const reportPeriod = ref<'month' | 'quarter'>('month');
const reportYear = ref(new Date().getFullYear());
const reportValue = ref(new Date().getMonth() + 1);

const dimensionChartRef = ref<EchartsUIType>();
const trendChartRef = ref<EchartsUIType>();
const hotCategoryChartRef = ref<EchartsUIType>();
const { renderEcharts: renderDimensionChart } = useEcharts(dimensionChartRef);
const { renderEcharts: renderTrendChart } = useEcharts(trendChartRef);
const { renderEcharts: renderHotCategoryChart } = useEcharts(hotCategoryChartRef);

const periodOptions = [
  { label: '月报', value: 'month' },
  { label: '季报', value: 'quarter' },
];

const yearOptions = computed(() => {
  const currentYear = new Date().getFullYear();
  return Array.from({ length: 5 }, (_, index) => ({
    label: `${currentYear - index} 年`,
    value: currentYear - index,
  }));
});

const valueOptions = computed(() => {
  if (reportPeriod.value === 'quarter') {
    return [
      { label: '第 1 季度', value: 1 },
      { label: '第 2 季度', value: 2 },
      { label: '第 3 季度', value: 3 },
      { label: '第 4 季度', value: 4 },
    ];
  }
  return Array.from({ length: 12 }, (_, index) => ({
    label: `${index + 1} 月`,
    value: index + 1,
  }));
});

const dimensionOptions = [
  { label: '按等级分析', value: 'level' },
  { label: '按来源分析', value: 'source' },
  { label: '按状态分析', value: 'status' },
  { label: '按事件类型分析', value: 'incident_type' },
];

const overdueColumns = computed<DataTableColumns<SecurityIncident>>(() => [
  {
    title: '事件编号',
    key: 'incident_no',
    width: 170,
  },
  {
    title: '事件名称',
    key: 'name',
    minWidth: 220,
    ellipsis: { tooltip: true },
  },
  {
    title: '等级',
    key: 'level',
    width: 90,
    align: 'center',
    render: (row) => renderLevelTag(row.level),
  },
  {
    title: '状态',
    key: 'status_text',
    width: 110,
    align: 'center',
    render: (row) => row.status_text || statusLabel(row.status),
  },
  {
    title: '资产',
    key: 'asset_name',
    minWidth: 180,
    ellipsis: { tooltip: true },
    render: (row) => row.asset_name || '-',
  },
  {
    title: '所属单位',
    key: 'unit',
    minWidth: 180,
    ellipsis: { tooltip: true },
    render: (row) => row.unit || '-',
  },
  {
    title: '整改截止',
    key: 'remediation_deadline',
    width: 180,
    render: (row) => formatTime(row.remediation_deadline),
  },
]);

onMounted(async () => {
  await loadAll();
});

watch(dimension, async () => {
  await loadDimension();
});

watch(isDark, () => {
  nextTick(() => renderCharts());
});

watch(reportPeriod, () => {
  const currentMonth = new Date().getMonth() + 1;
  reportValue.value = reportPeriod.value === 'quarter' ? Math.ceil(currentMonth / 3) : currentMonth;
});

async function loadAll() {
  loading.value = true;
  try {
    const [remediationResult, overdueResult, trendResult, aiResult] = await Promise.all([
      getRemediationStats(),
      getOverdueList({ page: 1, page_size: 10 }),
      getTrendPrediction({ range_type: '30d', predict_days: 7 }),
      getAIAnalysis(),
    ]);

    remediation.value = remediationResult;
    overdueItems.value = overdueResult.items;
    trendData.value = trendResult;
    aiData.value = aiResult;

    await loadDimension();
    await nextTick();
    renderCharts();
  } catch (error: any) {
    message.error(error?.message || '加载安全事件报告失败');
  } finally {
    loading.value = false;
  }
}

async function loadDimension() {
  try {
    dimensionData.value = await getMultiDimAnalysis({ dimension: dimension.value });
    await nextTick();
    renderDimensionOnly();
    renderHotCategoryOnly();
  } catch (error: any) {
    message.error(error?.message || '加载统计维度失败');
  }
}

function renderCharts() {
  renderDimensionOnly();
  renderTrendOnly();
  renderHotCategoryOnly();
}

const dimensionColorMap: Record<string, string> = {
  '紧急': '#dc2626',
  '高': '#ea580c',
  '中': '#d97706',
  '低': '#059669',
};
const defaultBarColors = ['#3b82f6', '#60a5fa', '#93c5fd', '#bfdbfe', '#dbeafe', '#eff6ff'];

function chartColors() {
  const dark = isDark.value;
  return {
    tooltipBg: dark ? 'rgba(30,41,59,0.95)' : 'rgba(255,255,255,0.96)',
    tooltipBorder: dark ? '#334155' : '#e2e8f0',
    tooltipText: dark ? '#e2e8f0' : '#334155',
    axisLabel: dark ? '#94a3b8' : '#64748b',
    axisLine: dark ? '#334155' : '#e2e8f0',
    splitLine: dark ? 'rgba(148,163,184,0.1)' : '#f1f5f9',
  };
}

function renderDimensionOnly() {
  const items = dimensionData.value;
  const barColors = items.map((item, idx) =>
    dimensionColorMap[item.value] ?? defaultBarColors[idx % defaultBarColors.length],
  );
  const cc = chartColors();

  renderDimensionChart({
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: cc.tooltipBg,
      borderColor: cc.tooltipBorder,
      textStyle: { color: cc.tooltipText },
    },
    grid: { left: 48, right: 20, top: 20, bottom: 48 },
    xAxis: {
      type: 'category',
      data: items.map((item) => item.value),
      axisLabel: {
        interval: 0,
        rotate: items.length > 5 ? 20 : 0,
        color: cc.axisLabel,
      },
      axisLine: { lineStyle: { color: cc.axisLine } },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: cc.axisLabel },
      splitLine: { lineStyle: { color: cc.splitLine, type: 'dashed' } },
    },
    series: [
      {
        type: 'bar',
        data: items.map((item, idx) => ({
          value: item.count,
          itemStyle: { color: barColors[idx] },
        })),
        barMaxWidth: 34,
        itemStyle: { borderRadius: [6, 6, 0, 0] },
      },
    ],
  });
}

function renderTrendOnly() {
  const historical = trendData.value?.historical ?? [];
  const predicted = trendData.value?.predicted ?? [];
  const labels = [...historical.map((item) => item.date), ...predicted.map((item) => item.date)];
  const cc = chartColors();

  renderTrendChart({
    color: ['#3b82f6', '#f59e0b'],
    tooltip: {
      trigger: 'axis',
      backgroundColor: cc.tooltipBg,
      borderColor: cc.tooltipBorder,
      textStyle: { color: cc.tooltipText },
    },
    legend: { top: 0, textStyle: { color: cc.axisLabel } },
    grid: { left: 48, right: 20, top: 36, bottom: 32 },
    xAxis: {
      type: 'category',
      data: labels,
      axisLabel: { color: cc.axisLabel },
      axisLine: { lineStyle: { color: cc.axisLine } },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: cc.axisLabel },
      splitLine: { lineStyle: { color: cc.splitLine, type: 'dashed' } },
    },
    series: [
      {
        name: '历史事件',
        type: 'line',
        smooth: true,
        data: historical.map((item) => item.count),
        areaStyle: { color: 'rgba(59,130,246,0.08)' },
        lineStyle: { width: 2.5 },
      },
      {
        name: '预测事件',
        type: 'line',
        smooth: true,
        lineStyle: { type: 'dashed', width: 2 },
        data: [
          ...Array(historical.length).fill(null),
          ...predicted.map((item) => item.count),
        ],
        areaStyle: { color: 'rgba(245,158,11,0.06)' },
      },
    ],
  });
}

function renderHotCategoryOnly() {
  const hotCategories = aiData.value?.hot_categories ?? [];
  const cc = chartColors();
  const hotBarGradient = {
    type: 'linear' as const, x: 0, y: 0, x2: 1, y2: 0,
    colorStops: [
      { offset: 0, color: '#3b82f6' },
      { offset: 1, color: '#60a5fa' },
    ],
  };

  renderHotCategoryChart({
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: cc.tooltipBg,
      borderColor: cc.tooltipBorder,
      textStyle: { color: cc.tooltipText },
    },
    grid: { left: 96, right: 20, top: 20, bottom: 20 },
    xAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: cc.axisLabel },
      splitLine: { lineStyle: { color: cc.splitLine, type: 'dashed' } },
    },
    yAxis: {
      type: 'category',
      data: hotCategories.map((item) => item.name).reverse(),
      axisLabel: { width: 84, overflow: 'truncate', color: cc.axisLabel },
      axisLine: { lineStyle: { color: cc.axisLine } },
    },
    series: [
      {
        type: 'bar',
        data: hotCategories.map((item) => item.count).reverse(),
        barMaxWidth: 24,
        itemStyle: { borderRadius: [0, 6, 6, 0], color: hotBarGradient },
      },
    ],
  });
}

async function handleDownloadReport() {
  downloading.value = true;
  try {
    const blob = await downloadIncidentReport({
      period: reportPeriod.value,
      year: reportYear.value,
      value: reportValue.value,
    });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `incident_report_${reportPeriod.value}_${reportYear.value}_${reportValue.value}.csv`;
    link.click();
    window.URL.revokeObjectURL(url);
  } catch (error: any) {
    message.error(error?.message || '导出安全事件报告失败');
  } finally {
    downloading.value = false;
  }
}

function renderLevelTag(level: number) {
  const config = {
    1: { label: '低', type: 'default' as const },
    2: { label: '中', type: 'warning' as const },
    3: { label: '高', type: 'error' as const },
    4: { label: '紧急', type: 'error' as const },
  }[level] ?? { label: String(level), type: 'default' as const };
  return h(
    NTag,
    { size: 'small', bordered: false, type: config.type },
    { default: () => config.label },
  );
}

function statusLabel(status?: number) {
  const map: Record<number, string> = {
    1: '待审核',
    2: '整改中',
    3: '待验证',
    4: '已关闭',
  };
  return status ? map[status] || String(status) : '-';
}

function formatTime(value?: string) {
  if (!value) return '-';
  return new Date(value).toLocaleString('zh-CN');
}
</script>

<template>
  <div class="incident-report-page">
    <NCard class="hero-card" :bordered="false">
      <div class="hero-row">
        <div>
          <div class="hero-eyebrow">治理报告</div>
          <h2 class="hero-title">安全事件报告</h2>
          <p class="hero-desc">
            聚合整改率、逾期事件、趋势预测和 AI 风险判断，输出面向管理和跟踪的治理视图。
          </p>
        </div>
        <NSpace :size="10" wrap>
          <NSelect v-model:value="reportPeriod" :options="periodOptions" style="width: 110px" />
          <NSelect v-model:value="reportYear" :options="yearOptions" style="width: 120px" />
          <NSelect v-model:value="reportValue" :options="valueOptions" style="width: 120px" />
          <NButton type="primary" :loading="downloading" @click="handleDownloadReport">
            导出 CSV
          </NButton>
        </NSpace>
      </div>
    </NCard>

    <NSpin :show="loading">
      <template v-if="remediation">
        <NGrid :cols="4" :x-gap="16" :y-gap="16" class="metrics-grid">
          <NGridItem>
            <NCard :bordered="false" class="metric-card accent-blue">
              <NStatistic label="事件总数" :value="remediation.total_count" />
            </NCard>
          </NGridItem>
          <NGridItem>
            <NCard :bordered="false" class="metric-card accent-green">
              <NStatistic label="整改完成率" :value="`${remediation.remediation_rate}%`" />
            </NCard>
          </NGridItem>
          <NGridItem>
            <NCard :bordered="false" class="metric-card accent-red">
              <NStatistic label="逾期事件" :value="remediation.overdue_count" />
            </NCard>
          </NGridItem>
          <NGridItem>
            <NCard :bordered="false" class="metric-card accent-gold">
              <NStatistic label="平均整改天数" :value="remediation.avg_remediation_day" />
            </NCard>
          </NGridItem>
        </NGrid>

        <NGrid :cols="2" :x-gap="16" :y-gap="16" class="panel-grid">
          <NGridItem>
            <NCard :bordered="false">
              <template #header>
                <div class="panel-header">
                  <h3 class="panel-title">治理分布</h3>
                  <NSelect
                    v-model:value="dimension"
                    :options="dimensionOptions"
                    style="width: 160px"
                  />
                </div>
              </template>
              <EchartsUI ref="dimensionChartRef" height="320px" />
            </NCard>
          </NGridItem>
          <NGridItem>
            <NCard :bordered="false">
              <template #header>
                <div class="panel-header">
                  <h3 class="panel-title">趋势预测</h3>
                  <div class="panel-subtitle">
                    算法：{{ trendData?.algorithm || '-' }} / 置信度：{{ trendData?.confidence || 0 }}
                  </div>
                </div>
              </template>
              <EchartsUI ref="trendChartRef" height="320px" />
            </NCard>
          </NGridItem>
        </NGrid>

        <NGrid :cols="2" :x-gap="16" :y-gap="16" class="panel-grid">
          <NGridItem>
            <NCard title="逾期事件清单" :bordered="false">
              <NDataTable
                :columns="overdueColumns"
                :data="overdueItems"
                :bordered="false"
                size="small"
                :pagination="false"
                max-height="360"
              />
            </NCard>
          </NGridItem>
          <NGridItem>
            <NCard title="AI 热点分类" :bordered="false">
              <EchartsUI ref="hotCategoryChartRef" height="220px" />
              <div v-if="aiData" class="ai-summary">
                <div class="ai-score">
                  <div class="ai-risk">
                    <span class="label">整体风险</span>
                    <strong>{{ aiData.overall_risk }}</strong>
                  </div>
                  <div class="ai-risk">
                    <span class="label">风险评分</span>
                    <strong>{{ aiData.risk_score }}</strong>
                  </div>
                  <div class="ai-risk">
                    <span class="label">趋势方向</span>
                    <strong>{{ aiData.trend_direction }}</strong>
                  </div>
                </div>
                <div class="ai-text">{{ aiData.summary }}</div>
                <div class="recommend-list">
                  <div class="recommend-title">治理建议</div>
                  <div v-for="item in aiData.recommendations" :key="item" class="recommend-item">
                    {{ item }}
                  </div>
                </div>
              </div>
            </NCard>
          </NGridItem>
        </NGrid>
      </template>

      <NCard v-else :bordered="false">
        <NEmpty description="暂无可用的安全事件统计数据" />
      </NCard>
    </NSpin>
  </div>
</template>

<style scoped>
.incident-report-page {
  --rp-primary: var(--primary-color, #2080f0);
  --rp-text-1: var(--text-color-1, #1e293b);
  --rp-text-2: var(--text-color-2, #475569);
  --rp-text-3: var(--text-color-3, #94a3b8);

  padding: 20px;
  min-height: 100%;
}

.incident-report-page :deep(.n-card) {
  border-radius: 12px;
}

.hero-card {
  margin-bottom: 16px;
  border-left: 4px solid var(--rp-primary, #2080f0);
}

.hero-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  flex-wrap: wrap;
}

.hero-eyebrow {
  font-size: 12px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--rp-primary, #2080f0);
  margin-bottom: 8px;
  font-weight: 600;
}

.hero-title {
  margin: 0;
  font-size: 28px;
  font-weight: 700;
}

.hero-desc {
  margin: 10px 0 0;
  max-width: 640px;
  opacity: 0.75;
  line-height: 1.7;
}

.metrics-grid,
.panel-grid {
  margin-bottom: 16px;
}

.metric-card {
  padding: 18px 18px 14px;
}

.accent-blue { border-left: 3px solid #3b82f6; }
.accent-green { border-left: 3px solid #059669; }
.accent-red { border-left: 3px solid #dc2626; }
.accent-gold { border-left: 3px solid #d97706; }

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.panel-title {
  margin: 0;
  font-size: 18px;
  font-weight: 700;
}

.panel-subtitle {
  color: var(--rp-text-3);
  font-size: 13px;
}

.ai-summary {
  margin-top: 12px;
}

.ai-score {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 12px;
}

.ai-risk {
  padding: 14px;
  border-radius: 12px;
  background: rgba(59, 130, 246, 0.06);
  border: 1px solid rgba(59, 130, 246, 0.12);
  transition: box-shadow 0.2s;
}

:global(.dark) .ai-risk {
  background: rgba(59, 130, 246, 0.1);
  border-color: rgba(59, 130, 246, 0.2);
}

.ai-risk:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
}

.ai-risk .label {
  display: block;
  font-size: 11px;
  color: var(--rp-text-3);
  margin-bottom: 6px;
  letter-spacing: 0.02em;
}

.ai-risk strong {
  font-size: 20px;
  font-weight: 800;
  color: var(--rp-primary, #2080f0);
}

.ai-text {
  line-height: 1.7;
  margin-bottom: 12px;
}

.recommend-list {
  border-radius: 12px;
  background: rgba(59, 130, 246, 0.05);
  border: 1px solid rgba(59, 130, 246, 0.1);
  padding: 14px 16px;
}

:global(.dark) .recommend-list {
  background: rgba(59, 130, 246, 0.08);
  border-color: rgba(59, 130, 246, 0.15);
}

.recommend-title {
  font-size: 13px;
  font-weight: 700;
  margin-bottom: 8px;
  color: var(--rp-primary, #2080f0);
}

.recommend-item {
  line-height: 1.7;
}

@media (max-width: 1024px) {
  .ai-score {
    grid-template-columns: 1fr;
  }
}
</style>
