<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';
import type { EchartsUIType } from '@vben/plugins/echarts';

import { computed, h, nextTick, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import { IconifyIcon } from '@vben/icons';
import { EchartsUI, useEcharts } from '@vben/plugins/echarts';
import {
  NButton,
  NCard,
  NDataTable,
  NEmpty,
  NGrid,
  NGridItem,
  NProgress,
  NSpace,
  NSpin,
  NTag,
  NTimeline,
  NTimelineItem,
} from 'naive-ui';

import {
  getDashboardOverview,
  getRecentActivity,
  getRecentTasks,
  getTaskStatusDist,
  getTaskTrend,
  getTopVulnAssets,
  getVulnTrend,
  type SecurityPosture,
} from '#/api/dashboard';
import {
  getDashboardStats as getIncidentStats,
  type DashboardStats as IncidentDashboardStats,
} from '#/api/incident';

defineOptions({ name: 'DashboardOverview' });

type TrendPoint = { timestamp: string; value: number };
type TopVulnAsset = { host: string; risk_score: number; vuln_count: number };
type RecentActivity = {
  created_at: string;
  detail: string;
  title: string;
  type: string;
};

const router = useRouter();
const loading = ref(true);
const posture = ref<SecurityPosture | null>(null);
const taskStatusDist = ref<Record<string, number>>({});
const recentActivities = ref<RecentActivity[]>([]);
const recentTasks = ref<any[]>([]);
const incidentStats = ref<IncidentDashboardStats | null>(null);

const vulnTrendRef = ref<EchartsUIType>();
const taskTrendRef = ref<EchartsUIType>();
const severityPieRef = ref<EchartsUIType>();
const topAssetsRef = ref<EchartsUIType>();

const { renderEcharts: renderVulnTrend } = useEcharts(vulnTrendRef);
const { renderEcharts: renderTaskTrend } = useEcharts(taskTrendRef);
const { renderEcharts: renderSeverityPie } = useEcharts(severityPieRef);
const { renderEcharts: renderTopAssets } = useEcharts(topAssetsRef);

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
const severityColors: Record<string, string> = {
  critical: '#d03050',
  high: '#f59e0b',
  info: '#2080f0',
  low: '#18a058',
  medium: '#f0a020',
};
const severityLabels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  info: '信息',
  low: '低危',
  medium: '中危',
};
const taskStatusMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  cancelled: { label: '已取消', type: 'default' },
  completed: { label: '已完成', type: 'success' },
  failed: { label: '失败', type: 'error' },
  pending: { label: '等待中', type: 'default' },
  queued: { label: '排队中', type: 'info' },
  running: { label: '运行中', type: 'warning' },
};

const score = computed(() => Math.round(posture.value?.risk_score ?? 0));
const totalSeverity = computed(() =>
  Object.values(posture.value?.severity_distribution ?? {}).reduce(
    (sum, value) => sum + Number(value || 0),
    0,
  ),
);
const severityItems = computed(() =>
  severityOrder.map((key) => ({
    color: severityColors[key],
    key,
    label: severityLabels[key],
    value: posture.value?.severity_distribution?.[key] ?? 0,
  })),
);
const monitorStats = computed(() => posture.value?.monitor_stats ?? {});
const hasTaskStatus = computed(() =>
  Object.values(taskStatusDist.value).some((value) => Number(value) > 0),
);
const topRiskAssets = computed(() => posture.value?.top_risk_assets ?? []);

const primaryStats = computed(() => [
  {
    color: '#2080f0',
    icon: 'lucide:server',
    label: '资产总数',
    route: '/asset/overview',
    sub: '纳入风险统计的资产',
    value: posture.value?.total_assets ?? 0,
  },
  {
    color: '#d03050',
    icon: 'lucide:bug',
    label: '漏洞总数',
    route: '/scan/vulns',
    sub: `${severityItems.value[0]?.value ?? 0} 严重 / ${severityItems.value[1]?.value ?? 0} 高危`,
    value: posture.value?.total_vulns ?? 0,
  },
  {
    color: '#0f9f9a',
    icon: 'lucide:radar',
    label: '运行中扫描',
    route: '/scan/task',
    sub: `${taskStatusDist.value.queued ?? 0} 个任务排队`,
    value: posture.value?.active_scans ?? 0,
  },
  {
    color: '#7c3aed',
    icon: 'lucide:shield-check',
    label: '安全评分',
    route: '/asm/security',
    sub: score.value >= 80 ? '整体态势稳定' : score.value >= 60 ? '需要持续跟进' : '建议优先处置',
    value: `${score.value}%`,
  },
]);

const monitorCards = computed(() => [
  {
    color: '#2080f0',
    label: '监控任务',
    route: '/monitor/tasks',
    sub: '已接入站点监控',
    value: monitorStats.value.total_tasks ?? 0,
  },
  {
    color: '#18a058',
    label: '启用中',
    route: '/monitor/tasks',
    sub: '当前生效任务',
    value: monitorStats.value.enabled_tasks ?? 0,
  },
  {
    color: '#f0a020',
    label: '告警总数',
    route: '/monitor/tasks/executions',
    sub: '历史触发记录',
    value: monitorStats.value.total_alerts ?? 0,
  },
  {
    color: '#d03050',
    label: '待处理告警',
    route: '/monitor/tasks/executions',
    sub: '需要人工确认',
    value: monitorStats.value.open_alerts ?? 0,
  },
]);

const incidentCards = computed(() => {
  const stats = incidentStats.value;
  return [
    { color: '#2080f0', label: '事件总数', value: stats?.total ?? 0 },
    { color: '#f0a020', label: '待审核', value: stats?.pending_audit ?? 0 },
    { color: '#7c3aed', label: '整改中', value: stats?.in_remediation ?? 0 },
    { color: '#18a058', label: '已关闭', value: stats?.closed ?? 0 },
    { color: '#d03050', label: '超期事件', value: stats?.overdue ?? 0 },
  ];
});

const taskColumns: DataTableColumns<any> = [
  { ellipsis: { tooltip: true }, key: 'name', minWidth: 180, title: '任务名称' },
  {
    align: 'center',
    key: 'status',
    render: (row) => {
      const item = taskStatusMap[row.status] ?? { label: row.status || '-', type: 'default' as const };
      return h(NTag, { bordered: false, size: 'small', type: item.type }, () => item.label);
    },
    title: '状态',
    width: 92,
  },
  {
    key: 'progress',
    render: (row) =>
      h(NProgress, {
        color: row.status === 'failed' ? '#d03050' : '#2080f0',
        height: 6,
        percentage: Math.round(row.progress ?? 0),
        processing: row.status === 'running',
        showIndicator: false,
        type: 'line',
      }),
    title: '进度',
    width: 120,
  },
  { align: 'right', key: 'total_targets', title: '目标数', width: 82 },
  {
    key: 'created_at',
    render: (row) => formatDateTime(row.created_at),
    title: '创建时间',
    width: 168,
  },
];

const topRiskColumns: DataTableColumns<any> = [
  { ellipsis: { tooltip: true }, key: 'name', minWidth: 180, title: '资产名称' },
  { ellipsis: { tooltip: true }, key: 'address', minWidth: 160, title: '地址' },
  {
    align: 'center',
    key: 'risk_score',
    render: (row) =>
      h(NTag, { bordered: false, type: riskTagType(row.risk_score ?? 0) }, () =>
        String(row.risk_score ?? 0),
      ),
    sorter: 'default',
    title: '风险分',
    width: 90,
  },
  { align: 'right', key: 'vuln_count', sorter: 'default', title: '漏洞数', width: 90 },
  { align: 'right', key: 'alert_count', sorter: 'default', title: '待处理告警', width: 112 },
];

function riskColor(value: number) {
  if (value >= 80) return '#18a058';
  if (value >= 60) return '#f0a020';
  if (value >= 40) return '#f59e0b';
  return '#d03050';
}

function riskTagType(value: number) {
  if (value >= 80) return 'success';
  if (value >= 60) return 'warning';
  return 'error';
}

function formatDate(value: string) {
  if (!value) return '-';
  return new Intl.DateTimeFormat('zh-CN', {
    day: '2-digit',
    month: 'short',
  }).format(new Date(value));
}

function formatDateTime(value: string) {
  if (!value) return '-';
  return new Intl.DateTimeFormat('zh-CN', {
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    month: '2-digit',
  }).format(new Date(value));
}

function go(route?: string) {
  if (route) router.push(route);
}

function renderEmptyChart(render: (option: Record<string, any>) => void, text: string) {
  render({
    title: {
      left: 'center',
      text,
      textStyle: {
        fontSize: 13,
        fontWeight: 'normal',
      },
      top: 'middle',
    },
    xAxis: { show: false, type: 'category' },
    yAxis: { show: false, type: 'value' },
  });
}

function renderLineChart(render: (option: Record<string, any>) => void, trend: TrendPoint[]) {
  if (!trend.length) {
    renderEmptyChart(render, '暂无漏洞趋势数据');
    return;
  }
  render({
    grid: { bottom: 28, left: 38, right: 16, top: 24 },
    tooltip: { trigger: 'axis' },
    xAxis: {
      axisLabel: { fontSize: 11 },
      axisLine: {},
      axisTick: { show: false },
      data: trend.map((point) => formatDate(point.timestamp)),
      type: 'category',
    },
    yAxis: {
      axisLabel: { fontSize: 11 },
      minInterval: 1,
      splitLine: {},
      type: 'value',
    },
    series: [
      {
        areaStyle: { color: 'rgba(208, 48, 80, 0.12)' },
        data: trend.map((point) => point.value),
        itemStyle: { color: '#d03050' },
        lineStyle: { color: '#d03050', width: 2 },
        smooth: true,
        symbol: 'circle',
        symbolSize: 6,
        type: 'line',
      },
    ],
  });
}

function renderBarChart(render: (option: Record<string, any>) => void, trend: TrendPoint[]) {
  if (!trend.length) {
    renderEmptyChart(render, '暂无任务趋势数据');
    return;
  }
  render({
    grid: { bottom: 28, left: 38, right: 16, top: 24 },
    tooltip: { trigger: 'axis' },
    xAxis: {
      axisLabel: { fontSize: 11 },
      axisLine: {},
      axisTick: { show: false },
      data: trend.map((point) => formatDate(point.timestamp)),
      type: 'category',
    },
    yAxis: {
      axisLabel: { fontSize: 11 },
      minInterval: 1,
      splitLine: {},
      type: 'value',
    },
    series: [
      {
        barMaxWidth: 28,
        data: trend.map((point) => point.value),
        itemStyle: { borderRadius: [4, 4, 0, 0], color: '#2080f0' },
        type: 'bar',
      },
    ],
  });
}

function renderSeverityChart() {
  const data = severityItems.value
    .filter((item) => item.value > 0)
    .map((item) => ({
      itemStyle: { color: item.color },
      name: item.label,
      value: item.value,
    }));
  if (!data.length) {
    renderEmptyChart(renderSeverityPie, '暂无漏洞分布数据');
    return;
  }
  renderSeverityPie({
    legend: { bottom: 0, itemGap: 14, textStyle: { fontSize: 11 } },
    series: [
      {
        center: ['50%', '43%'],
        data,
        label: { formatter: '{b} {c}', fontSize: 11 },
        radius: ['46%', '70%'],
        type: 'pie',
      },
    ],
    tooltip: { trigger: 'item' },
  });
}

function renderTopAssetsChart(assets: TopVulnAsset[]) {
  const data = assets.slice(0, 8).reverse();
  if (!data.length) {
    renderEmptyChart(renderTopAssets, '暂无高危资产数据');
    return;
  }
  renderTopAssets({
    grid: { bottom: 20, left: 112, right: 28, top: 12 },
    series: [
      {
        barMaxWidth: 16,
        data: data.map((asset) => asset.vuln_count),
        itemStyle: { borderRadius: [0, 4, 4, 0], color: '#f59e0b' },
        type: 'bar',
      },
    ],
    tooltip: { axisPointer: { type: 'shadow' }, trigger: 'axis' },
    xAxis: {
      axisLabel: { fontSize: 11 },
      minInterval: 1,
      splitLine: {},
      type: 'value',
    },
    yAxis: {
      axisLabel: { fontSize: 11, overflow: 'truncate', width: 96 },
      axisTick: { show: false },
      data: data.map((asset) => asset.host),
      type: 'category',
    },
  });
}

async function fetchDashboard() {
  loading.value = true;
  try {
    const [
      overviewRes,
      vulnTrendRes,
      taskTrendRes,
      topAssetsRes,
      taskDistRes,
      activityRes,
      tasksRes,
      incidentRes,
    ] = await Promise.allSettled([
      getDashboardOverview(),
      getVulnTrend(),
      getTaskTrend(),
      getTopVulnAssets(),
      getTaskStatusDist(),
      getRecentActivity(),
      getRecentTasks({ page: 1, page_size: 8 }),
      getIncidentStats(),
    ]);

    if (overviewRes.status === 'fulfilled') posture.value = overviewRes.value;
    if (taskDistRes.status === 'fulfilled') taskStatusDist.value = taskDistRes.value ?? {};
    if (activityRes.status === 'fulfilled') recentActivities.value = activityRes.value ?? [];
    if (incidentRes.status === 'fulfilled') incidentStats.value = incidentRes.value;
    if (tasksRes.status === 'fulfilled') recentTasks.value = tasksRes.value?.items ?? [];

    await nextTick();
    renderLineChart(
      renderVulnTrend,
      vulnTrendRes.status === 'fulfilled' ? (vulnTrendRes.value ?? []) : [],
    );
    renderBarChart(
      renderTaskTrend,
      taskTrendRes.status === 'fulfilled' ? (taskTrendRes.value ?? []) : [],
    );
    renderSeverityChart();
    renderTopAssetsChart(
      topAssetsRes.status === 'fulfilled' ? (topAssetsRes.value ?? []) : [],
    );
  } finally {
    loading.value = false;
  }
}

onMounted(fetchDashboard);
</script>

<template>
  <div class="dashboard-page">
    <NSpin :show="loading">
      <section class="overview-header">
        <div>
          <div class="page-kicker">安全态势总览</div>
          <h1>总览</h1>
          <p>资产、漏洞、扫描、监控和事件的全局风险视图</p>
        </div>
        <NButton size="small" type="primary" :loading="loading" @click="fetchDashboard">
          刷新
        </NButton>
      </section>

      <section class="hero-grid">
        <button
          v-for="item in primaryStats"
          :key="item.label"
          class="metric-card"
          type="button"
          @click="go(item.route)"
        >
          <span class="metric-icon" :style="{ color: item.color, backgroundColor: `${item.color}14` }">
            <IconifyIcon :icon="item.icon" />
          </span>
          <span class="metric-content">
            <span class="metric-label">{{ item.label }}</span>
            <span class="metric-value">{{ item.value }}</span>
            <span class="metric-sub">{{ item.sub }}</span>
          </span>
        </button>

        <div class="score-card">
          <NProgress
            type="circle"
            :percentage="score"
            :color="riskColor(score)"
            :stroke-width="8"
            style="width: 76px"
          />
          <div>
            <div class="metric-label">风险概览</div>
            <div class="score-title">{{ totalSeverity }} 个漏洞</div>
            <div class="metric-sub">按严重级别汇总</div>
          </div>
        </div>
      </section>

      <section class="severity-strip">
        <div
          v-for="item in severityItems"
          :key="item.key"
          class="severity-item"
          :style="{ borderColor: `${item.color}33` }"
        >
          <span class="severity-dot" :style="{ backgroundColor: item.color }"></span>
          <span>{{ item.label }}</span>
          <strong>{{ item.value }}</strong>
        </div>
      </section>

      <NGrid cols="1 m:2" :x-gap="16" :y-gap="16" responsive="screen" class="section-grid">
        <NGridItem>
          <NCard title="监控与告警" size="small" class="panel-card">
            <div class="mini-stat-grid">
              <button
                v-for="item in monitorCards"
                :key="item.label"
                class="mini-stat"
                type="button"
                @click="go(item.route)"
              >
                <span class="mini-label">{{ item.label }}</span>
                <strong :style="{ color: item.color }">{{ item.value }}</strong>
                <span class="mini-sub">{{ item.sub }}</span>
              </button>
            </div>
            <div v-if="hasTaskStatus" class="status-list">
              <div v-for="(count, status) in taskStatusDist" :key="status" class="status-row">
                <span>{{ taskStatusMap[status]?.label ?? status }}</span>
                <strong>{{ count }}</strong>
              </div>
            </div>
          </NCard>
        </NGridItem>

        <NGridItem>
          <NCard title="安全事件" size="small" class="panel-card">
            <div class="mini-stat-grid incident-grid">
              <button
                v-for="item in incidentCards"
                :key="item.label"
                class="mini-stat"
                type="button"
                @click="go('/incident/list')"
              >
                <span class="mini-label">{{ item.label }}</span>
                <strong :style="{ color: item.color }">{{ item.value }}</strong>
              </button>
            </div>
          </NCard>
        </NGridItem>
      </NGrid>

      <NGrid cols="1 xl:2" :x-gap="16" :y-gap="16" responsive="screen" class="section-grid">
        <NGridItem>
          <NCard title="漏洞趋势（近30天）" size="small" class="chart-card">
            <EchartsUI ref="vulnTrendRef" height="260px" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard title="任务趋势（近30天）" size="small" class="chart-card">
            <EchartsUI ref="taskTrendRef" height="260px" />
          </NCard>
        </NGridItem>
      </NGrid>

      <NGrid cols="1 xl:2" :x-gap="16" :y-gap="16" responsive="screen" class="section-grid">
        <NGridItem>
          <NCard title="漏洞严重级别分布" size="small" class="chart-card">
            <EchartsUI ref="severityPieRef" height="280px" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard title="高危资产 TOP 8" size="small" class="chart-card">
            <EchartsUI ref="topAssetsRef" height="280px" />
          </NCard>
        </NGridItem>
      </NGrid>

      <NGrid cols="1 xl:3" :x-gap="16" :y-gap="16" responsive="screen" class="section-grid">
        <NGridItem span="1 xl:2">
          <NCard title="高风险资产 TOP 10" size="small" class="table-card">
            <NDataTable
              v-if="topRiskAssets.length"
              :columns="topRiskColumns"
              :data="topRiskAssets"
              :bordered="false"
              :pagination="false"
              :max-height="320"
              size="small"
            />
            <NEmpty
              v-if="!topRiskAssets.length"
              description="暂无高风险资产"
              class="table-empty"
            />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard title="最近动态" size="small" class="activity-card">
            <NTimeline v-if="recentActivities.length">
              <NTimelineItem
                v-for="(activity, index) in recentActivities.slice(0, 8)"
                :key="`${activity.title}-${index}`"
                :type="activity.type === 'vuln' ? 'error' : 'info'"
                :title="activity.title"
                :time="formatDateTime(activity.created_at)"
              >
                <NSpace :size="6" align="center">
                  <NTag
                    size="tiny"
                    :type="activity.type === 'vuln' ? 'error' : 'info'"
                    :bordered="false"
                    round
                  >
                    {{ activity.type === 'vuln' ? '漏洞' : '任务' }}
                  </NTag>
                  <span class="activity-detail">{{ activity.detail }}</span>
                </NSpace>
              </NTimelineItem>
            </NTimeline>
            <NEmpty v-else description="暂无最近动态" />
          </NCard>
        </NGridItem>
      </NGrid>

      <NCard title="最近扫描任务" size="small" class="table-card section-grid">
        <NDataTable
          v-if="recentTasks.length"
          :columns="taskColumns"
          :data="recentTasks"
          :bordered="false"
          :pagination="false"
          :max-height="360"
          size="small"
        />
        <NEmpty v-if="!recentTasks.length" description="暂无扫描任务" class="table-empty" />
      </NCard>
    </NSpin>
  </div>
</template>

<style scoped>
.dashboard-page {
  --dashboard-card-bg: var(--n-color, hsl(var(--card, 0 0% 100%)));
  --dashboard-card-border: var(--n-border-color, hsl(var(--border, 214 32% 91%)));
  --dashboard-text-1: var(--n-text-color, hsl(var(--foreground, 222 47% 11%)));
  --dashboard-text-2: var(--n-text-color-2, hsl(var(--muted-foreground, 215 16% 47%)));
  --dashboard-text-3: var(--n-text-color-3, hsl(var(--muted-foreground, 215 16% 47%)));
  --dashboard-divider: var(--n-border-color, hsl(var(--border, 214 32% 91%)));
  --dashboard-hover-border: var(--primary-color-hover, #4098fc);
  --dashboard-shadow: 0 8px 22px rgb(0 0 0 / 8%);
  width: 100%;
  padding: 18px 20px 28px;
}

:global(.dark) .dashboard-page {
  --dashboard-card-bg: var(--n-color, hsl(var(--card, 224 14% 12%)));
  --dashboard-card-border: var(--n-border-color, hsl(var(--border, 215 14% 23%)));
  --dashboard-text-1: var(--n-text-color, hsl(var(--foreground, 210 20% 98%)));
  --dashboard-text-2: var(--n-text-color-2, hsl(var(--muted-foreground, 215 14% 66%)));
  --dashboard-text-3: var(--n-text-color-3, hsl(var(--muted-foreground, 215 14% 58%)));
  --dashboard-divider: var(--n-border-color, hsl(var(--border, 215 14% 23%)));
  --dashboard-shadow: 0 8px 22px rgb(0 0 0 / 22%);
}

.overview-header {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 14px;
}

.page-kicker {
  margin-bottom: 4px;
  color: #2080f0;
  font-size: 12px;
  font-weight: 700;
}

.overview-header h1 {
  margin: 0;
  color: var(--dashboard-text-1);
  font-size: 22px;
  font-weight: 700;
  line-height: 1.25;
}

.overview-header p {
  margin: 4px 0 0;
  color: var(--dashboard-text-2);
  font-size: 13px;
}

.hero-grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(180px, 1fr));
  gap: 14px;
}

.metric-card,
.score-card,
.mini-stat {
  border: 1px solid var(--dashboard-card-border);
  border-radius: 8px;
  background: var(--dashboard-card-bg);
  color: var(--dashboard-text-1);
}

.metric-card {
  display: flex;
  align-items: center;
  min-height: 104px;
  padding: 16px;
  gap: 12px;
  cursor: pointer;
  text-align: left;
  transition: border-color 0.16s ease, box-shadow 0.16s ease, transform 0.16s ease;
}

.metric-card:hover,
.mini-stat:hover {
  border-color: var(--dashboard-hover-border);
  box-shadow: var(--dashboard-shadow);
  transform: translateY(-1px);
}

.metric-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 42px;
  height: 42px;
  border-radius: 8px;
  flex-shrink: 0;
  font-size: 22px;
}

.metric-content {
  display: flex;
  min-width: 0;
  flex-direction: column;
}

.metric-label,
.mini-label {
  color: var(--dashboard-text-2);
  font-size: 12px;
  font-weight: 600;
}

.metric-value {
  margin-top: 2px;
  color: var(--dashboard-text-1);
  font-size: 28px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  line-height: 1.1;
}

.metric-sub,
.mini-sub {
  margin-top: 5px;
  overflow: hidden;
  color: var(--dashboard-text-3);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.score-card {
  display: flex;
  align-items: center;
  min-height: 104px;
  padding: 14px 16px;
  gap: 14px;
}

.score-title {
  margin-top: 4px;
  color: var(--dashboard-text-1);
  font-size: 18px;
  font-weight: 800;
}

.severity-strip {
  display: grid;
  grid-template-columns: repeat(5, minmax(120px, 1fr));
  gap: 10px;
  margin-top: 12px;
}

.severity-item {
  display: flex;
  align-items: center;
  min-height: 38px;
  padding: 8px 12px;
  border: 1px solid;
  border-radius: 8px;
  background: var(--dashboard-card-bg);
  color: var(--dashboard-text-2);
  font-size: 13px;
  gap: 8px;
}

.severity-item strong {
  margin-left: auto;
  color: var(--dashboard-text-1);
  font-size: 16px;
  font-variant-numeric: tabular-nums;
}

.severity-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.section-grid {
  margin-top: 16px;
}

.panel-card,
.chart-card,
.table-card,
.activity-card {
  height: 100%;
}

.mini-stat-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(120px, 1fr));
  gap: 10px;
}

.incident-grid {
  grid-template-columns: repeat(5, minmax(96px, 1fr));
}

.mini-stat {
  min-height: 82px;
  padding: 12px;
  cursor: pointer;
  text-align: left;
  transition: border-color 0.16s ease, box-shadow 0.16s ease, transform 0.16s ease;
}

.mini-stat strong {
  display: block;
  margin-top: 4px;
  font-size: 24px;
  font-variant-numeric: tabular-nums;
  line-height: 1.1;
}

.status-list {
  display: grid;
  grid-template-columns: repeat(3, minmax(120px, 1fr));
  gap: 8px 14px;
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px solid var(--dashboard-divider);
}

.status-row {
  display: flex;
  justify-content: space-between;
  color: var(--dashboard-text-2);
  font-size: 13px;
}

.status-row strong {
  color: var(--dashboard-text-1);
  font-variant-numeric: tabular-nums;
}

.activity-card :deep(.n-card__content) {
  min-height: 320px;
}

.activity-detail {
  color: var(--dashboard-text-2);
  font-size: 12px;
}

.table-empty {
  padding: 32px 0;
}

:deep(.n-card) {
  border-radius: 8px;
}

:deep(.n-card-header) {
  padding: 14px 16px 8px;
}

:deep(.n-card__content) {
  padding: 12px 16px 16px;
}

@media (max-width: 1280px) {
  .hero-grid {
    grid-template-columns: repeat(2, minmax(220px, 1fr));
  }

  .severity-strip,
  .mini-stat-grid,
  .incident-grid {
    grid-template-columns: repeat(2, minmax(140px, 1fr));
  }
}

@media (max-width: 720px) {
  .dashboard-page {
    padding: 14px;
  }

  .overview-header {
    align-items: flex-start;
    flex-direction: column;
  }

  .hero-grid,
  .severity-strip,
  .mini-stat-grid,
  .incident-grid,
  .status-list {
    grid-template-columns: 1fr;
  }

  .metric-card,
  .score-card {
    min-height: 92px;
  }
}
</style>
