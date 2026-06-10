<script lang="ts" setup>
import type { RecentActivity, SecurityPosture } from '#/api/dashboard';
import type { DashboardStats, SecurityIncident } from '#/api/incident';
import type { ScanTask } from '#/api/task';
import type { DataTableColumns } from 'naive-ui';

import { computed, h, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';
import { IconifyIcon } from '@vben/icons';

import {
  NButton,
  NCard,
  NDataTable,
  NEmpty,
  NGrid,
  NGridItem,
  NModal,
  NProgress,
  NSpin,
  NTag,
} from 'naive-ui';

import { getDashboardOverview, getRecentActivity } from '#/api/dashboard';
import {
  getDashboardStats as getIncidentStats,
  getIncidentList,
} from '#/api/incident';
import { getTaskList } from '#/api/task';

defineOptions({ name: 'WorkbenchOverview' });

const router = useRouter();
const loading = ref(false);
const showThreatHelp = ref(false);
const posture = ref<SecurityPosture | null>(null);
const incidentStats = ref<DashboardStats | null>(null);
const incidents = ref<SecurityIncident[]>([]);
const recentTasks = ref<ScanTask[]>([]);
const activities = ref<RecentActivity[]>([]);

const severityMeta: Record<string, { color: string; label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  critical: { color: '#d03050', label: '严重', type: 'error' },
  high: { color: '#f0a020', label: '高危', type: 'warning' },
  medium: { color: '#2080f0', label: '中危', type: 'info' },
  low: { color: '#18a058', label: '低危', type: 'success' },
  info: { color: '#6b7280', label: '提示', type: 'default' },
};

const statusLabels: Record<number, string> = {
  1: '待人工复核',
  2: '复核通过',
  3: '复核失败',
  4: '待整改',
  5: '整改中',
  6: '待验证',
  7: '已关闭',
};

const taskStatusLabels: Record<string, string> = {
  completed: '已完成',
  failed: '失败',
  paused: '已暂停',
  pending: '等待中',
  queued: '排队中',
  running: '运行中',
};

const taskStatusType: Record<string, 'default' | 'error' | 'info' | 'success' | 'warning'> = {
  completed: 'success',
  failed: 'error',
  paused: 'warning',
  pending: 'default',
  queued: 'info',
  running: 'info',
};

const visibleModules = computed(() => ({
  assets: router.hasRoute('AssetLedger'),
  incidents: router.hasRoute('IncidentList'),
  monitoring: router.hasRoute('MonitorIssues'),
  scans: router.hasRoute('ScanTask'),
}));

type WorkbenchRiskAsset = {
  id?: string;
  asset_id?: string;
  address?: string;
  alert_count?: number;
  host?: string;
  name?: string;
  risk_score?: number;
  vuln_count?: number;
};

const score = computed(() => Math.round(posture.value?.risk_score ?? 0));
const severityItems = computed(() => Object.entries(severityMeta).map(([key, meta]) => ({
  ...meta,
  key,
  value: Number(posture.value?.severity_distribution?.[key] ?? 0),
})));
const totalSeverity = computed(() =>
  severityItems.value.reduce((sum, item) => sum + item.value, 0),
);
const riskDeductions = computed(() =>
  severityItems.value.map((item) => ({
    ...item,
    deduction:
      item.key === 'critical' ? item.value * 10
        : item.key === 'high' ? item.value * 5
          : item.key === 'medium' ? item.value * 2
            : item.key === 'low' ? item.value * 0.5
              : 0,
  })),
);
const totalDeduction = computed(() =>
  riskDeductions.value.reduce((sum, item) => sum + item.deduction, 0),
);
const topRiskAssets = computed<WorkbenchRiskAsset[]>(() =>
  ((posture.value?.top_risk_assets ?? posture.value?.top_vuln_assets ?? []) as WorkbenchRiskAsset[])
    .filter((asset) =>
      Number(asset.risk_score ?? 0) > 0 ||
      Number(asset.vuln_count ?? 0) > 0 ||
      Number(asset.alert_count ?? 0) > 0,
    )
    .slice(0, 6),
);

const todoItems = computed(() => {
  const stats = incidentStats.value;
  const monitorStats = posture.value?.monitor_stats;
  return [
    {
      color: '#d03050',
      count: stats?.pending_audit ?? 0,
      icon: 'lucide:clipboard-check',
      label: '待复核事件',
      route: '/incident/list',
      visible: visibleModules.value.incidents,
    },
    {
      color: '#f0a020',
      count: stats?.overdue ?? 0,
      icon: 'lucide:alarm-clock',
      label: '逾期处置',
      route: '/incident/list',
      visible: visibleModules.value.incidents,
    },
    {
      color: '#2080f0',
      count: posture.value?.active_scans ?? 0,
      icon: 'lucide:radar',
      label: '运行中扫描',
      route: '/scan/task',
      visible: visibleModules.value.scans,
    },
    {
      color: '#7c3aed',
      count: monitorStats?.open_alerts ?? 0,
      icon: 'lucide:shield-alert',
      label: '监测告警',
      route: '/site-monitor/issues',
      visible: visibleModules.value.monitoring,
    },
  ].filter((item) => item.visible);
});

const summaryCards = computed(() => [
  {
    color: '#2080f0',
    icon: 'lucide:server',
    label: '资产总数',
    route: '/asset/ledger',
    value: posture.value?.total_assets ?? 0,
    visible: visibleModules.value.assets,
  },
  {
    color: '#d03050',
    icon: 'lucide:bug',
    label: '漏洞总数',
    route: '/scan/vulns',
    value: posture.value?.total_vulns ?? 0,
    visible: router.hasRoute('ScanVulnList'),
  },
  {
    color: '#f0a020',
    icon: 'lucide:shield-alert',
    label: '未关闭事件',
    route: '/incident/list',
    value: Math.max((incidentStats.value?.total ?? 0) - (incidentStats.value?.closed ?? 0), 0),
    visible: visibleModules.value.incidents,
  },
  {
    color: '#18a058',
    icon: 'lucide:gauge',
    label: '风险评分',
    route: '/dashboard/overview',
    value: `${score.value}%`,
    visible: router.hasRoute('DashboardOverview'),
  },
].filter((item) => item.visible));

const riskActivities = computed(() =>
  activities.value.filter((activity) => {
    if (activity.type === 'task') return false;
    if (activity.type === 'vuln') return router.hasRoute('ScanVulnList');
    if (activity.type === 'incident') return visibleModules.value.incidents;
    if (activity.type === 'alert') return visibleModules.value.monitoring;
    return true;
  }),
);
const hasRiskActivities = computed(() => riskActivities.value.length > 0);
const hasRiskRow = computed(() => visibleModules.value.assets || hasRiskActivities.value);

function go(route?: string) {
  if (route) router.push(route);
}

function goIncident(row: SecurityIncident) {
  go(`/incident/list/${row.id}`);
}

function goTask(row: ScanTask) {
  go(`/scan/task/${row.id}`);
}

function goAsset(asset: WorkbenchRiskAsset) {
  const id = asset.id || asset.asset_id;
  go(id ? `/asset/detail/${id}` : '/asset/ledger');
}

function getActivityDetail(activity: RecentActivity) {
  if (activity.type === 'vuln') return severityMeta[activity.detail]?.label || activity.detail;
  return activity.detail;
}

function getActivityTypeLabel(activity: RecentActivity) {
  if (activity.type === 'vuln') return '漏洞';
  if (activity.type === 'incident') return '事件';
  if (activity.type === 'alert') return '告警';
  return '动态';
}

function getActivityTagType(activity: RecentActivity) {
  if (activity.type === 'vuln') return 'error';
  if (activity.type === 'incident' || activity.type === 'alert') return 'warning';
  return 'info';
}

function canOpenActivity(activity: RecentActivity) {
  return activity.type === 'vuln' && !!activity.id && router.hasRoute('ScanVulnDetail');
}

function goActivity(activity: RecentActivity) {
  if (activity.type === 'vuln' && activity.id) {
    go(`/scan/vulns/${activity.id}`);
  }
}

function formatDateTime(value?: string) {
  if (!value) return '-';
  return new Intl.DateTimeFormat('zh-CN', {
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    month: '2-digit',
  }).format(new Date(value));
}

function getAssetName(row: any) {
  return row.name || row.host || row.address || '-';
}

async function fetchWorkbench() {
  loading.value = true;
  try {
    const [overviewRes, statsRes, tasksRes, incidentListRes, activityRes] =
      await Promise.allSettled([
        getDashboardOverview(),
        visibleModules.value.incidents ? getIncidentStats() : Promise.resolve(null),
        visibleModules.value.scans ? getTaskList({ page: 1, page_size: 6 }) : Promise.resolve(null),
        visibleModules.value.incidents ? getIncidentList({ page: 1, page_size: 6 }) : Promise.resolve(null),
        getRecentActivity(),
      ]);

    if (overviewRes.status === 'fulfilled') posture.value = overviewRes.value;
    if (statsRes.status === 'fulfilled') incidentStats.value = statsRes.value;
    if (tasksRes.status === 'fulfilled') recentTasks.value = tasksRes.value?.items ?? [];
    if (incidentListRes.status === 'fulfilled') incidents.value = incidentListRes.value?.items ?? [];
    if (activityRes.status === 'fulfilled') activities.value = activityRes.value ?? [];
  } finally {
    loading.value = false;
  }
}

const incidentColumns: DataTableColumns<SecurityIncident> = [
  {
    key: 'name',
    minWidth: 180,
    title: '事件',
    render: (row) => h('button', { class: 'table-link', onClick: (event: MouseEvent) => {
      event.stopPropagation();
      goIncident(row);
    } }, row.name || row.incident_no),
  },
  {
    key: 'level',
    title: '等级',
    width: 80,
    render: (row) => {
      const type = row.level >= 4 ? 'error' : row.level >= 3 ? 'warning' : 'info';
      const label = row.level >= 4 ? '紧急' : row.level >= 3 ? '高' : row.level >= 2 ? '中' : '低';
      return h(NTag, { bordered: false, size: 'small', type }, () => label);
    },
  },
  {
    key: 'status',
    title: '状态',
    width: 110,
    render: (row) => h(NTag, { bordered: false, size: 'small' }, () => row.status_text || statusLabels[row.status] || '-'),
  },
  {
    key: 'action',
    title: '操作',
    width: 80,
    render: (row) => h(NButton, { size: 'tiny', text: true, type: 'primary', onClick: (event: MouseEvent) => {
      event.stopPropagation();
      goIncident(row);
    } }, () => '查看'),
  },
];

const taskColumns: DataTableColumns<ScanTask> = [
  {
    key: 'name',
    minWidth: 180,
    title: '任务',
    render: (row) => h('button', { class: 'table-link', onClick: (event: MouseEvent) => {
      event.stopPropagation();
      goTask(row);
    } }, row.name),
  },
  {
    key: 'status',
    title: '状态',
    width: 90,
    render: (row) => h(NTag, { bordered: false, size: 'small', type: taskStatusType[row.status] || 'default' }, () => taskStatusLabels[row.status] || row.status),
  },
  {
    key: 'progress',
    title: '进度',
    width: 150,
    render: (row) => h(NProgress, { percentage: Math.round(row.progress || 0), processing: row.status === 'running', showIndicator: false, type: 'line' }),
  },
  {
    key: 'updated_at',
    title: '更新时间',
    width: 120,
    render: (row) => formatDateTime(row.updated_at),
  },
];

function incidentRowProps(row: SecurityIncident) {
  return {
    class: 'clickable-table-row',
    onClick: () => goIncident(row),
  };
}

function taskRowProps(row: ScanTask) {
  return {
    class: 'clickable-table-row',
    onClick: () => goTask(row),
  };
}

onMounted(fetchWorkbench);
</script>

<template>
  <Page
    auto-content-height
    content-class="workbench-page-content"
    title="工作台"
    description="当前待办与资产威胁态势"
  >
    <template #extra>
      <NButton size="small" :loading="loading" @click="fetchWorkbench">
        <template #icon>
          <IconifyIcon icon="lucide:refresh-cw" />
        </template>
        刷新
      </NButton>
    </template>

    <NSpin :show="loading">
      <div class="workbench-page">
        <NGrid cols="1 s:2 xl:4" :x-gap="12" :y-gap="12" responsive="screen">
          <NGridItem v-for="card in summaryCards" :key="card.label">
            <button class="summary-card" type="button" @click="go(card.route)">
              <span class="summary-card__icon" :style="{ color: card.color, backgroundColor: `${card.color}14` }">
                <IconifyIcon :icon="card.icon" />
              </span>
              <span class="summary-card__body">
                <span class="summary-card__label">{{ card.label }}</span>
                <strong class="summary-card__value">{{ card.value }}</strong>
              </span>
            </button>
          </NGridItem>
        </NGrid>

        <NGrid cols="1 xl:3" :x-gap="14" :y-gap="14" responsive="screen" class="section-grid">
          <NGridItem>
            <NCard title="当前待办" size="small" class="panel-card">
              <div v-if="todoItems.length" class="todo-list">
                <button v-for="item in todoItems" :key="item.label" class="todo-item" type="button" @click="go(item.route)">
                  <span class="todo-item__icon" :style="{ color: item.color, backgroundColor: `${item.color}14` }">
                    <IconifyIcon :icon="item.icon" />
                  </span>
                  <span class="todo-item__label">{{ item.label }}</span>
                  <strong class="todo-item__count">{{ item.count }}</strong>
                </button>
              </div>
              <NEmpty v-else description="暂无可查看待办" />
            </NCard>
          </NGridItem>

          <NGridItem span="1 xl:2">
            <NCard size="small" class="panel-card">
              <template #header>
                <div class="panel-title-with-action">
                  <span>资产威胁态势</span>
                  <NButton size="tiny" text type="primary" @click="showThreatHelp = true">
                    计算说明
                  </NButton>
                </div>
              </template>
              <div class="threat-layout">
                <div class="score-block">
                  <NProgress
                    type="circle"
                    :percentage="score"
                    :color="score >= 80 ? '#18a058' : score >= 60 ? '#f0a020' : '#d03050'"
                    :rail-color="'#eef2f7'"
                  />
                  <div class="score-meta">
                    <span>综合风险评分</span>
                  </div>
                </div>
                <div class="severity-list">
                  <div v-for="item in severityItems" :key="item.key" class="severity-row">
                    <span class="severity-name">
                      <i :style="{ backgroundColor: item.color }" />
                      {{ item.label }}
                    </span>
                    <NProgress
                      class="severity-progress"
                      type="line"
                      :percentage="totalSeverity ? Math.round((item.value / totalSeverity) * 100) : 0"
                      :color="item.color"
                      :show-indicator="false"
                    />
                    <strong>{{ item.value }}</strong>
                  </div>
                </div>
              </div>
            </NCard>
          </NGridItem>
        </NGrid>

        <div
          v-if="hasRiskRow"
          class="risk-grid section-grid"
          :class="{ 'risk-grid--single': !visibleModules.assets || !hasRiskActivities }"
        >
          <NCard v-if="visibleModules.assets" title="高风险资产" size="small" class="panel-card risk-panel">
            <div v-if="topRiskAssets.length" class="asset-list">
              <button v-for="asset in topRiskAssets" :key="getAssetName(asset)" class="asset-row" type="button" @click="goAsset(asset)">
                <span class="asset-main">
                  <strong>{{ getAssetName(asset) }}</strong>
                  <span>漏洞 {{ asset.vuln_count ?? 0 }} · 告警 {{ asset.alert_count ?? 0 }}</span>
                </span>
                <NTag :bordered="false" size="small" :type="Number(asset.risk_score ?? 0) >= 80 ? 'error' : 'warning'">
                  {{ asset.risk_score ?? 0 }}
                </NTag>
              </button>
            </div>
            <NEmpty v-else description="暂无高风险资产" />
          </NCard>

          <NCard v-if="hasRiskActivities" title="风险动态" size="small" class="panel-card risk-panel">
            <div class="activity-list">
              <button
                v-for="(activity, index) in riskActivities.slice(0, 5)"
                :key="`${activity.type}-${activity.id || activity.title}-${index}`"
                class="activity-item"
                type="button"
                :disabled="!canOpenActivity(activity)"
                @click="goActivity(activity)"
              >
                <NTag size="tiny" :bordered="false" :type="getActivityTagType(activity)">
                  {{ getActivityTypeLabel(activity) }}
                </NTag>
                <div>
                  <strong>{{ activity.title }}</strong>
                  <span>{{ getActivityDetail(activity) }}</span>
                  <em>{{ formatDateTime(activity.created_at) }}</em>
                </div>
              </button>
            </div>
          </NCard>
        </div>

        <NCard v-if="visibleModules.incidents" title="待处理事件" size="small" class="panel-card section-grid">
          <NDataTable
            v-if="incidents.length"
            :bordered="false"
            :columns="incidentColumns"
            :data="incidents"
            :pagination="false"
            :row-props="incidentRowProps"
            size="small"
          />
          <NEmpty v-else description="暂无待处理事件" />
        </NCard>

        <NCard v-if="visibleModules.scans" title="最近扫描任务" size="small" class="panel-card section-grid">
          <NDataTable
            v-if="recentTasks.length"
            :bordered="false"
            :columns="taskColumns"
            :data="recentTasks"
            :pagination="false"
            :row-props="taskRowProps"
            size="small"
          />
          <NEmpty v-else description="暂无扫描任务" />
        </NCard>
      </div>
    </NSpin>

    <NModal
      v-model:show="showThreatHelp"
      preset="card"
      title="资产威胁态势计算说明"
      style="width: min(640px, calc(100vw - 32px))"
    >
      <div class="threat-help">
        <p>
          这里展示的是当前用户数据权限可见资产的风险态势，不是全局统计，也不是时间趋势。数据来自工作台接口
          <code>GET /dashboard/overview</code>。
        </p>
        <div class="threat-help__block">
          <h4>数据来源</h4>
          <p>
            后端先按 IAM 数据权限过滤资产表 <code>vs_asset</code>，再统计这些资产在漏洞表
            <code>vs_vulnerability</code> 中发现的漏洞，并按 <code>severity</code> 字段分组。
          </p>
        </div>
        <div class="threat-help__block">
          <h4>评分公式</h4>
          <p>
            综合风险评分 = <code>max(100 - 扣分总和, 0)</code>。
          </p>
          <div class="weight-grid">
            <span>严重 × 10</span>
            <span>高危 × 5</span>
            <span>中危 × 2</span>
            <span>低危 × 0.5</span>
            <span>提示 × 0</span>
          </div>
        </div>
        <div class="threat-help__block">
          <h4>当前计算</h4>
          <div class="deduction-list">
            <span v-for="item in riskDeductions" :key="item.key">
              {{ item.label }} {{ item.value }} 个，扣 {{ item.deduction }} 分
            </span>
          </div>
          <p>
            当前扣分总和 <strong>{{ totalDeduction }}</strong>，
            综合风险评分 <strong>{{ score }}%</strong>。
          </p>
        </div>
      </div>
    </NModal>
  </Page>
</template>

<style scoped>
.workbench-page {
  --workbench-border: var(--n-border-color, #e5e7eb);
  --workbench-card-bg: #fff;
  --workbench-card-hover: #f8fafc;
  --workbench-text-1: var(--n-text-color, #111827);
  --workbench-text-2: var(--n-text-color-2, #4b5563);
  --workbench-text-3: var(--n-text-color-3, #6b7280);
  min-height: 100%;
}

:global(.workbench-page-content) {
  min-height: 0;
  overflow-y: auto !important;
  scrollbar-gutter: stable;
}

:global(.dark) .workbench-page {
  --workbench-card-bg: #18181c;
  --workbench-card-hover: #202027;
}

.section-grid {
  margin-top: 14px;
}

.risk-grid {
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(360px, 1fr);
  gap: 14px;
  align-items: stretch;
}

.risk-grid--single {
  grid-template-columns: 1fr;
}

.risk-panel {
  min-height: 152px;
}

.summary-card {
  display: flex;
  width: 100%;
  min-height: 86px;
  align-items: center;
  gap: 12px;
  padding: 16px;
  border: 1px solid var(--workbench-border);
  border-radius: 8px;
  background-color: var(--workbench-card-bg);
  background-image: none;
  color: var(--workbench-text-1);
  cursor: pointer;
  text-align: left;
  transition: border-color 0.2s, transform 0.2s;
}

.summary-card:hover,
.todo-item:hover,
.asset-row:hover {
  background-color: var(--workbench-card-hover);
  border-color: var(--primary-color-hover, #4098fc);
}

.summary-card__icon,
.todo-item__icon {
  display: inline-flex;
  flex: 0 0 auto;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  line-height: 1;
}

.summary-card__icon {
  width: 38px;
  height: 38px;
  font-size: 21px;
}

.summary-card__body,
.asset-main,
.activity-item > div {
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.summary-card__label,
.todo-item__label,
.asset-main span,
.activity-item span,
.score-meta span {
  color: var(--workbench-text-2);
  font-size: 12px;
}

.summary-card__value {
  margin-top: 4px;
  font-size: 24px;
  line-height: 1.1;
}

.panel-card {
  border-radius: 8px;
}

.panel-title-with-action {
  display: flex;
  width: 100%;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.todo-list,
.asset-list,
.activity-list,
.severity-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.todo-item,
.asset-row {
  display: flex;
  width: 100%;
  align-items: center;
  border: 1px solid var(--workbench-border);
  border-radius: 8px;
  background: transparent;
  color: var(--workbench-text-1);
  cursor: pointer;
  transition: border-color 0.2s;
}

.todo-item {
  gap: 10px;
  min-height: 48px;
  padding: 8px 10px;
}

.todo-item__icon {
  width: 30px;
  height: 30px;
  font-size: 17px;
}

.todo-item__label {
  flex: 1;
  text-align: left;
}

.todo-item__count {
  font-size: 18px;
}

.threat-layout {
  display: grid;
  grid-template-columns: 180px minmax(0, 1fr);
  gap: 18px;
  align-items: center;
}

.score-block {
  display: flex;
  align-items: center;
  gap: 14px;
}

.severity-row {
  display: grid;
  grid-template-columns: 70px minmax(80px, 1fr) 40px;
  gap: 10px;
  align-items: center;
}

.severity-name {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--workbench-text-2);
  font-size: 12px;
}

.severity-name i {
  width: 7px;
  height: 7px;
  border-radius: 999px;
}

.severity-row strong {
  text-align: right;
}

.asset-row {
  justify-content: space-between;
  min-height: 56px;
  gap: 12px;
  padding: 10px 12px;
}

.asset-main strong,
.activity-item strong,
:deep(.cell-strong) {
  overflow: hidden;
  color: var(--workbench-text-1);
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.activity-item {
  display: grid;
  width: 100%;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 8px;
  align-items: start;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--workbench-border);
  border-top: 0;
  border-right: 0;
  border-left: 0;
  background: transparent;
  color: inherit;
  cursor: pointer;
  text-align: left;
}

.activity-item:last-child {
  padding-bottom: 0;
  border-bottom: 0;
}

.activity-item:disabled {
  cursor: default;
}

.activity-item:not(:disabled):hover strong {
  color: var(--primary-color, #2080f0);
  text-decoration: underline;
}

.activity-item span {
  display: -webkit-box;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.activity-item em {
  margin-top: 2px;
  color: var(--workbench-text-3);
  font-size: 12px;
  font-style: normal;
}

:deep(.clickable-table-row) {
  cursor: pointer;
}

:deep(.clickable-table-row:hover td) {
  background-color: var(--workbench-card-hover);
}

:deep(.table-link) {
  max-width: 100%;
  overflow: hidden;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--primary-color, #2080f0);
  cursor: pointer;
  font: inherit;
  font-weight: 600;
  text-align: left;
  text-overflow: ellipsis;
  white-space: nowrap;
}

:deep(.table-link:hover) {
  text-decoration: underline;
}

.threat-help {
  display: flex;
  flex-direction: column;
  gap: 14px;
  color: var(--workbench-text-2);
  line-height: 1.7;
}

.threat-help p {
  margin: 0;
}

.threat-help code {
  border-radius: 4px;
  background: var(--workbench-card-hover);
  color: var(--workbench-text-1);
  font-size: 12px;
  padding: 2px 5px;
}

.threat-help__block {
  border: 1px solid var(--workbench-border);
  border-radius: 8px;
  padding: 12px;
}

.threat-help__block h4 {
  margin: 0 0 8px;
  color: var(--workbench-text-1);
  font-size: 14px;
}

.weight-grid,
.deduction-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.weight-grid span,
.deduction-list span {
  border-radius: 999px;
  background: var(--workbench-card-hover);
  color: var(--workbench-text-2);
  font-size: 12px;
  padding: 3px 8px;
}

@media (max-width: 768px) {
  .threat-layout {
    grid-template-columns: 1fr;
  }

  .risk-grid {
    grid-template-columns: 1fr;
  }

}
</style>
