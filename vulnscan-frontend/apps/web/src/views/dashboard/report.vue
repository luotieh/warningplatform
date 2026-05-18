<script lang="ts" setup>
import { computed, h, nextTick, onMounted, ref, watch } from 'vue';

import { EchartsUI, useEcharts } from '@vben/plugins/echarts';
import type { EchartsUIType } from '@vben/plugins/echarts';
import type { DataTableColumns } from 'naive-ui';
import {
  NButton,
  NCard,
  NDataTable,
  NEmpty,
  NProgress,
  NSelect,
  NSpin,
  NStatistic,
  NTag,
  useMessage,
  useThemeVars,
} from 'naive-ui';

import {
  downloadTaskReport,
  getTaskReportJSON,
  type AssetItem,
  type DiscoveryItem,
  type ReportData,
  type VulnItem,
} from '#/api/report';
import { getTaskList, type ScanTask } from '#/api/task';

defineOptions({ name: 'DashboardReport' });

const message = useMessage();
const themeVars = useThemeVars();

const loading = ref(false);
const tasks = ref<ScanTask[]>([]);
const selectedTaskId = ref('');
const reportData = ref<null | ReportData>(null);

const severityChartRef = ref<EchartsUIType>();
const discoveryChartRef = ref<EchartsUIType>();
const { renderEcharts: renderSeverityChart } = useEcharts(severityChartRef);
const { renderEcharts: renderDiscoveryChart } = useEcharts(discoveryChartRef);

const severityLabels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '提示',
};

const severityPalette: Record<string, string> = {
  critical: '#c0392b',
  high: '#d97706',
  medium: '#d4a017',
  low: '#2f855a',
  info: '#2563eb',
};

const taskList = computed(() =>
  [...tasks.value].sort((left, right) => {
    const leftFinished = left.finished_at ? new Date(left.finished_at).getTime() : 0;
    const rightFinished = right.finished_at ? new Date(right.finished_at).getTime() : 0;
    return rightFinished - leftFinished;
  }),
);

const taskOptions = computed(() =>
  taskList.value.map((task) => ({
    label: `${task.name} · ${taskStatusLabel(task.status)} · ${taskTargetPreview(task.targets)}`,
    value: task.id,
  })),
);

const summary = computed(() => reportData.value?.summary);
const vulnerabilities = computed(() => reportData.value?.vulnerabilities ?? []);
const discoveryFindings = computed(() => reportData.value?.discovery_findings ?? []);
const assets = computed(() => reportData.value?.assets ?? []);
const completedTaskCount = computed(
  () => taskList.value.filter((task) => task.status === 'completed').length,
);
const runningTaskCount = computed(
  () => taskList.value.filter((task) => ['running', 'queued'].includes(task.status)).length,
);
const latestFinishedAt = computed(() => {
  const latest = taskList.value.find((task) => task.finished_at || task.created_at);
  return latest?.finished_at || latest?.created_at || '';
});

const recentTaskColumns = computed<DataTableColumns<ScanTask>>(() => [
  {
    title: '任务名称',
    key: 'name',
    ellipsis: { tooltip: true },
  },
  {
    title: '任务状态',
    key: 'status',
    width: 110,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        {
          size: 'small',
          bordered: false,
          type: taskStatusType(row.status),
        },
        { default: () => taskStatusLabel(row.status) },
      ),
  },
  {
    title: '目标范围',
    key: 'targets',
    minWidth: 260,
    ellipsis: { tooltip: true },
    render: (row) => taskTargetPreview(row.targets),
  },
  {
    title: '完成时间',
    key: 'finished_at',
    width: 180,
    render: (row) => formatTime(row.finished_at || row.created_at),
  },
  {
    title: '操作',
    key: 'actions',
    width: 120,
    render: (row) =>
      h(
        NButton,
        {
          size: 'small',
          type: 'primary',
          secondary: true,
          onClick: () => handleLoadReport(row.id),
        },
        { default: () => '查看报告' },
      ),
  },
]);

const vulnerabilityColumns = computed<DataTableColumns<VulnItem>>(() => [
  {
    title: '漏洞标题',
    key: 'title',
    minWidth: 260,
    ellipsis: { tooltip: true },
  },
  {
    title: '严重度',
    key: 'severity',
    width: 100,
    align: 'center',
    render: (row) => renderSeverityTag(row.severity),
  },
  {
    title: '资产',
    key: 'asset',
    minWidth: 220,
    ellipsis: { tooltip: true },
  },
  {
    title: 'CVE',
    key: 'cve_id',
    width: 150,
    render: (row) => row.cve_id || '-',
  },
  {
    title: '状态',
    key: 'status',
    width: 110,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        {
          size: 'small',
          bordered: false,
          type: row.status === 'fixed' ? 'success' : row.status === 'ignored' ? 'warning' : 'error',
        },
        { default: () => vulnStatusLabel(row.status) },
      ),
  },
]);

const discoveryColumns = computed<DataTableColumns<DiscoveryItem>>(() => [
  {
    title: '发现类型',
    key: 'type_label',
    width: 150,
    render: (row) =>
      h(
        NTag,
        {
          size: 'small',
          bordered: false,
          type: 'info',
        },
        { default: () => row.type_label || humanizeText(row.type) },
      ),
  },
  {
    title: '标题',
    key: 'title',
    minWidth: 220,
    ellipsis: { tooltip: true },
  },
  {
    title: '目标',
    key: 'target',
    minWidth: 220,
    ellipsis: { tooltip: true },
    render: (row) => formatTarget(row.target, row.port),
  },
  {
    title: '摘要',
    key: 'summary',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render: (row) => row.summary || row.description || '-',
  },
  {
    title: '置信度',
    key: 'confidence',
    width: 90,
    align: 'center',
    render: (row) => `${row.confidence || 0}%`,
  },
]);

const assetColumns = computed<DataTableColumns<AssetItem>>(() => [
  {
    title: '主机',
    key: 'host',
    minWidth: 220,
    ellipsis: { tooltip: true },
  },
  {
    title: 'IP',
    key: 'ip',
    width: 140,
    render: (row) => row.ip || '-',
  },
  {
    title: '开放端口',
    key: 'open_ports',
    width: 150,
    render: (row) => (row.open_ports?.length ? row.open_ports.join(', ') : '-'),
  },
  {
    title: '服务',
    key: 'services',
    minWidth: 180,
    ellipsis: { tooltip: true },
    render: (row) => (row.services?.length ? row.services.join(', ') : '-'),
  },
  {
    title: '漏洞数',
    key: 'vuln_count',
    width: 90,
    align: 'center',
  },
  {
    title: '发现总数',
    key: 'finding_count',
    width: 100,
    align: 'center',
  },
]);

onMounted(async () => {
  await loadTasks();
});

watch(
  () => [
    themeVars.value.primaryColor,
    themeVars.value.textColor1,
    themeVars.value.textColor2,
    themeVars.value.borderColor,
  ],
  () => {
    if (!reportData.value) {
      return;
    }
    void nextTick(() => renderCharts(reportData.value!));
  },
);

async function loadTasks() {
  try {
    const result = await getTaskList({ page: 1, page_size: 100 });
    const items = Array.isArray(result.items) ? result.items : [];
    tasks.value = items.filter((task) =>
      ['completed', 'failed', 'running', 'queued', 'paused', 'cancelled'].includes(task.status),
    );

    if (!selectedTaskId.value && taskList.value.length > 0) {
      const preferred =
        taskList.value.find((task) => task.status === 'completed') ?? taskList.value[0];
      selectedTaskId.value = preferred?.id ?? '';
    }
  } catch (error: any) {
    tasks.value = [];
    message.error(error?.message || '加载扫描任务失败');
  }
}

async function handleLoadReport(taskId = selectedTaskId.value) {
  if (!taskId) {
    message.warning('请先选择一个扫描任务');
    return;
  }

  loading.value = true;
  try {
    const result = await getTaskReportJSON(taskId);
    reportData.value = result;
    selectedTaskId.value = taskId;
    await nextTick();
    renderCharts(result);
  } catch (error: any) {
    message.error(error?.message || '加载任务报告失败');
  } finally {
    loading.value = false;
  }
}

function renderCharts(data: ReportData) {
  const currentSummary = data.summary;
  const axisColor = themeVars.value.textColor3 || themeVars.value.textColor2 || '#94a3b8';
  const textColor = themeVars.value.textColor2 || '#475569';
  const borderColor = themeVars.value.borderColor || '#e2e8f0';
  const primaryColor = themeVars.value.primaryColor || '#2563eb';

  renderSeverityChart({
    color: [
      severityPalette.critical ?? '#c0392b',
      severityPalette.high ?? '#d97706',
      severityPalette.medium ?? '#d4a017',
      severityPalette.low ?? '#2f855a',
      severityPalette.info ?? '#2563eb',
    ],
    tooltip: { trigger: 'item' },
    legend: {
      bottom: 0,
      textStyle: { color: textColor },
    },
    series: [
      {
        type: 'pie',
        radius: ['44%', '68%'],
        center: ['50%', '42%'],
        label: { color: textColor, formatter: '{b}\n{c}' },
        itemStyle: {
          borderColor,
          borderWidth: 2,
        },
        data: [
          { name: '严重', value: currentSummary.critical_count },
          { name: '高危', value: currentSummary.high_count },
          { name: '中危', value: currentSummary.medium_count },
          { name: '低危', value: currentSummary.low_count },
          { name: '提示', value: currentSummary.info_count },
        ].filter((item) => item.value > 0),
      },
    ],
  });

  renderDiscoveryChart({
    color: [primaryColor],
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: 56, right: 20, top: 24, bottom: 48 },
    xAxis: {
      type: 'category',
      data: data.discovery_groups.map((item) => item.label),
      axisLine: { lineStyle: { color: borderColor } },
      axisTick: { lineStyle: { color: borderColor } },
      axisLabel: {
        color: axisColor,
        interval: 0,
        rotate: data.discovery_groups.length > 5 ? 18 : 0,
      },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLine: { show: false },
      splitLine: { lineStyle: { color: borderColor } },
      axisLabel: { color: axisColor },
    },
    series: [
      {
        type: 'bar',
        barMaxWidth: 36,
        data: data.discovery_groups.map((item) => item.count),
        itemStyle: { borderRadius: [8, 8, 0, 0] },
      },
    ],
  });
}

function renderSeverityTag(severity: string) {
  const normalized = normalizeSeverity(severity);
  const typeMap: Record<string, 'default' | 'error' | 'info' | 'success' | 'warning'> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'success',
    info: 'info',
  };

  return h(
    NTag,
    {
      size: 'small',
      bordered: false,
      type: typeMap[normalized] ?? 'default',
    },
    { default: () => severityLabels[normalized] ?? (normalized || '-') },
  );
}

function riskStatus(score = 0): 'error' | 'success' | 'warning' {
  if (score >= 80) return 'error';
  if (score >= 45) return 'warning';
  return 'success';
}

function taskTargetPreview(targets?: string[]) {
  if (!targets?.length) return '无目标';
  if (targets.length <= 2) return targets.join(', ');
  return `${targets.slice(0, 2).join(', ')} 等 ${targets.length} 个目标`;
}

function formatTarget(target?: string, port?: number) {
  if (!target) return '-';
  return port ? `${target}:${port}` : target;
}

function formatTime(value?: string) {
  if (!value) return '-';
  return new Date(value).toLocaleString('zh-CN');
}

async function exportReport(format: 'pdf' | 'word') {
  if (!selectedTaskId.value) {
    message.warning('请先选择一个扫描任务');
    return;
  }
  try {
    const blob = await downloadTaskReport(selectedTaskId.value, format);
    const fileName = `${reportData.value?.task?.name || 'scan-report'}.${format === 'word' ? 'doc' : 'pdf'}`;
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
    message.success(`${format === 'word' ? 'Word' : 'PDF'} 报告已开始下载`);
  } catch (error: any) {
    message.error(error?.message || '导出报告失败');
  }
}

function vulnStatusLabel(status?: string) {
  switch (status) {
    case 'fixed':
      return '已修复';
    case 'ignored':
      return '已忽略';
    case 'verified':
      return '已验证';
    default:
      return '待处理';
  }
}

function taskStatusLabel(status?: string) {
  switch (status) {
    case 'completed':
      return '已完成';
    case 'failed':
      return '失败';
    case 'running':
      return '执行中';
    case 'queued':
      return '排队中';
    case 'paused':
      return '已暂停';
    case 'cancelled':
      return '已取消';
    default:
      return status || '-';
  }
}

function taskStatusType(status?: string): 'default' | 'error' | 'info' | 'success' | 'warning' {
  switch (status) {
    case 'completed':
      return 'success';
    case 'failed':
      return 'error';
    case 'running':
      return 'info';
    case 'queued':
    case 'paused':
      return 'warning';
    default:
      return 'default';
  }
}

function normalizeSeverity(severity?: string) {
  return (severity || 'info').trim().toLowerCase();
}

function humanizeText(value?: string) {
  if (!value) {
    return '未分类';
  }
  return value
    .split('_')
    .filter(Boolean)
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(' ');
}
</script>

<template>
  <div class="report-page">
    <section class="page-head">
      <div class="page-head__content">
        <div class="page-kicker">报告中心</div>
        <h2 class="page-title">漏洞扫描任务报告</h2>
        <p class="page-desc">
          以任务为单位查看漏洞、发现信息和资产画像，适合直接用于研判、复核和导出。
        </p>
      </div>
      <div class="head-stats">
        <div class="head-stat">
          <span class="head-stat__label">可用任务</span>
          <strong class="head-stat__value">{{ taskList.length }}</strong>
        </div>
        <div class="head-stat">
          <span class="head-stat__label">已完成</span>
          <strong class="head-stat__value">{{ completedTaskCount }}</strong>
        </div>
        <div class="head-stat">
          <span class="head-stat__label">最近更新</span>
          <strong class="head-stat__value head-stat__value--time">
            {{ latestFinishedAt ? formatTime(latestFinishedAt) : '-' }}
          </strong>
        </div>
      </div>
    </section>

    <NCard :bordered="false" class="surface-card control-card">
      <div class="control-shell">
        <div class="control-top">
          <div>
            <div class="section-title">任务筛选</div>
            <div class="section-desc">
              先选择扫描任务，再生成当前任务的报告预览；支持直接下载 Word 或 PDF 报告。
            </div>
          </div>
          <div class="control-actions">
            <NButton type="primary" @click="handleLoadReport()">生成预览</NButton>
            <NButton secondary @click="exportReport('word')">Word</NButton>
            <NButton secondary @click="exportReport('pdf')">PDF</NButton>
          </div>
        </div>

        <div class="control-row">
          <div class="control-main">
            <div class="control-label">扫描任务</div>
            <NSelect
              v-model:value="selectedTaskId"
              class="task-select"
              filterable
              placeholder="从扫描任务中选择"
              :options="taskOptions"
            />
          </div>

          <div class="control-aside">
            <div class="control-aside__item">
              <span class="control-aside__label">运行中</span>
              <strong class="control-aside__value">{{ runningTaskCount }}</strong>
            </div>
            <div class="control-aside__item">
              <span class="control-aside__label">支持导出</span>
              <strong class="control-aside__value">2 种</strong>
            </div>
          </div>
        </div>
      </div>
    </NCard>

    <NSpin :show="loading">
      <template v-if="reportData && summary">
        <NCard :bordered="false" class="surface-card summary-card">
          <div class="summary-head">
            <div>
              <div class="summary-title">{{ reportData.title }}</div>
              <div class="summary-meta">
                <span>生成时间：{{ formatTime(reportData.generated_at) }}</span>
                <span v-if="reportData.task?.name">任务：{{ reportData.task.name }}</span>
                <span v-if="summary.scan_duration">耗时：{{ summary.scan_duration }}</span>
              </div>
            </div>
            <div class="risk-block">
              <div class="risk-label">风险评分</div>
              <NProgress
                type="circle"
                :percentage="Math.min(100, Math.round(summary.risk_score || 0))"
                :status="riskStatus(summary.risk_score)"
                :stroke-width="8"
              />
            </div>
          </div>

          <div class="metrics-grid">
            <div class="metric-card metric-card--warm">
              <NStatistic label="总发现" :value="summary.total_findings" />
            </div>
            <div class="metric-card metric-card--danger">
              <NStatistic label="漏洞数" :value="summary.total_vulns" />
            </div>
            <div class="metric-card metric-card--info">
              <NStatistic label="发现信息" :value="summary.discovery_count" />
            </div>
            <div class="metric-card metric-card--safe">
              <NStatistic label="资产数" :value="summary.total_assets" />
            </div>
            <div class="metric-card">
              <NStatistic
                label="严重 / 高危"
                :value="`${summary.critical_count} / ${summary.high_count}`"
              />
            </div>
          </div>
        </NCard>

        <div class="panel-grid panel-grid--two">
          <NCard title="漏洞严重度分布" :bordered="false" class="surface-card panel-card">
            <EchartsUI ref="severityChartRef" height="320px" />
          </NCard>
          <NCard title="发现类型分布" :bordered="false" class="surface-card panel-card">
            <EchartsUI ref="discoveryChartRef" height="320px" />
          </NCard>
        </div>

        <div class="panel-grid panel-grid--two">
          <NCard title="漏洞列表" :bordered="false" class="surface-card panel-card">
            <NDataTable
              :columns="vulnerabilityColumns"
              :data="vulnerabilities"
              :bordered="false"
              size="small"
              max-height="420"
              :pagination="{ pageSize: 8 }"
            />
          </NCard>
          <NCard title="发现信息" :bordered="false" class="surface-card panel-card">
            <NDataTable
              :columns="discoveryColumns"
              :data="discoveryFindings"
              :bordered="false"
              size="small"
              max-height="420"
              :pagination="{ pageSize: 8 }"
            />
          </NCard>
        </div>

        <NCard title="资产概览" :bordered="false" class="surface-card panel-card">
          <NDataTable
            :columns="assetColumns"
            :data="assets"
            :bordered="false"
            size="small"
            :pagination="{ pageSize: 10 }"
          />
        </NCard>
      </template>

      <NCard v-else :bordered="false" class="surface-card empty-card">
        <div class="empty-head">
          <div>
            <div class="empty-title">还没有载入报告</div>
            <div class="empty-desc">
              先从上方选择任务。即使任务还未完成，也可以先查看当前已经产生的结果。
            </div>
          </div>
          <div class="empty-badge">快速打开最近任务</div>
        </div>

        <template v-if="taskList.length > 0">
          <NDataTable
            :columns="recentTaskColumns"
            :data="taskList.slice(0, 12)"
            :bordered="false"
            size="small"
            :pagination="false"
          />
        </template>
        <NEmpty v-else description="当前没有可用于生成报告的扫描任务" />
      </NCard>
    </NSpin>
  </div>
</template>

<style scoped>
.report-page {
  --report-surface-bg: hsl(var(--card, 0 0% 100%));
  --report-surface-muted: hsl(var(--card, 0 0% 100%));
  --report-border: hsl(var(--border, 214.3deg 31.8% 91.4%));
  --report-text-1: hsl(var(--foreground, 222 47% 11%));
  --report-text-2: hsl(var(--muted-foreground, 215 16% 47%));
  --report-text-3: hsl(var(--muted-foreground, 215 16% 47%));
  --report-shadow: 0 8px 18px rgba(15, 23, 42, 0.04);
  min-height: 100%;
  padding: 16px 20px 24px;
  background:
    radial-gradient(circle at top right, rgba(37, 99, 235, 0.08), transparent 26%),
    radial-gradient(circle at top left, rgba(14, 165, 233, 0.05), transparent 22%),
    linear-gradient(180deg, rgba(59, 130, 246, 0.035) 0%, rgba(148, 163, 184, 0.02) 28%, transparent 52%),
    var(--body-color);
}

:global(html.dark) .report-page,
:global(.dark) .report-page {
  --report-surface-bg: hsl(var(--card, 224 14% 12%));
  --report-surface-muted: hsl(var(--accent, 216 5% 19%));
  --report-border: hsl(var(--border, 215 14% 23%));
  --report-text-1: hsl(var(--foreground, 210 20% 98%));
  --report-text-2: hsl(var(--muted-foreground, 215 14% 66%));
  --report-text-3: hsl(var(--muted-foreground, 215 14% 58%));
  --report-shadow: 0 10px 24px rgba(0, 0, 0, 0.22);
}

.page-head,
.surface-card {
  background: var(--report-surface-bg);
  border: 1px solid var(--report-border);
  box-shadow: var(--report-shadow);
}

.page-head {
  display: flex;
  align-items: stretch;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 16px;
  padding: 20px 22px;
  border-radius: 16px;
}

.page-head__content {
  max-width: 720px;
}

.page-kicker {
  margin-bottom: 8px;
  color: var(--primary-color);
  font-size: 13px;
  font-weight: 600;
}

.page-title {
  margin: 0;
  color: var(--report-text-1);
  font-size: 28px;
  line-height: 1.2;
}

.page-desc {
  margin: 10px 0 0;
  color: var(--report-text-2);
  font-size: 14px;
  line-height: 1.7;
}

.head-stats {
  flex-shrink: 0;
  min-width: 420px;
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.head-stat {
  border-radius: 14px;
  border: 1px solid var(--report-border);
  background: var(--report-surface-muted);
  padding: 14px 16px;
}

.head-stat__label {
  display: inline-block;
  font-size: 12px;
  color: var(--report-text-2);
}

.head-stat__value {
  display: block;
  margin-top: 10px;
  font-size: 26px;
  font-weight: 700;
  line-height: 1;
  color: var(--report-text-1);
}

.head-stat__value--time {
  font-size: 14px;
  line-height: 1.4;
}

.surface-card {
  --n-color: var(--report-surface-bg);
  --n-color-modal: var(--report-surface-bg);
  --n-color-popover: var(--report-surface-bg);
  --n-color-embedded: var(--report-surface-muted);
  --n-color-embedded-modal: var(--report-surface-muted);
  --n-color-embedded-popover: var(--report-surface-muted);
  --n-action-color: var(--report-surface-muted);
  --n-border-color: var(--report-border);
  --n-text-color: var(--report-text-1);
  border-radius: 16px;
}

.control-card,
.summary-card,
.panel-card,
.empty-card {
  margin-bottom: 16px;
}

.control-shell {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.control-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
  flex-wrap: wrap;
}

.section-title {
  color: var(--report-text-1);
  font-size: 18px;
  font-weight: 700;
}

.section-desc {
  margin-top: 6px;
  color: var(--report-text-2);
  font-size: 13px;
  line-height: 1.65;
}

.control-row {
  display: flex;
  gap: 20px;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
}

.control-main {
  min-width: 360px;
  flex: 1;
}

.control-label {
  margin-bottom: 10px;
  color: var(--report-text-2);
  font-size: 13px;
  font-weight: 600;
}

.task-select {
  width: 100%;
}

.control-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.control-aside {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.control-aside__item {
  min-width: 104px;
  padding: 12px 14px;
  border-radius: 14px;
  border: 1px solid var(--report-border);
  background: var(--report-surface-muted);
}

.control-aside__label {
  display: block;
  color: var(--report-text-3);
  font-size: 12px;
}

.control-aside__value {
  display: block;
  margin-top: 6px;
  color: var(--report-text-1);
  font-size: 18px;
  font-weight: 700;
}

.summary-head {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  align-items: center;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.summary-title {
  color: var(--report-text-1);
  font-size: 20px;
  font-weight: 700;
}

.summary-meta {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  margin-top: 10px;
  color: var(--report-text-3);
  font-size: 13px;
}

.risk-block {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

.risk-label {
  color: var(--report-text-3);
  font-size: 12px;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 16px;
}

.metric-card {
  border-radius: 14px;
  border: 1px solid var(--report-border);
  padding: 18px 16px;
  background: var(--report-surface-muted);
}

.metric-card--warm {
  border-color: rgba(217, 119, 6, 0.22);
}

.metric-card--danger {
  border-color: rgba(192, 57, 43, 0.22);
}

.metric-card--info {
  border-color: rgba(37, 99, 235, 0.22);
}

.metric-card--safe {
  border-color: rgba(47, 133, 90, 0.22);
}

.panel-grid {
  display: grid;
  gap: 16px;
  margin-bottom: 16px;
}

.panel-grid--two {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.empty-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 16px;
}

.empty-title {
  color: var(--report-text-1);
  font-size: 18px;
  font-weight: 700;
}

.empty-desc {
  margin-top: 8px;
  color: var(--report-text-2);
  font-size: 14px;
}

.empty-badge {
  flex-shrink: 0;
  padding: 8px 12px;
  border-radius: 999px;
  background: rgba(37, 99, 235, 0.08);
  color: var(--primary-color);
  font-size: 12px;
  font-weight: 600;
}

@media (max-width: 1180px) {
  .head-stats,
  .metrics-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 960px) {
  .page-head,
  .control-top,
  .summary-head,
  .control-row {
    flex-direction: column;
    align-items: stretch;
  }

  .head-stats,
  .control-main {
    min-width: 100%;
  }

  .empty-head,
  .panel-grid--two,
  .metrics-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
