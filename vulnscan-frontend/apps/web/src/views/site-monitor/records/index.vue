<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';
import { computed, h, onMounted, reactive, ref } from 'vue';

import type { MonitorExecution, MonitorTask } from '#/api/sitemonitor';

import { Page } from '@vben/common-ui';
import { IconifyIcon } from '@vben/icons';

import { LineChart, BarChart } from 'echarts/charts';
import {
  DataZoomComponent,
  GridComponent,
  LegendComponent,
  TooltipComponent,
} from 'echarts/components';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import VChart from 'vue-echarts';

use([
  CanvasRenderer,
  LineChart,
  BarChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  DataZoomComponent,
]);

import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NCol,
  NDataTable,
  NDatePicker,
  NDrawer,
  NDrawerContent,
  NEmpty,
  NFormItem,
  NGrid,
  NGi,
  NPopconfirm,
  NRow,
  NSelect,
  NSpace,
  NSpin,
  NStatistic,
  NTag,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  batchDeleteExecutions,
  deleteExecution,
  getExecutionDetail,
  getExecutionList,
  getTaskDetail,
  getTaskTrend,
} from '#/api/sitemonitor';

import AvailabilityDetail from '../executions/components/AvailabilityDetail.vue';
import BlacklinkDetail from '../executions/components/BlacklinkDetail.vue';
import DomainHijackDetail from '../executions/components/DomainHijackDetail.vue';
import SensitiveFileDetail from '../executions/components/SensitiveFileDetail.vue';
import SensitiveWordDetail from '../executions/components/SensitiveWordDetail.vue';
import TamperDetail from '../executions/components/TamperDetail.vue';

defineOptions({ name: 'MonitorRecords' });

const props = defineProps<{
  taskId?: string;
}>();

const taskId = ref(props.taskId || '');
const task = ref<MonitorTask | null>(null);

const dimensions = [
  { key: 'all', label: '全部', icon: 'ri:layout-grid-line', color: '#6b7280' },
  { key: 'availability', label: '可用性', icon: 'ri:pulse-line', color: '#3b82f6' },
  { key: 'tamper', label: '篡改监测', icon: 'ri:shield-flash-line', color: '#ef4444' },
  { key: 'blacklink', label: '暗链监测', icon: 'ri:bug-line', color: '#f59e0b' },
  { key: 'sensitive_word', label: '敏感词', icon: 'ri:file-text-line', color: '#8b5cf6' },
  { key: 'sensitive_file', label: '敏感文件', icon: 'ri:folder-shield-2-line', color: '#14b8a6' },
  { key: 'domain_hijack', label: '域名劫持', icon: 'ri:globe-line', color: '#10b981' },
];

const activeDim = ref('all');

const dimLabelMap: Record<string, string> = Object.fromEntries(
  dimensions.map((d) => [d.key, d.label]),
);

const statusLabel = (v: string) =>
  ({
    failed: '失败',
    pending: '等待中',
    running: '运行中',
    success: '成功',
  })[v] ?? v;

const fmtTime = (v: string) => (v ? dayjs(v).format('YYYY-MM-DD HH:mm:ss') : '-');

const filterForm = reactive({
  hasIssue: '',
  disposition: '',
  dateRange: null as [number, number] | null,
});

const issueOpts = [
  { label: '有问题', value: 'true' },
  { label: '正常', value: 'false' },
];

const dispositionOptions = [
  { label: '未处置', value: 'pending' },
  { label: '有效', value: 'valid' },
  { label: '无效', value: 'invalid' },
  { label: '误报', value: 'false_positive' },
];

const dispositionLabelMap: Record<string, string> = {
  false_positive: '误报',
  invalid: '无效',
  pending: '未处置',
  valid: '有效',
};

// 各维度数据
const dimDataMap = reactive<Record<string, MonitorExecution[]>>({});
const dimLoadingMap = reactive<Record<string, boolean>>({});
const dimStatsMap = reactive<Record<string, { total: number; success: number; failed: number; issueCount: number }>>({});

const pagination = reactive({
  page: 1,
  pageSize: 15,
  showSizePicker: true,
  pageSizes: [10, 15, 20, 50],
});

const pageCountMap = reactive<Record<string, number>>({});

async function loadTaskInfo() {
  if (!taskId.value) return;
  try {
    const res = await getTaskDetail(taskId.value);
    task.value = (res as any)?.data || res;
  } catch (e: any) {
    message.error(e?.msg || '加载任务信息失败');
  }
}

// ── 可用性趋势 ──
const trendData = ref<any>(null);
const trendLoading = ref(false);
const trendHours = ref(24);

const trendHoursOptions = [
  { label: '近24小时', value: 24 },
  { label: '近3天', value: 72 },
  { label: '近7天', value: 168 },
  { label: '近30天', value: 720 },
];

async function loadTrend() {
  if (!taskId.value) return;
  trendLoading.value = true;
  try {
    const res: any = await getTaskTrend(taskId.value, trendHours.value);
    trendData.value = res?.data ?? res;
  } catch {
    trendData.value = null;
  } finally {
    trendLoading.value = false;
  }
}

const trendChartOption = computed(() => {
  const pts = trendData.value?.points || [];
  if (!pts.length) return null;
  const times = pts.map((p: any) => p.time);
  const totalMs = pts.map((p: any) => p.total_ms ?? 0);
  const dnsMs = pts.map((p: any) => p.dns_ms ?? 0);
  const tcpMs = pts.map((p: any) => p.tcp_connect_ms ?? 0);
  const tlsMs = pts.map((p: any) => p.tls_handshake_ms ?? 0);
  const ttfbMs = pts.map((p: any) => p.ttfb_ms ?? 0);
  return {
    tooltip: {
      trigger: 'axis',
      formatter: (params: any) => {
        const p = params[0]?.axisValueLabel || '';
        let html = `<div style="font-weight:600;margin-bottom:4px">${p}</div>`;
        for (const s of params) {
          html += `<div>${s.marker} ${s.seriesName}: <b>${s.value?.toFixed(0) ?? '-'}</b> ms</div>`;
        }
        const idx = params[0]?.dataIndex;
        if (idx != null && pts[idx]) {
          const avail = pts[idx].available;
          html += `<div style="margin-top:4px">${avail ? '✅ 可用' : '❌ 不可用'}</div>`;
        }
        return html;
      },
    },
    legend: { data: ['总耗时', 'DNS', 'TCP', 'TLS', 'TTFB'], bottom: 0, textStyle: { fontSize: 11 } },
    grid: { left: 50, right: 16, top: 16, bottom: pts.length > 30 ? 70 : 40 },
    xAxis: { type: 'category', data: times, axisLabel: { fontSize: 10, rotate: pts.length > 30 ? 45 : 0 } },
    yAxis: { type: 'value', name: 'ms', axisLabel: { fontSize: 10 } },
    dataZoom: pts.length > 60 ? [{ type: 'inside', start: 80, end: 100 }] : [],
    series: [
      { name: '总耗时', type: 'line', data: totalMs, smooth: true, lineStyle: { width: 2 }, areaStyle: { opacity: 0.1 }, itemStyle: { color: '#3b82f6' } },
      { name: 'DNS', type: 'line', data: dnsMs, smooth: true, lineStyle: { width: 1 }, itemStyle: { color: '#22c55e' } },
      { name: 'TCP', type: 'line', data: tcpMs, smooth: true, lineStyle: { width: 1 }, itemStyle: { color: '#f59e0b' } },
      { name: 'TLS', type: 'line', data: tlsMs, smooth: true, lineStyle: { width: 1 }, itemStyle: { color: '#a855f7' } },
      { name: 'TTFB', type: 'line', data: ttfbMs, smooth: true, lineStyle: { width: 1 }, itemStyle: { color: '#ef4444' } },
    ],
  };
});

const availBarOption = computed(() => {
  const pts = trendData.value?.points || [];
  if (!pts.length) return null;
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: 50, right: 16, top: 8, bottom: 4 },
    xAxis: { type: 'category', data: pts.map((p: any) => p.time), show: false },
    yAxis: { type: 'value', show: false, max: 1 },
    series: [{
      type: 'bar',
      data: pts.map((p: any) => ({
        value: 1,
        itemStyle: { color: p.available ? (p.has_issue ? '#f59e0b' : '#22c55e') : '#ef4444' },
      })),
      barGap: '0%',
      barCategoryGap: '10%',
    }],
  };
});

async function loadData(dimKey: string) {
  if (!taskId.value) return;

  const targetDim = dimKey === 'all' ? '' : dimKey;
  dimLoadingMap[dimKey] = true;

  try {
    const params: any = {
      index: pagination.page,
      size: pagination.pageSize,
      task_id: taskId.value,
    };

    if (targetDim) params.dimension = targetDim;
    if (filterForm.hasIssue) params.has_issue = filterForm.hasIssue;
    if (filterForm.disposition) params.disposition = filterForm.disposition;
    if (filterForm.dateRange?.[0])
      params.time_start = dayjs(filterForm.dateRange[0]).format('YYYY-MM-DD HH:mm:ss');
    if (filterForm.dateRange?.[1])
      params.time_end = dayjs(filterForm.dateRange[1]).format('YYYY-MM-DD HH:mm:ss');

    const res = await getExecutionList(params);
    const items = res.data || [];
    const count = (res as any).count || 0;
    dimDataMap[dimKey] = items;
    pageCountMap[dimKey] = count;

    dimStatsMap[dimKey] = {
      total: count,
      success: items.filter((r) => r.status === 'success').length,
      failed: items.filter((r) => r.status === 'failed').length,
      issueCount: items.filter((r) => r.has_issue).length,
    };
  } catch (e: any) {
    dimDataMap[dimKey] = [];
    dimStatsMap[dimKey] = { total: 0, success: 0, failed: 0, issueCount: 0 };
    message.error(e?.msg || '加载数据失败');
  } finally {
    dimLoadingMap[dimKey] = false;
  }
}

async function loadAllDimStats() {
  if (!taskId.value) return;
  const dimKeys = dimensions.map((d) => d.key);
  await Promise.all(
    dimKeys.map(async (dimKey) => {
      const targetDim = dimKey === 'all' ? '' : dimKey;
      try {
        const params: any = {
          index: 1,
          size: 1,
          task_id: taskId.value,
        };
        if (targetDim) params.dimension = targetDim;
        const res = await getExecutionList(params);
        const count = (res as any).count || 0;
        if (!dimStatsMap[dimKey] || dimKey !== activeDim.value) {
          dimStatsMap[dimKey] = {
            total: count,
            success: 0,
            failed: 0,
            issueCount: 0,
          };
        }
        pageCountMap[dimKey] = pageCountMap[dimKey] || count;
      } catch {
        // ignore
      }
    }),
  );
}

function handleFilterChange() {
  pagination.page = 1;
  loadData(activeDim.value);
}

function handlePageChange(p: number) {
  pagination.page = p;
  loadData(activeDim.value);
}

function handlePageSizeChange(s: number) {
  pagination.pageSize = s;
  pagination.page = 1;
  loadData(activeDim.value);
}

function handleDimChange(dim: string) {
  activeDim.value = dim;
  pagination.page = 1;
  if (!dimDataMap[dim]) {
    loadData(dim);
  }
}

// 详情抽屉
const detailVisible = ref(false);
const detailLoading = ref(false);
const detailData = ref<any>(null);

const detailParsedResult = computed(() => {
  if (!detailData.value?.result_json) return null;
  try {
    return JSON.parse(detailData.value.result_json);
  } catch {
    return null;
  }
});

async function openDetail(row: MonitorExecution) {
  detailData.value = null;
  detailVisible.value = true;
  detailLoading.value = true;
  try {
    const res: any = await getExecutionDetail(row.id);
    detailData.value = res?.data ?? res;
  } catch (e: any) {
    message.error(e?.msg || '加载详情失败');
  } finally {
    detailLoading.value = false;
  }
}

async function handleDelete(row: MonitorExecution) {
  try {
    await deleteExecution(row.id);
    message.success('删除成功');
    loadData(activeDim.value);
  } catch (e: any) {
    message.error(e?.msg || '删除失败');
  }
}

function handleBatchDelete() {
  const data = dimDataMap[activeDim.value] || [];
  if (data.length === 0) {
    message.warning('当前列表无记录');
    return;
  }
  
  dialog.error({
    title: '危险操作',
    content: `确认删除当前页面 ${data.length} 条记录？同时清除相关证据文件，不可恢复！`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const ids = data.map((r) => r.id);
        await batchDeleteExecutions(ids);
        message.success(`已删除 ${ids.length} 条记录`);
        loadData(activeDim.value);
      } catch (e: any) {
        message.error(e?.msg || '批量删除失败');
      }
    },
  });
}

const columns: DataTableColumns<MonitorExecution> = [
  { key: 'index', title: '序号', width: 60, align: 'center', render: (_, i) => i + 1 },
  {
    key: 'dimension',
    title: '维度',
    width: 100,
    align: 'center',
    render: (row) => {
      const dim = dimensions.find((d) => d.key === row.dimension);
      return h(
        'span',
        { style: { color: dim?.color || '#6b7280', fontWeight: 500 } },
        dimLabelMap[row.dimension] || row.dimension || '-',
      );
    },
  },
  {
    key: 'status',
    title: '状态',
    width: 80,
    align: 'center',
    render: (row) => {
      const type =
        row.status === 'success'
          ? 'success'
          : row.status === 'failed'
          ? 'error'
          : row.status === 'running'
          ? 'warning'
          : 'info';
      return h(NTag, { type, size: 'small', bordered: false }, statusLabel(row.status));
    },
  },
  {
    key: 'has_issue',
    title: '安全问题',
    width: 90,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        {
          type: row.has_issue ? 'error' : 'success',
          size: 'small',
          bordered: false,
        },
        row.has_issue ? '⚠ 问题' : '正常',
      ),
  },
  {
    key: 'disposition',
    title: '处置',
    width: 80,
    align: 'center',
    render: (row) => {
      const d = row.disposition || 'pending';
      const typeMap: Record<string, string> = {
        false_positive: 'default',
        invalid: 'default',
        pending: 'warning',
        valid: 'success',
      };
      return h(
        NTag,
        { type: typeMap[d] || 'default', size: 'small', bordered: false },
        dispositionLabelMap[d] || d,
      );
    },
  },
  { key: 'url', title: 'URL', minWidth: 200, ellipsis: { tooltip: true }, align: 'center' },
  {
    key: 'created_at',
    title: '创建时间',
    width: 160,
    align: 'center',
    render: (row) => fmtTime(row.created_at),
  },
  {
    key: 'op',
    title: '操作',
    width: 120,
    fixed: 'right',
    align: 'center',
    render: (row) =>
      h(NSpace, { size: 8, justify: 'center' }, () => [
        h(
          NButton,
          {
            text: true,
            size: 'small',
            type: 'primary',
            onClick: () => openDetail(row),
          },
          { default: () => '详情' },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDelete(row) },
          {
            trigger: () =>
              h(
                NButton,
                {
                  text: true,
                  size: 'small',
                  type: 'error',
                },
                { default: () => '删除' },
              ),
            default: () => '确认删除该条记录及相关证据文件？',
          },
        ),
      ]),
  },
];

function execStatusType(s: string) {
  if (s === 'success') return 'success';
  if (s === 'failed') return 'error';
  if (s === 'running') return 'warning';
  return 'info';
}

onMounted(() => {
  if (taskId.value) {
    loadTaskInfo();
    loadTrend();
    loadData(activeDim.value);
    loadAllDimStats();
  }
});
</script>

<template>
  <Page :title="`监测记录${task?.task_name ? ` — ${task.task_name}` : ''}`" description="网站监测记录详情">
    <template #extra>
      <NSpace :size="8">
        <NButton size="small" @click="() => loadData(activeDim)">
          <IconifyIcon icon="ri:refresh-line" class="text-sm" />
          刷新
        </NButton>
      </NSpace>
    </template>

    <!-- 筛选区域 -->
    <NCard class="mb-4">
      <div class="records-filter-bar">
        <NSpace align="center" wrap>
          <NFormItem label="状态" label-width="40">
            <NSelect
              v-model:value="filterForm.hasIssue"
              placeholder="全部"
              clearable
              size="small"
              style="width: 110px"
              :options="issueOpts"
            />
          </NFormItem>
          <NFormItem label="处置" label-width="40">
            <NSelect
              v-model:value="filterForm.disposition"
              placeholder="全部"
              clearable
              size="small"
              style="width: 110px"
              :options="dispositionOptions"
            />
          </NFormItem>
          <NFormItem label="时间" label-width="40">
            <NDatePicker
              v-model:value="filterForm.dateRange"
              type="datetimerange"
              clearable
              size="small"
              style="width: 340px"
            />
          </NFormItem>
          <NSpace :size="8">
            <NButton type="primary" size="small" @click="handleFilterChange">查询</NButton>
            <NButton
              size="small"
              @click="
                () => {
                  filterForm.hasIssue = '';
                  filterForm.disposition = '';
                  filterForm.dateRange = null;
                  handleFilterChange();
                }
              "
            >
              重置
            </NButton>
          </NSpace>
        </NSpace>
      </div>
    </NCard>

    <!-- 可用性趋势概览 -->
    <NCard class="mb-4">
      <NSpin :show="trendLoading" size="small">
        <template v-if="trendData">
          <div class="mb-2 flex items-center justify-between">
            <span class="text-base font-bold">可用性概览</span>
            <NSelect
              v-model:value="trendHours"
              :options="trendHoursOptions"
              size="small"
              style="width: 120px"
              @update:value="() => loadTrend()"
            />
          </div>
          <NRow :gutter="12" class="mb-3">
            <NCol :span="4">
              <NStatistic label="可用率" tabular-nums>
                <span :class="(trendData.summary?.availability_pct ?? 0) >= 99 ? 'text-green-500' : (trendData.summary?.availability_pct ?? 0) >= 95 ? 'text-yellow-500' : 'text-red-500'" class="text-xl font-bold">
                  {{ (trendData.summary?.availability_pct ?? 0).toFixed(1) }}%
                </span>
              </NStatistic>
            </NCol>
            <NCol :span="4">
              <NStatistic label="检测次数" :value="trendData.summary?.total_checks ?? 0" tabular-nums />
            </NCol>
            <NCol :span="4">
              <NStatistic label="平均耗时" tabular-nums>
                <span class="font-mono">{{ (trendData.summary?.avg_response_ms ?? 0).toFixed(0) }} ms</span>
              </NStatistic>
            </NCol>
            <NCol :span="4">
              <NStatistic label="最大耗时" tabular-nums>
                <span class="font-mono">{{ (trendData.summary?.max_response_ms ?? 0).toFixed(0) }} ms</span>
              </NStatistic>
            </NCol>
            <NCol :span="4">
              <NStatistic label="最小耗时" tabular-nums>
                <span class="font-mono">{{ (trendData.summary?.min_response_ms ?? 0).toFixed(0) }} ms</span>
              </NStatistic>
            </NCol>
            <NCol :span="4">
              <NStatistic label="发现问题" tabular-nums>
                <span :class="(trendData.summary?.issue_count ?? 0) > 0 ? 'text-red-500 font-bold' : 'text-green-500'">
                  {{ trendData.summary?.issue_count ?? 0 }}
                </span>
              </NStatistic>
            </NCol>
          </NRow>

          <div v-if="availBarOption" class="mb-2">
            <div class="text-muted-foreground mb-1 text-xs">可用性状态（绿=正常 黄=有问题 红=不可用）</div>
            <VChart :option="availBarOption" style="height: 28px; width: 100%" autoresize />
          </div>

          <div v-if="trendChartOption" class="mb-3">
            <div class="text-muted-foreground mb-1 text-xs">响应时间趋势</div>
            <VChart :option="trendChartOption" style="height: 220px; width: 100%" autoresize />
          </div>

          <div v-if="(trendData.dimensions || []).length">
            <div class="text-muted-foreground mb-1 text-xs">各维度状态</div>
            <div class="flex flex-wrap gap-2">
              <NTag
                v-for="dim in trendData.dimensions"
                :key="dim.dimension"
                :type="dim.issue_count > 0 ? 'error' : dim.total > 0 ? 'success' : 'default'"
                size="small"
                :bordered="false"
              >
                {{ dimLabelMap[dim.dimension] || dim.dimension }}：{{ dim.total }} 次
                <template v-if="dim.issue_count > 0">（{{ dim.issue_count }} 问题）</template>
              </NTag>
            </div>
          </div>
        </template>
        <NEmpty v-else description="暂无趋势数据" />
      </NSpin>
    </NCard>

    <!-- 维度统计卡片 -->
    <NGrid cols="2 s:3 m:4 l:7" :x-gap="12" :y-gap="12" responsive="screen" class="mb-4">
      <NGi
        v-for="item in dimensions"
        :key="item.key"
        @click="handleDimChange(item.key)"
      >
        <div
          class="dim-stat-card"
          :class="{ active: activeDim === item.key }"
          :style="{ '--dim-color': item.color }"
        >
          <div class="dim-stat-icon">
            <IconifyIcon :icon="item.icon" />
          </div>
          <div class="dim-stat-content">
            <div class="dim-stat-label">{{ item.label }}</div>
            <div class="dim-stat-row">
              <span class="dim-stat-value">{{ dimStatsMap[item.key]?.total || 0 }}</span>
              <span
                v-if="dimStatsMap[item.key]?.issueCount"
                class="dim-stat-issue"
              >
                {{ dimStatsMap[item.key]?.issueCount }}问题
              </span>
            </div>
          </div>
        </div>
      </NGi>
    </NGrid>

    <!-- 列表区域 -->
    <NCard>
      <div class="flex justify-between items-center mb-3">
        <span class="text-sm text-muted-foreground">
          共 {{ pageCountMap[activeDim] || 0 }} 条记录
        </span>
        <NButton type="error" size="small" @click="handleBatchDelete" v-if="dimDataMap[activeDim]?.length">
          批量删除当前页
        </NButton>
      </div>

      <NDataTable
        :columns="columns"
        :data="dimDataMap[activeDim] || []"
        :loading="dimLoadingMap[activeDim]"
        :pagination="{
          ...pagination,
          itemCount: pageCountMap[activeDim] || 0,
        }"
        :row-key="(r: MonitorExecution) => r.id"
        remote
        size="small"
        @update:page="handlePageChange"
        @update:page-size="handlePageSizeChange"
      >
        <template #empty>
          <NEmpty description="暂无监测记录" />
        </template>
      </NDataTable>
    </NCard>

    <!-- 详情抽屉 -->
    <NDrawer v-model:show="detailVisible" :width="900" placement="right">
      <NDrawerContent
        :title="
          detailData
            ? `监测详情 — ${dimLabelMap[detailData.dimension] || detailData.dimension}`
            : '监测详情'
        "
        closable
      >
        <NSpin :show="detailLoading">
          <template v-if="detailData">
            <NCard size="small" class="mb-3">
              <div class="grid grid-cols-4 gap-4">
                <div class="text-center p-2 bg-gray-50 rounded">
                  <div class="text-xs text-gray-500 mb-1">状态</div>
                  <NTag
                    :type="execStatusType(detailData.status)"
                    size="small"
                    :bordered="false"
                  >
                    {{ statusLabel(detailData.status) }}
                  </NTag>
                </div>
                <div class="text-center p-2 bg-gray-50 rounded">
                  <div class="text-xs text-gray-500 mb-1">安全问题</div>
                  <NTag
                    :type="detailData.has_issue ? 'error' : 'success'"
                    size="small"
                    :bordered="false"
                  >
                    {{ detailData.has_issue ? '⚠ 发现问题' : '无' }}
                  </NTag>
                </div>
                <div class="text-center p-2 bg-gray-50 rounded">
                  <div class="text-xs text-gray-500 mb-1">响应耗时</div>
                  <span class="font-mono text-green-600">
                    {{ detailData.duration_ms ?? '-' }} ms
                  </span>
                </div>
                <div class="text-center p-2 bg-gray-50 rounded">
                  <div class="text-xs text-gray-500 mb-1">监测ID</div>
                  <span class="font-mono text-xs text-blue-600">
                    {{ detailData.id }}
                  </span>
                </div>
              </div>
            </NCard>

            <AvailabilityDetail
              v-if="detailData.dimension === 'availability'"
              :result="detailParsedResult"
              class="mb-3"
            />
            <TamperDetail
              v-else-if="detailData.dimension === 'tamper'"
              :result="detailParsedResult"
              :execution-id="detailData.id"
              class="mb-3"
            />
            <BlacklinkDetail
              v-else-if="detailData.dimension === 'blacklink'"
              :result="detailParsedResult"
              class="mb-3"
            />
            <SensitiveWordDetail
              v-else-if="detailData.dimension === 'sensitive_word'"
              :result="detailParsedResult"
              class="mb-3"
            />
            <SensitiveFileDetail
              v-else-if="detailData.dimension === 'sensitive_file'"
              :result="detailParsedResult"
              class="mb-3"
            />
            <DomainHijackDetail
              v-else-if="detailData.dimension === 'domain_hijack'"
              :result="detailParsedResult"
              class="mb-3"
            />

            <NCard
              v-if="detailData.result_json"
              size="small"
              class="mb-3"
            >
              <div class="text-xs text-gray-500 mb-2 font-mono">原始数据</div>
              <pre class="text-xs font-mono text-gray-600 overflow-auto max-h-48">{{ detailData.result_json }}</pre>
            </NCard>
          </template>
          <NEmpty v-else-if="!detailLoading" description="暂无数据" />
        </NSpin>
      </NDrawerContent>
    </NDrawer>
  </Page>
</template>

<style scoped>
.records-filter-bar {
  padding: 12px 16px;
  background: var(--n-color-embedded);
  border-radius: 8px;
}

.records-filter-bar :deep(.n-form-item) {
  margin-bottom: 0;
}

.dim-stat-card {
  display: flex;
  align-items: center;
  padding: 16px;
  background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
  border-radius: 10px;
  border: 2px solid transparent;
  cursor: pointer;
  transition: all 0.2s ease;
}

.dim-stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.06);
  border-color: rgba(59, 130, 246, 0.2);
}

.dim-stat-card.active {
  border-color: var(--dim-color);
  background: linear-gradient(135deg, rgba(59, 130, 246, 0.05) 0%, #f8fafc 100%);
}

.dim-stat-icon {
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--dim-color);
  font-size: 18px;
  opacity: 0.8;
}

.dim-stat-content {
  flex: 1;
  padding-left: 12px;
}

.dim-stat-label {
  font-size: 12px;
  color: var(--n-text-color-3);
}

.dim-stat-row {
  display: flex;
  align-items: baseline;
  gap: 8px;
  margin-top: 4px;
}

.dim-stat-value {
  font-size: 20px;
  font-weight: 600;
  color: var(--n-text-color);
}

.dim-stat-issue {
  font-size: 12px;
  color: #ef4444;
  font-weight: 500;
}
</style>
