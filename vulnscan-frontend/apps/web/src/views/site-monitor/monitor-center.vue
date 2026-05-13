<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import type {
  DashboardStats,
  MonitorAgent,
  MonitorExecution,
  MonitorTask,
} from '#/api/sitemonitor';

import { computed, h, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';
import { IconifyIcon } from '@vben/icons';
import { useTabbarStore } from '@vben/stores';

import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NCollapse,
  NCollapseItem,
  NDataTable,
  NDatePicker,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NEmpty,
  NForm,
  NFormItem,
  NGrid,
  NGi,
  NInput,
  NInputNumber,
  NModal,
  NPopconfirm,
  NRadio,
  NRadioGroup,
  NSelect,
  NSpace,
  NSpin,
  NSwitch,
  NTabPane,
  NTabs,
  NTag,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  batchDeleteExecutions,
  deleteExecution,
  getAgentList,
  getDashboardStats,
  getExecutionDetail,
  getExecutionList,
  getTaskExecutionStats,
  getTaskList,
  runTask,
  updateDisposition,
} from '#/api/sitemonitor';
import { useAutoRefresh } from '#/composables/useAutoRefresh';

import AvailabilityDetail from './executions/components/AvailabilityDetail.vue';
import BlacklinkDetail from './executions/components/BlacklinkDetail.vue';
import DomainHijackDetail from './executions/components/DomainHijackDetail.vue';
import SensitiveFileDetail from './executions/components/SensitiveFileDetail.vue';
import SensitiveWordDetail from './executions/components/SensitiveWordDetail.vue';
import TamperDetail from './executions/components/TamperDetail.vue';

defineOptions({ name: 'MonitorCenter' });

const router = useRouter();
const tabbarStore = useTabbarStore();
const loading = ref(false);

const stats = reactive({
  enabledTasks: 0,
  issueExecutions: 0,
  onlineAgents: 0,
  totalAgents: 0,
  totalExecutions: 0,
  totalTasks: 0,
});

const recentExecutions = ref<MonitorExecution[]>([]);
const agentList = ref<MonitorAgent[]>([]);
const taskStatsMap = ref<
  Record<string, Record<string, { total: number; issue_count: number }>>
>({});

const dimensions = [
  { key: 'availability', label: '可用性', icon: 'ri:pulse-line', color: '#3b82f6' },
  { key: 'tamper', label: '篡改监测', icon: 'ri:shield-flash-line', color: '#ef4444' },
  { key: 'blacklink', label: '暗链监测', icon: 'ri:bug-line', color: '#f59e0b' },
  { key: 'sensitive_word', label: '敏感词', icon: 'ri:file-text-line', color: '#8b5cf6' },
  { key: 'sensitive_file', label: '敏感文件', icon: 'ri:folder-shield-2-line', color: '#14b8a6' },
  { key: 'domain_hijack', label: '域名劫持', icon: 'ri:globe-line', color: '#10b981' },
];

const dimMap: Record<string, string> = Object.fromEntries(
  dimensions.map((v) => [v.key, v.label]),
);

const statusLabel = (v: string) =>
  ({
    failed: '失败',
    pending: '等待中',
    running: '运行中',
    success: '成功',
  })[v] ?? v;

const statusColor = (v: string) => {
  if (v === 'success') return '#22c55e';
  if (v === 'failed') return '#ef4444';
  if (v === 'running') return '#f59e0b';
  return '#6b7280';
};

const agentStatusLabel = (v: string) =>
  v === 'online' ? '在线' : v === 'offline' ? '离线' : v || '未知';

const agentStatusColor = (v: string) => {
  if (v === 'online') return '#22c55e';
  if (v === 'offline') return '#ef4444';
  return '#6b7280';
};

const fmtTime = (v: string) =>
  v ? dayjs(v).format('YYYY-MM-DD HH:mm:ss') : '-';

const fmtPercent = (v: number | undefined) =>
  v == null ? '-' : `${v.toFixed(1)}%`;

const dimensionCards = computed(() =>
  dimensions.map((d) => {
    let total = 0;
    let issueCount = 0;
    for (const item of Object.values(taskStatsMap.value || {})) {
      const stat = item?.[d.key];
      if (!stat) continue;
      total += Number(stat.total || 0);
      issueCount += Number(stat.issue_count || 0);
    }
    return { ...d, issueCount, total };
  }),
);

const lastRefreshAt = ref<null | string>(null);

async function fetchDashboardStats() {
  loading.value = true;
  try {
    const [statsRes, execRes, agentRes, taskStatsRes] = await Promise.all([
      getDashboardStats(),
      getExecutionList({ size: 20 }),
      getAgentList(),
      getTaskExecutionStats(),
    ]);
    const overview = ((statsRes as any)?.data ?? statsRes ?? {}) as DashboardStats;
    stats.totalTasks = overview.total_tasks || 0;
    stats.enabledTasks = overview.enabled_tasks || 0;
    stats.totalExecutions = overview.total_executions || 0;
    stats.issueExecutions = overview.issue_executions || 0;
    stats.onlineAgents = overview.online_agents || 0;
    stats.totalAgents = overview.total_agents || 0;
    recentExecutions.value = execRes.data || [];
    agentList.value = Array.isArray(agentRes) ? agentRes : ((agentRes as any)?.data || []);
    taskStatsMap.value = (taskStatsRes as any)?.data ?? taskStatsRes ?? {};
    lastRefreshAt.value = dayjs().format('HH:mm:ss');
  } finally {
    loading.value = false;
  }
}

const refreshIntervalOptions = [
  { label: '10 秒', value: 10_000 },
  { label: '30 秒', value: 30_000 },
  { label: '1 分钟', value: 60_000 },
  { label: '5 分钟', value: 300_000 },
];

const { enabled: autoRefreshEnabled, interval: autoRefreshInterval } =
  useAutoRefresh({
    task: fetchDashboardStats,
    interval: 30_000,
    immediate: true,
    runOnMount: true,
  });

const goExecDetail = (row: MonitorExecution) =>
  router.push(`/monitor/tasks/executions/detail/${row.id}`);

// ── Agent 状态表格 ──
const agentColumns: DataTableColumns<MonitorAgent> = [
  { key: 'uuid', title: 'UUID', minWidth: 220, ellipsis: { tooltip: true } },
  { key: 'version', title: '版本', width: 90, align: 'center' },
  {
    key: 'status',
    title: '状态',
    width: 80,
    align: 'center',
    render: (row) =>
      h(
        'span',
        { style: { color: agentStatusColor(row.status), fontWeight: 500 } },
        agentStatusLabel(row.status),
      ),
  },
  {
    key: 'tasks',
    title: '任务',
    width: 150,
    align: 'center',
    render: (row) =>
      h('span', null, [
        `${row.running_tasks ?? 0}/${row.max_concurrent ?? 0}`,
        h(
          'span',
          { style: { color: '#6b7280', marginLeft: '4px' } },
          `(${row.queued_tasks ?? 0}/${row.max_queue ?? 0})`,
        ),
      ]),
  },
  {
    key: 'cpu',
    title: 'CPU',
    width: 90,
    align: 'center',
    render: (row) => fmtPercent(row.cpu_usage),
  },
  {
    key: 'memory',
    title: '内存',
    width: 90,
    align: 'center',
    render: (row) => fmtPercent(row.memory_usage),
  },
  {
    key: 'updated_at',
    title: '最后心跳',
    width: 170,
    align: 'center',
    render: (row) => fmtTime(row.updated_at),
  },
];

// ── 执行记录表格 ──
const executionColumns: DataTableColumns<MonitorExecution> = [
  { key: 'id', title: '执行ID', width: 180, ellipsis: { tooltip: true } },
  { key: 'url', title: 'URL', minWidth: 220, ellipsis: { tooltip: true } },
  {
    key: 'dimension',
    title: '维度',
    width: 110,
    align: 'center',
    render: (row) => dimMap[row.dimension] || row.dimension || '-',
  },
  {
    key: 'status',
    title: '状态',
    width: 90,
    align: 'center',
    render: (row) =>
      h(
        'span',
        { style: { color: statusColor(row.status), fontWeight: 500 } },
        statusLabel(row.status),
      ),
  },
  {
    key: 'has_issue',
    title: '安全问题',
    width: 100,
    align: 'center',
    render: (row) =>
      h(
        'span',
        {
          style: {
            color: row.has_issue ? '#ef4444' : '#22c55e',
            fontWeight: 500,
          },
        },
        row.has_issue ? '发现' : '无',
      ),
  },
  {
    key: 'created_at',
    title: '创建时间',
    width: 170,
    align: 'center',
    render: (row) => fmtTime(row.created_at),
  },
  {
    key: 'op',
    title: '操作',
    width: 90,
    align: 'center',
    fixed: 'right',
    render: (row) =>
      h(
        NButton,
        {
          text: true,
          type: 'primary',
          size: 'small',
          onClick: () => goExecDetail(row),
        },
        { default: () => '详情' },
      ),
  },
];

// ── 监测任务表格 ──
const taskLoading = ref(false);
const taskDataList = ref<MonitorTask[]>([]);
const taskForm = reactive({ enabled: '', name: '' });
const taskPagination = reactive({
  page: 1,
  pageCount: 1,
  pageSize: 15,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 15, 20, 50],
});

const dimLabelMap: Record<string, string> = {
  availability: '可用性',
  blacklink: '暗链监测',
  domain_hijack: '域名劫持',
  sensitive_file: '敏感文件',
  sensitive_word: '敏感词',
  tamper: '篡改监测',
};

async function fetchTaskList() {
  taskLoading.value = true;
  try {
    const [taskRes, statsRes] = await Promise.all([
      getTaskList({
        enabled: taskForm.enabled,
        index: taskPagination.page,
        name: taskForm.name,
        size: taskPagination.pageSize,
      }),
      getTaskExecutionStats(),
    ]);
    taskDataList.value = taskRes.data || [];
    taskPagination.itemCount = (taskRes as any).count || 0;
    taskStatsMap.value = (statsRes as any)?.data ?? statsRes ?? {};
  } finally {
    taskLoading.value = false;
  }
}

async function handleRunTask(row: MonitorTask) {
  try {
    await runTask(row.id, []);
    message.success('已触发监测');
  } catch (e: any) {
    message.error(e?.msg || '监测失败');
  }
}

function dimStatRender(dimKey: string) {
  return (row: MonitorTask) => {
    const cfg = (row as any)[`config_${dimKey}`];
    if (!cfg?.enabled) return h('span', { style: { color: '#9ca3af' } }, '-');
    const stat = taskStatsMap.value[row.id]?.[dimKey];
    const total = stat?.total ?? 0;
    const pendingCount = stat?.pending_count ?? 0;
    const validCount = stat?.valid_count ?? 0;
    return h(
      'div',
      {
        style: {
          alignItems: 'center',
          display: 'flex',
          gap: '2px',
          justifyContent: 'center',
        },
      },
      [
        h(
          'span',
          {
            style: {
              color: pendingCount > 0 ? '#ef4444' : '#6b7280',
              cursor: 'pointer',
              fontWeight: 500,
            },
            title: '点击查看未处置的问题记录',
            onClick: (e: Event) => {
              e.stopPropagation();
              openRecordsWithFilter(row, dimKey, 'true', 'pending');
            },
          },
          String(pendingCount),
        ),
        h('span', { style: { color: '#d1d5db', margin: '0 1px' } }, '/'),
        h(
          'span',
          {
            style: {
              color: validCount > 0 ? '#f59e0b' : '#6b7280',
              cursor: 'pointer',
              fontWeight: 500,
            },
            title: '点击查看有效问题记录',
            onClick: (e: Event) => {
              e.stopPropagation();
              openRecordsWithFilter(row, dimKey, 'true', 'valid');
            },
          },
          String(validCount),
        ),
        h('span', { style: { color: '#d1d5db', margin: '0 1px' } }, '/'),
        h(
          'span',
          {
            style: { color: '#3b82f6', cursor: 'pointer', fontWeight: 500 },
            title: '点击查看全部监测记录',
            onClick: (e: Event) => {
              e.stopPropagation();
              openRecordsWithFilter(row, dimKey, '', '');
            },
          },
          String(total),
        ),
      ],
    );
  };
}

const taskColumns = computed<DataTableColumns<MonitorTask>>(() => [
  { key: 'index', title: '序号', width: 60, render: (_, i) => i + 1 },
  {
    key: 'target_homepage',
    title: '首页(URL)',
    minWidth: 200,
    ellipsis: { tooltip: true },
  },
  {
    key: 'task_name',
    title: '系统名称',
    minWidth: 130,
    ellipsis: { tooltip: true },
  },
  {
    key: 'target_ips',
    title: 'IP',
    minWidth: 130,
    ellipsis: { tooltip: true },
    render: (row) => row.target_ips || '-',
  },
  {
    title: '未处置 / 问题 / 总检测',
    align: 'center',
    key: 'stats',
    children: dimensions.map((dim) => ({
      key: `stat_${dim.key}`,
      title: dim.label,
      width: 120,
      align: 'center' as const,
      render: dimStatRender(dim.key),
    })),
  } as any,
  {
    key: 'enabled',
    title: '状态',
    width: 70,
    align: 'center',
    render: (row) =>
      h(
        'span',
        {
          style: {
            color: row.enabled ? '#22c55e' : '#6b7280',
            fontWeight: 500,
          },
        },
        row.enabled ? '启用' : '停止',
      ),
  },
  {
    key: 'op',
    title: '操作',
    width: 140,
    fixed: 'right',
    align: 'center',
    render: (row) =>
      h(NSpace, { size: 'small' }, () => [
        h(
          NPopconfirm,
          {
            onPositiveClick: () => handleRunTask(row),
          },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, type: 'primary', size: 'small' },
                { default: () => '监测' },
              ),
            default: () => '确认进行一次全维度监测？',
          },
        ),
        h(
          NButton,
          {
            text: true,
            type: 'info',
            size: 'small',
            onClick: () => {
              const tabPath = `/monitor/records/${row.id}`;
              tabbarStore.addTab({
                path: tabPath,
                name: `MonitorRecords_${row.id}`,
                meta: {
                  title: `${row.name} - 监测记录`,
                  hideInMenu: true,
                },
              });
              router.push(tabPath);
            },
          },
          { default: () => '记录' },
        ),
      ]),
  },
]);

// ── 监测记录弹窗 ──
const recordsTask = ref<MonitorTask | null>(null);
const recordsVisible = ref(false);
const recordsLoading = ref(false);
const recordsList = ref<MonitorExecution[]>([]);
const recordsPagination = reactive({
  page: 1,
  pageSize: 15,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 15, 20, 50],
});
const recordsFilter = reactive<{
  dimension: string;
  hasIssue: string;
  disposition: string;
  dateRange: [number, number] | null;
}>({ dateRange: null, dimension: '', disposition: '', hasIssue: '' });

const recordsStats = reactive({
  total: 0,
  success: 0,
  failed: 0,
  avgTime: 0,
  maxTime: 0,
  minTime: 0,
  issueCount: 0,
});

function calculateRecordsStats() {
  recordsStats.total = recordsList.value.length;
  recordsStats.success = recordsList.value.filter((r) => r.status === 'success').length;
  recordsStats.failed = recordsList.value.filter((r) => r.status === 'failed').length;
  recordsStats.issueCount = recordsList.value.filter((r) => r.has_issue).length;
  
  const times = recordsList.value
    .map((r) => r.duration_ms)
    .filter((t) => t != null && t > 0);
  if (times.length > 0) {
    recordsStats.avgTime = Math.round(times.reduce((a, b) => a + (b || 0), 0) / times.length);
    recordsStats.maxTime = Math.max(...times);
    recordsStats.minTime = Math.min(...times);
  } else {
    recordsStats.avgTime = 0;
    recordsStats.maxTime = 0;
    recordsStats.minTime = 0;
  }
}

const dimensionOpts = dimensions.map((d) => ({ label: d.label, value: d.key }));
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

function openRecordsWithFilter(
  row: MonitorTask,
  dimension: string,
  hasIssue: string,
  disposition = '',
) {
  recordsTask.value = row;
  recordsFilter.dimension = dimension;
  recordsFilter.hasIssue = hasIssue;
  recordsFilter.disposition = disposition;
  recordsFilter.dateRange = null;
  recordsPagination.page = 1;
  recordsVisible.value = true;
  loadRecords();
}

function openRecordsDrawer(row: MonitorTask) {
  openRecordsWithFilter(row, '', '');
}

async function loadRecords() {
  if (!recordsTask.value) return;
  recordsLoading.value = true;
  try {
    const params: any = {
      index: recordsPagination.page,
      size: recordsPagination.pageSize,
      task_id: recordsTask.value.id,
    };
    if (recordsFilter.dimension) params.dimension = recordsFilter.dimension;
    if (recordsFilter.hasIssue) params.has_issue = recordsFilter.hasIssue;
    if (recordsFilter.disposition)
      params.disposition = recordsFilter.disposition;
    if (recordsFilter.dateRange?.[0])
      params.time_start = dayjs(recordsFilter.dateRange[0]).format(
        'YYYY-MM-DD HH:mm:ss',
      );
    if (recordsFilter.dateRange?.[1])
      params.time_end = dayjs(recordsFilter.dateRange[1]).format(
        'YYYY-MM-DD HH:mm:ss',
      );
    const res = await getExecutionList(params);
    recordsList.value = res.data || [];
    recordsPagination.itemCount = (res as any).count || 0;
    calculateRecordsStats();
  } catch {
    recordsList.value = [];
  } finally {
    recordsLoading.value = false;
  }
}

const recordsColumns = computed<DataTableColumns<MonitorExecution>>(() => [
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
  { key: 'url', title: 'URL', minWidth: 180, ellipsis: { tooltip: true } },
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
      h(NSpace, { size: 4 }, () => [
        row.has_issue
          ? h(
              NButton,
              {
                circle: true,
                size: 'small',
                type: 'warning',
                onClick: () => openDispDialog(row),
                title: '处置',
              },
              { icon: () => h(IconifyIcon, { icon: 'ri:edit-2-line', class: 'text-sm' }) },
            )
          : null,
        h(
          NButton,
          {
            circle: true,
            size: 'small',
            type: 'primary',
            onClick: () => openDetailDrawer(row),
            title: '详情',
          },
          { icon: () => h(IconifyIcon, { icon: 'ri:eye-line', class: 'text-sm' }) },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDeleteExecution(row) },
          {
            trigger: () =>
              h(
                NButton,
                {
                  circle: true,
                  size: 'small',
                  type: 'error',
                  title: '删除',
                },
                { icon: () => h(IconifyIcon, { icon: 'ri:trash-2-line', class: 'text-sm' }) },
              ),
            default: () => '确认删除该条记录及相关证据文件？',
          },
        ),
      ]),
  },
]);

async function handleDeleteExecution(row: MonitorExecution) {
  try {
    await deleteExecution(row.id);
    message.success('删除成功');
    loadRecords();
    fetchTaskList();
  } catch (e: any) {
    message.error(e?.msg || '删除失败');
  }
}

function handleDeleteAllExecutions() {
  if (!recordsPagination.itemCount) {
    message.warning('当前列表无记录');
    return;
  }
  dialog.error({
    title: '危险操作',
    content: `确认删除任务「${recordsTask.value?.task_name}」当前筛选结果共 ${recordsPagination.itemCount} 条？同时清除相关证据文件，不可恢复！`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const params: any = {
          index: 1,
          size: 500,
          task_id: recordsTask.value!.id,
        };
        if (recordsFilter.dimension) params.dimension = recordsFilter.dimension;
        if (recordsFilter.hasIssue) params.has_issue = recordsFilter.hasIssue;
        if (recordsFilter.dateRange?.[0])
          params.time_start = dayjs(recordsFilter.dateRange[0]).format(
            'YYYY-MM-DD HH:mm:ss',
          );
        if (recordsFilter.dateRange?.[1])
          params.time_end = dayjs(recordsFilter.dateRange[1]).format(
            'YYYY-MM-DD HH:mm:ss',
          );
        const res = await getExecutionList(params);
        const ids = (res.data || []).map((r: MonitorExecution) => r.id);
        if (ids.length === 0) return;
        await batchDeleteExecutions(ids);
        message.success(`已删除 ${ids.length} 条记录`);
        loadRecords();
        fetchTaskList();
      } catch (e: any) {
        message.error(e?.msg || '批量删除失败');
      }
    },
  });
}

// ── 处置弹窗 ──
const dispDialogVisible = ref(false);
const dispTarget = ref<MonitorExecution | null>(null);
const dispForm = reactive({ disposition: '', remark: '' });
const dispLoading = ref(false);

function openDispDialog(row: MonitorExecution) {
  dispTarget.value = row;
  dispForm.disposition = row.disposition || 'pending';
  dispForm.remark = row.disposition_remark || '';
  dispDialogVisible.value = true;
}

async function submitDisposition() {
  if (!dispTarget.value) return;
  if (!dispForm.disposition) {
    message.warning('请选择处置状态');
    return;
  }
  dispLoading.value = true;
  try {
    await updateDisposition(
      dispTarget.value.id,
      dispForm.disposition,
      dispForm.remark,
    );
    message.success('处置成功');
    dispDialogVisible.value = false;
    loadRecords();
    fetchTaskList();
  } catch (e: any) {
    message.error(e?.msg || '处置失败');
  } finally {
    dispLoading.value = false;
  }
}

// ── 详情抽屉 ──
const detailVisible = ref(false);
const detailLoading = ref(false);
const detailData = ref<any>(null);
const detailExecId = ref('');

const detailParsedResult = computed(() => {
  if (!detailData.value?.result_json) return null;
  try {
    return JSON.parse(detailData.value.result_json);
  } catch {
    return null;
  }
});

async function openDetailDrawer(row: MonitorExecution) {
  detailData.value = null;
  detailExecId.value = row.id;
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

function execStatusType(s: string) {
  if (s === 'success') return 'success';
  if (s === 'failed') return 'error';
  if (s === 'running') return 'warning';
  return 'info';
}
</script>

<template>
  <Page title="风险监测" description="网站监测全局总览与任务管理">
    <template #extra>
      <NSpace :size="12" align="center">
        <NTag v-if="lastRefreshAt" type="default" size="small" round>
          上次刷新：{{ lastRefreshAt }}
        </NTag>
        <span class="text-muted-foreground text-xs">自动刷新</span>
        <NSwitch v-model:value="autoRefreshEnabled" size="small" />
        <NSelect
          v-model:value="autoRefreshInterval"
          :options="refreshIntervalOptions"
          :disabled="!autoRefreshEnabled"
          size="small"
          style="width: 100px"
        />
        <NButton
          size="small"
          type="primary"
          :loading="loading"
          @click="fetchDashboardStats"
        >
          立即刷新
        </NButton>
      </NSpace>
    </template>

    <!-- 顶部统计卡片 -->
    <NGrid cols="2 m:4" :x-gap="16" :y-gap="16" responsive="screen" class="stats-grid">
      <NGi>
        <div class="stat-card stat-card--blue">
          <div class="stat-icon">
            <IconifyIcon icon="ri:task-line" class="text-2xl" />
          </div>
          <div class="stat-content">
            <div class="stat-value">{{ stats.totalTasks }}</div>
            <div class="stat-label">监测任务</div>
            <div class="stat-sub">已启用 {{ stats.enabledTasks }}</div>
          </div>
        </div>
      </NGi>
      <NGi>
        <div class="stat-card stat-card--orange">
          <div class="stat-icon">
            <IconifyIcon icon="ri:file-chart-line" class="text-2xl" />
          </div>
          <div class="stat-content">
            <div class="stat-value">{{ stats.totalExecutions }}</div>
            <div class="stat-label">执行记录</div>
            <div class="stat-sub" :class="stats.issueExecutions > 0 ? 'text-error' : ''">
              发现问题 {{ stats.issueExecutions }}
            </div>
          </div>
        </div>
      </NGi>
      <NGi>
        <div class="stat-card stat-card--green">
          <div class="stat-icon">
            <IconifyIcon icon="ri:robot-line" class="text-2xl" />
          </div>
          <div class="stat-content">
            <div class="stat-value">{{ stats.totalAgents }}</div>
            <div class="stat-label">Agent 节点</div>
            <div class="stat-sub text-success">在线 {{ stats.onlineAgents }}</div>
          </div>
        </div>
      </NGi>
      <NGi>
        <div class="stat-card stat-card--purple">
          <div class="stat-icon">
            <IconifyIcon icon="ri:shield-check-line" class="text-2xl" />
          </div>
          <div class="stat-content">
            <div class="stat-value">6</div>
            <div class="stat-label">监测维度</div>
            <div class="stat-sub">可用性/篡改/暗链/敏感词/敏感文件/域名劫持</div>
          </div>
        </div>
      </NGi>
    </NGrid>

    <!-- 维度统计 -->
    <NGrid
      cols="2 s:3 m:6"
      :x-gap="12"
      :y-gap="12"
      responsive="screen"
      class="mt-4"
    >
      <NGi v-for="item in dimensionCards" :key="item.key">
        <div class="dim-card" :style="{ '--dim-color': item.color }">
          <div class="dim-header">
            <span class="dim-label">{{ item.label }}</span>
            <IconifyIcon :icon="item.icon" class="dim-icon" />
          </div>
          <div class="dim-body">
            <div class="dim-item">
              <span class="dim-item-label">监测次数</span>
              <span class="dim-item-value">{{ item.total }}</span>
            </div>
            <div class="dim-item">
              <span class="dim-item-label">发现问题</span>
              <span class="dim-item-value" :class="item.issueCount > 0 ? 'text-error' : ''">
                {{ item.issueCount }}
              </span>
            </div>
          </div>
        </div>
      </NGi>
    </NGrid>

    <!-- Tab 切换区 -->
    <NCard class="mt-4">
      <NTabs type="line" v-model:value="activeTab" class="tab-container">
        <NTabPane name="tasks" tab="监测任务">
          <!-- 搜索栏 -->
          <div class="filter-bar">
            <NSpace align="center" wrap>
              <NFormItem label="系统名称" label-width="70">
                <NInput
                  v-model:value="taskForm.name"
                  placeholder="请输入系统名称"
                  clearable
                  style="width: 200px"
                />
              </NFormItem>
              <NFormItem label="状态" label-width="40">
                <NSelect
                  v-model:value="taskForm.enabled"
                  placeholder="全部"
                  clearable
                  style="width: 120px"
                  :options="[
                    { label: '启用', value: 'true' },
                    { label: '停止', value: 'false' },
                  ]"
                />
              </NFormItem>
              <NSpace :size="8">
                <NButton
                  type="primary"
                  size="small"
                  @click="
                    () => {
                      taskPagination.page = 1;
                      fetchTaskList();
                    }
                  "
                >
                  查询
                </NButton>
                <NButton
                  size="small"
                  @click="
                    () => {
                      taskForm.name = '';
                      taskForm.enabled = '';
                      taskPagination.page = 1;
                      fetchTaskList();
                    }
                  "
                >
                  重置
                </NButton>
                <NButton size="small" @click="fetchTaskList">刷新</NButton>
              </NSpace>
            </NSpace>
          </div>

          <!-- 任务表格 -->
          <NDataTable
            :columns="taskColumns"
            :data="taskDataList"
            :loading="taskLoading"
            :pagination="taskPagination"
            :row-key="(r: MonitorTask) => r.id"
            remote
            size="small"
            :scroll-x="1600"
            class="task-table"
            @update:page="
              (p: number) => {
                taskPagination.page = p;
                fetchTaskList();
              }
            "
            @update:page-size="
              (s: number) => {
                taskPagination.pageSize = s;
                taskPagination.page = 1;
                fetchTaskList();
              }
            "
          />
        </NTabPane>

        <NTabPane name="executions" tab="执行记录">
          <NDataTable
            :columns="executionColumns"
            :data="recentExecutions"
            :loading="loading"
            :max-height="500"
            :row-key="(r: MonitorExecution) => r.id"
            size="small"
            class="exec-table"
          />
        </NTabPane>

        <NTabPane name="agents" tab="Agent 状态">
          <NDataTable
            :columns="agentColumns"
            :data="agentList"
            :loading="loading"
            :max-height="500"
            :row-key="(r: MonitorAgent) => r.uuid"
            size="small"
            class="agent-table"
          />
        </NTabPane>
      </NTabs>
    </NCard>

    <!-- 监测记录弹窗 -->
    <NModal
      v-model:show="recordsVisible"
      preset="card"
      :title="`监测记录 — ${recordsTask?.task_name || ''}`"
      style="width: 1300px"
      :bordered="false"
      class="records-modal"
    >
      <!-- 统计概览 -->
      <div class="records-stats mb-4">
        <div class="stat-item">
          <span class="stat-label">检测次数</span>
          <span class="stat-value">{{ recordsStats.total }}</span>
        </div>
        <div class="stat-divider"></div>
        <div class="stat-item">
          <span class="stat-label">成功</span>
          <span class="stat-value stat-success">{{ recordsStats.success }}</span>
        </div>
        <div class="stat-divider"></div>
        <div class="stat-item">
          <span class="stat-label">失败</span>
          <span class="stat-value stat-error">{{ recordsStats.failed }}</span>
        </div>
        <div class="stat-divider"></div>
        <div class="stat-item">
          <span class="stat-label">平均耗时</span>
          <span class="stat-value">{{ recordsStats.avgTime }} ms</span>
        </div>
        <div class="stat-divider"></div>
        <div class="stat-item">
          <span class="stat-label">发现问题</span>
          <span class="stat-value" :class="recordsStats.issueCount > 0 ? 'stat-error' : ''">
            {{ recordsStats.issueCount }}
          </span>
        </div>
      </div>

      <!-- 筛选区域 -->
      <div class="records-filter">
        <NSpace align="center" wrap>
          <NFormItem label="维度" label-width="40">
            <NSelect
              v-model:value="recordsFilter.dimension"
              placeholder="全部"
              clearable
              size="small"
              style="width: 120px"
              :options="dimensionOpts"
            />
          </NFormItem>
          <NFormItem label="状态" label-width="40">
            <NSelect
              v-model:value="recordsFilter.hasIssue"
              placeholder="全部"
              clearable
              size="small"
              style="width: 110px"
              :options="issueOpts"
            />
          </NFormItem>
          <NFormItem label="处置" label-width="40">
            <NSelect
              v-model:value="recordsFilter.disposition"
              placeholder="全部"
              clearable
              size="small"
              style="width: 110px"
              :options="dispositionOptions"
            />
          </NFormItem>
          <NFormItem label="时间" label-width="40">
            <NDatePicker
              v-model:value="recordsFilter.dateRange"
              type="datetimerange"
              clearable
              size="small"
              style="width: 340px"
            />
          </NFormItem>
          <NSpace :size="8">
            <NButton
              type="primary"
              size="small"
              @click="
                () => {
                  recordsPagination.page = 1;
                  loadRecords();
                }
              "
            >
              查询
            </NButton>
            <NButton
              size="small"
              @click="
                () => {
                  recordsFilter.dimension = '';
                  recordsFilter.hasIssue = '';
                  recordsFilter.disposition = '';
                  recordsFilter.dateRange = null;
                  recordsPagination.page = 1;
                  loadRecords();
                }
              "
            >
              重置
            </NButton>
            <NButton type="error" size="small" @click="handleDeleteAllExecutions">
              全部删除
            </NButton>
            <NButton circle size="small" @click="loadRecords" title="刷新">
              <IconifyIcon icon="ri:refresh-line" class="text-sm" />
            </NButton>
          </NSpace>
        </NSpace>
      </div>

      <NDataTable
        :columns="recordsColumns"
        :data="recordsList"
        :loading="recordsLoading"
        :pagination="recordsPagination"
        :row-key="(r: MonitorExecution) => r.id"
        remote
        size="small"
        @update:page="
          (p: number) => {
            recordsPagination.page = p;
            loadRecords();
          }
        "
        @update:page-size="
          (s: number) => {
            recordsPagination.pageSize = s;
            recordsPagination.page = 1;
            loadRecords();
          }
        "
      />
    </NModal>

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
              <NDescriptions :column="2" bordered size="small">
                <NDescriptionsItem label="监测ID" :span="2">
                  <span class="font-mono text-xs">{{ detailData.id }}</span>
                </NDescriptionsItem>
                <NDescriptionsItem label="状态">
                  <NTag
                    :type="execStatusType(detailData.status)"
                    size="small"
                    :bordered="false"
                  >
                    {{ statusLabel(detailData.status) }}
                  </NTag>
                </NDescriptionsItem>
                <NDescriptionsItem label="安全问题">
                  <NTag
                    :type="detailData.has_issue ? 'error' : 'success'"
                    size="small"
                    :bordered="false"
                  >
                    {{ detailData.has_issue ? '⚠ 发现问题' : '无' }}
                  </NTag>
                </NDescriptionsItem>
                <NDescriptionsItem label="目标URL" :span="2">
                  <span class="font-mono break-all text-xs">
                    {{ detailData.url }}
                  </span>
                </NDescriptionsItem>
                <NDescriptionsItem label="开始时间">
                  {{ fmtTime(detailData.started_at) }}
                </NDescriptionsItem>
                <NDescriptionsItem label="结束时间">
                  {{ fmtTime(detailData.finished_at) }}
                </NDescriptionsItem>
                <NDescriptionsItem label="创建时间">
                  {{ fmtTime(detailData.created_at) }}
                </NDescriptionsItem>
                <NDescriptionsItem
                  v-if="detailData.error"
                  label="错误信息"
                  :span="2"
                >
                  <span class="text-error font-mono text-sm">
                    {{ detailData.error }}
                  </span>
                </NDescriptionsItem>
              </NDescriptions>
            </NCard>

            <template v-if="detailParsedResult">
              <AvailabilityDetail
                v-if="detailData.dimension === 'availability'"
                :result="detailParsedResult"
                class="mb-3"
              />
              <TamperDetail
                v-else-if="detailData.dimension === 'tamper'"
                :result="detailParsedResult"
                :execution-id="detailExecId"
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
            </template>

            <NCard
              v-else-if="detailData.status === 'failed'"
              size="small"
              class="mb-3"
            >
              <NEmpty description="监测失败，无结果数据">
                <template #extra>
                  <div class="text-error mt-2 text-sm">
                    {{ detailData.error || '监测异常，未返回结果' }}
                  </div>
                </template>
              </NEmpty>
            </NCard>

            <NCard
              v-if="detailData.result_json"
              size="small"
              class="mb-3"
            >
              <NCollapse>
                <NCollapseItem
                  title="原始 result_json（调试用）"
                  name="raw"
                >
                  <NInput
                    type="textarea"
                    :value="JSON.stringify(detailParsedResult, null, 2)"
                    readonly
                    :rows="16"
                    class="font-mono"
                  />
                </NCollapseItem>
              </NCollapse>
            </NCard>
          </template>
          <NEmpty v-else-if="!detailLoading" description="暂无数据" />
        </NSpin>
      </NDrawerContent>
    </NDrawer>

    <!-- 处置弹窗 -->
    <NModal
      v-model:show="dispDialogVisible"
      preset="card"
      title="问题处置"
      style="width: 480px"
    >
      <NForm label-placement="left" label-width="80">
        <NFormItem label="处置状态">
          <NRadioGroup v-model:value="dispForm.disposition">
            <NRadio value="valid">有效</NRadio>
            <NRadio value="invalid">无效</NRadio>
            <NRadio value="false_positive">误报</NRadio>
          </NRadioGroup>
        </NFormItem>
        <NFormItem label="处置备注">
          <NInput
            v-model:value="dispForm.remark"
            type="textarea"
            :rows="3"
            placeholder="请输入处置备注（可选）"
          />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="dispDialogVisible = false">取消</NButton>
          <NButton
            type="primary"
            :loading="dispLoading"
            @click="submitDisposition"
          >
            确认处置
          </NButton>
        </NSpace>
      </template>
    </NModal>
  </Page>
</template>

<style scoped>
.activeTab {
  color: var(--n-primary-color);
}

.stats-grid {
  margin-bottom: 0;
}

.stat-card {
  display: flex;
  align-items: center;
  padding: 20px;
  border-radius: 12px;
  background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
  border-left: 4px solid;
  transition: all 0.2s ease;
}

.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
}

.stat-card--blue {
  border-color: #3b82f6;
}

.stat-card--blue .stat-icon {
  color: #3b82f6;
}

.stat-card--orange {
  border-color: #f59e0b;
}

.stat-card--orange .stat-icon {
  color: #f59e0b;
}

.stat-card--green {
  border-color: #22c55e;
}

.stat-card--green .stat-icon {
  color: #22c55e;
}

.stat-card--purple {
  border-color: #8b5cf6;
}

.stat-card--purple .stat-icon {
  color: #8b5cf6;
}

.stat-icon {
  width: 50px;
  height: 50px;
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0.7;
}

.stat-content {
  flex: 1;
  padding-left: 16px;
}

.stat-value {
  font-size: 28px;
  font-weight: 700;
  color: var(--n-text-color);
  line-height: 1.2;
}

.stat-label {
  font-size: 13px;
  color: var(--n-text-color-3);
  margin-top: 4px;
}

.stat-sub {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-top: 2px;
}

.dim-card {
  padding: 16px;
  border-radius: 10px;
  background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
  border: 1px solid var(--n-border-color);
  transition: all 0.2s ease;
}

.dim-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.06);
}

.dim-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.dim-label {
  font-weight: 600;
  color: var(--n-text-color);
}

.dim-icon {
  font-size: 20px;
  color: var(--dim-color);
}

.dim-body {
  display: flex;
  justify-content: space-between;
}

.dim-item {
  text-align: center;
}

.dim-item-label {
  display: block;
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 4px;
}

.dim-item-value {
  font-size: 18px;
  font-weight: 600;
  color: var(--n-text-color);
}

.tab-container {
  --n-tab-color: var(--n-text-color-3);
  --n-tab-color-active: var(--n-primary-color);
  --n-tab-bottom-border-color-active: var(--n-primary-color);
}

.filter-bar {
  padding: 12px 16px;
  background: var(--n-color-embedded);
  border-radius: 8px;
  margin-bottom: 16px;
}

.filter-bar :deep(.n-form-item) {
  margin-bottom: 0;
}

.task-table :deep(.n-data-table-th) {
  background: var(--n-color-embedded);
}

.task-table :deep(.n-data-table-tr:hover .n-data-table-td) {
  background: rgba(59, 130, 246, 0.05);
}

.exec-table :deep(.n-data-table-th) {
  background: var(--n-color-embedded);
}

.exec-table :deep(.n-data-table-tr:hover .n-data-table-td) {
  background: rgba(59, 130, 246, 0.05);
}

.agent-table :deep(.n-data-table-th) {
  background: var(--n-color-embedded);
}

.agent-table :deep(.n-data-table-tr:hover .n-data-table-td) {
  background: rgba(59, 130, 246, 0.05);
}

.records-modal :deep(.n-modal-body) {
  max-height: 75vh;
  overflow-y: auto;
}

.records-stats {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  padding: 16px 20px;
  background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
  border-radius: 10px;
  border: 1px solid var(--n-border-color);
}

.stat-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 0 24px;
}

.stat-label {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 4px;
}

.stat-value {
  font-size: 20px;
  font-weight: 600;
  color: var(--n-text-color);
}

.stat-value.stat-success {
  color: #22c55e;
}

.stat-value.stat-error {
  color: #ef4444;
}

.stat-divider {
  width: 1px;
  height: 40px;
  background: var(--n-border-color);
}

.records-filter {
  padding: 12px 16px;
  background: var(--n-color-embedded);
  border-radius: 8px;
  margin-bottom: 16px;
}

.records-filter :deep(.n-form-item) {
  margin-bottom: 0;
}

.records-filter :deep(.n-select-trigger) {
  height: 28px;
}

.records-filter :deep(.n-input) {
  height: 28px;
}

.records-filter :deep(.n-date-picker-trigger) {
  height: 28px;
}
</style>
