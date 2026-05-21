<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import type {
  DashboardStats,
  MonitorExecution,
  MonitorTask,
} from '#/api/sitemonitor';

import { computed, h, reactive, ref, watch } from 'vue';
import { useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';
import { IconifyIcon } from '@vben/icons';
import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NDataTable,
  NDatePicker,
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
  NSwitch,
  NTag,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  batchDeleteExecutions,
  deleteExecution,
  getDashboardStats,
  getExecutionList,
  getTaskExecutionStats,
  getTaskList,
  runTask,
  updateDisposition,
} from '#/api/sitemonitor';
import { useAutoRefresh } from '#/composables/useAutoRefresh';
import { useMonitorRecordDetail } from './composables/useMonitorRecordDetail';
import { useOpenTaskRecordsTab } from './composables/useOpenTaskRecordsTab';

defineOptions({ name: 'MonitorCenter' });

const router = useRouter();
const { openRecordDetail } = useMonitorRecordDetail();
const { openTaskRecordsTab } = useOpenTaskRecordsTab();
const loading = ref(false);

const stats = reactive({
  enabledTasks: 0,
  issueExecutions: 0,
  onlineAgents: 0,
  totalAgents: 0,
  totalExecutions: 0,
  totalTasks: 0,
});

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

const taskNameMap = computed<Record<string, string>>(() =>
  Object.fromEntries(
    taskDataList.value
      .filter((item) => item.id && item.task_name)
      .map((item) => [item.id, item.task_name]),
  ),
);

const statusLabel = (v: string) =>
  ({
    failed: '失败',
    pending: '等待中',
    running: '运行中',
    success: '成功',
  })[v] ?? v;

const fmtTime = (v: string) =>
  v ? dayjs(v).format('YYYY-MM-DD HH:mm:ss') : '-';

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

const issueDimensionCards = computed(() =>
  [...dimensionCards.value]
    .filter((item) => item.issueCount > 0)
    .sort((a, b) => b.issueCount - a.issueCount),
);

const selectedDimension = ref('');
const centerIssueLoading = ref(false);
const centerIssueList = ref<MonitorExecution[]>([]);
const centerIssueFilter = reactive({ disposition: 'pending' });
const centerIssuePagination = reactive({
  page: 1,
  pageSize: 15,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 15, 20, 50],
});

const selectedDimensionLabel = computed(
  () => dimMap[selectedDimension.value] || '监测维度',
);

function selectDimension(key: string) {
  selectedDimension.value = key;
  centerIssuePagination.page = 1;
  loadCenterIssues();
}

function ensureDefaultDimension() {
  if (selectedDimension.value) return;
  const firstWithIssues = issueDimensionCards.value[0]?.key;
  selectedDimension.value = firstWithIssues || dimensions[0]?.key || '';
}

async function loadCenterIssues() {
  if (!selectedDimension.value) return;
  centerIssueLoading.value = true;
  try {
    const params: Record<string, string | number> = {
      dimension: selectedDimension.value,
      disposition: centerIssueFilter.disposition,
      has_issue: 'true',
      index: centerIssuePagination.page,
      size: centerIssuePagination.pageSize,
    };
    const res = await getExecutionList(params);
    centerIssueList.value = res.data || [];
    centerIssuePagination.itemCount = (res as any).count || 0;
  } catch {
    centerIssueList.value = [];
    centerIssuePagination.itemCount = 0;
  } finally {
    centerIssueLoading.value = false;
  }
}

const lastRefreshAt = ref<null | string>(null);

async function fetchDashboardStats() {
  loading.value = true;
  try {
    const [statsRes, taskStatsRes, taskRes] = await Promise.all([
      getDashboardStats(),
      getTaskExecutionStats(),
      getTaskList({ index: 1, size: 200 }),
    ]);
    const overview = ((statsRes as any)?.data ?? statsRes ?? {}) as DashboardStats;
    stats.totalTasks =
      overview.total_path_tasks ?? (overview as any).total_tasks ?? overview.total_targets ?? 0;
    stats.enabledTasks =
      overview.enabled_path_tasks ?? (overview as any).enabled_tasks ?? overview.enabled_targets ?? 0;
    stats.totalExecutions = overview.total_executions || 0;
    stats.issueExecutions = overview.issue_executions || 0;
    stats.onlineAgents = overview.online_agents || 0;
    stats.totalAgents = overview.total_agents || 0;
    taskStatsMap.value = (taskStatsRes as any)?.data ?? taskStatsRes ?? {};
    taskDataList.value = taskRes.data || [];
    lastRefreshAt.value = dayjs().format('HH:mm:ss');
    ensureDefaultDimension();
    await loadCenterIssues();
  } finally {
    loading.value = false;
  }
}

async function refreshAll() {
  await fetchDashboardStats();
}

watch(
  () => centerIssueFilter.disposition,
  () => {
    centerIssuePagination.page = 1;
    loadCenterIssues();
  },
);

const refreshIntervalOptions = [
  { label: '10 秒', value: 10_000 },
  { label: '30 秒', value: 30_000 },
  { label: '1 分钟', value: 60_000 },
  { label: '5 分钟', value: 300_000 },
];

const { enabled: autoRefreshEnabled, interval: autoRefreshInterval } =
  useAutoRefresh({
    task: refreshAll,
    interval: 30_000,
    immediate: true,
    runOnMount: true,
  });

function goToIssues(query?: Record<string, string>) {
  router.push({ path: '/monitor/issues', query });
}

const centerIssueColumns = computed<DataTableColumns<MonitorExecution>>(() => [
  {
    key: 'task_name',
    title: '任务名称',
    minWidth: 160,
    ellipsis: { tooltip: true },
    render: (row) =>
      (row as any).task_name ||
      taskNameMap.value[row.task_id] ||
      taskNameMap.value[row.path_task_id] ||
      row.path_task_id ||
      '-',
  },
  { key: 'url', title: 'URL', minWidth: 200, ellipsis: { tooltip: true } },
  {
    key: 'status',
    title: '状态',
    width: 90,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        { type: execStatusType(row.status), size: 'small', bordered: false },
        () => statusLabel(row.status),
      ),
  },
  {
    key: 'disposition',
    title: '处置',
    width: 90,
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
        () => dispositionLabelMap[d] || d,
      );
    },
  },
  {
    key: 'created_at',
    title: '时间',
    width: 170,
    align: 'center',
    render: (row) => fmtTime(row.created_at),
  },
  {
    key: 'op',
    title: '操作',
    width: 200,
    fixed: 'right',
    align: 'center',
    render: (row) =>
      h(NSpace, { size: 4 }, () => [
        h(
          NButton,
          { text: true, type: 'primary', size: 'small', onClick: () => openDetailDrawer(row) },
          () => '详情',
        ),
        h(
          NButton,
          { text: true, type: 'warning', size: 'small', onClick: () => openDispDialog(row) },
          () => '处置',
        ),
        h(
          NButton,
          {
            text: true,
            type: 'success',
            size: 'small',
            onClick: async () => {
              await updateDisposition(row.id, 'valid');
              message.success('已标记为有效');
              loadCenterIssues();
              fetchDashboardStats();
            },
          },
          () => '有效',
        ),
        h(
          NButton,
          {
            text: true,
            size: 'small',
            onClick: async () => {
              await updateDisposition(row.id, 'false_positive');
              message.success('已标记为误报');
              loadCenterIssues();
              fetchDashboardStats();
            },
          },
          () => '误报',
        ),
      ]),
  },
]);

// ── 监测任务表格 ──
const taskLoading = ref(false);
const taskDataList = ref<MonitorTask[]>([]);
const taskForm = reactive({ enabled: '', name: '', target_homepage: '' });
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
        target_homepage: taskForm.target_homepage,
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
            onClick: () =>
              openTaskRecordsTab({
                id: row.id,
                task_name: row.task_name,
              }),
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
    loadCenterIssues();
    fetchDashboardStats();
    fetchTaskList();
  } catch (e: any) {
    message.error(e?.msg || '处置失败');
  } finally {
    dispLoading.value = false;
  }
}

function openDetailDrawer(row: MonitorExecution) {
  openRecordDetail(row.id, {
    taskId: row.path_task_id || row.task_id,
    from: 'tasks',
  });
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
          @click="refreshAll"
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
            <div
              class="stat-sub stat-sub--link"
              :class="stats.issueExecutions > 0 ? 'text-error' : ''"
              @click="goToIssues({ hasIssue: 'true', disposition: 'pending' })"
            >
              发现问题 {{ stats.issueExecutions }} · 去处置
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
        <div
          class="dim-card"
          :class="{ 'dim-card--active': selectedDimension === item.key }"
          :style="{ '--dim-color': item.color }"
          role="button"
          tabindex="0"
          @click="selectDimension(item.key)"
          @keydown.enter="selectDimension(item.key)"
        >
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
    <div v-if="issueDimensionCards.length > 0" class="issue-banner mt-4">
      <div class="issue-banner__title">
        <IconifyIcon icon="ri:alarm-warning-line" />
        <span>当前重点风险维度</span>
      </div>
      <div class="issue-banner__list">
        <span
          v-for="item in issueDimensionCards.slice(0, 4)"
          :key="item.key"
          class="issue-pill issue-pill--link"
          :style="{ '--issue-color': item.color }"
          @click="selectDimension(item.key)"
        >
          {{ item.label }} {{ item.issueCount }}
        </span>
      </div>
      <NButton
        size="small"
        type="error"
        ghost
        @click="goToIssues({ hasIssue: 'true', disposition: 'pending' })"
      >
        查看全部待处置问题
      </NButton>
    </div>

    <NCard class="mt-4 issue-records-card" size="small">
      <template #header>
        <NSpace align="center" :size="8">
          <span class="issue-records-card__title">{{ selectedDimensionLabel }} — 问题记录</span>
          <NTag size="small" :bordered="false" type="error">
            共 {{ centerIssuePagination.itemCount }} 条
          </NTag>
        </NSpace>
      </template>
      <template #header-extra>
        <NSpace :size="8" align="center">
          <NSelect
            v-model:value="centerIssueFilter.disposition"
            :options="dispositionOptions"
            size="small"
            style="width: 110px"
          />
          <NButton
            text
            type="primary"
            size="small"
            @click="
              goToIssues({
                dimension: selectedDimension,
                disposition: centerIssueFilter.disposition,
                hasIssue: 'true',
              })
            "
          >
            完整问题处置
          </NButton>
          <NButton text type="primary" size="small" @click="router.push('/monitor/targets')">
            网站监测
          </NButton>
        </NSpace>
      </template>
      <NDataTable
        :columns="centerIssueColumns"
        :data="centerIssueList"
        :loading="centerIssueLoading"
        :pagination="centerIssuePagination"
        :row-key="(r: MonitorExecution) => r.id"
        remote
        size="small"
        :scroll-x="900"
        class="exec-table"
        @update:page="
          (p: number) => {
            centerIssuePagination.page = p;
            loadCenterIssues();
          }
        "
        @update:page-size="
          (s: number) => {
            centerIssuePagination.pageSize = s;
            centerIssuePagination.page = 1;
            loadCenterIssues();
          }
        "
      >
        <template #empty>
          <NEmpty description="该维度暂无待查看的问题记录" />
        </template>
      </NDataTable>
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
  cursor: pointer;
}

.dim-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.06);
}

.dim-card--active {
  border-color: var(--dim-color);
  box-shadow: 0 0 0 1px color-mix(in srgb, var(--dim-color) 35%, transparent);
  background: linear-gradient(
    135deg,
    color-mix(in srgb, var(--dim-color) 6%, white) 0%,
    #f8fafc 100%
  );
}

.issue-records-card__title {
  font-weight: 600;
  font-size: 15px;
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

.issue-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 16px;
  border: 1px solid rgba(245, 158, 11, 0.2);
  border-radius: 12px;
  background: linear-gradient(135deg, rgba(255, 251, 235, 0.95) 0%, rgba(255, 247, 237, 0.98) 100%);
}

.issue-banner__title {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #b45309;
  font-weight: 600;
}

.issue-banner__title > span {
  font-size: 0;
}

.issue-banner__title > span::after {
  content: '当前重点风险维度';
  font-size: 14px;
}

.issue-banner__list {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
}

.issue-pill {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  border-radius: 999px;
  background: color-mix(in srgb, var(--issue-color) 10%, white);
  color: var(--issue-color);
  font-size: 12px;
  font-weight: 600;
}

.stat-sub--link,
.issue-pill--link {
  cursor: pointer;
}

.stat-sub--link:hover {
  text-decoration: underline;
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

@media (max-width: 1200px) {
  .preview-layout {
    grid-template-columns: 1fr;
  }

  .issue-banner {
    flex-direction: column;
    align-items: flex-start;
  }

  .issue-banner__list {
    justify-content: flex-start;
  }
}
</style>
