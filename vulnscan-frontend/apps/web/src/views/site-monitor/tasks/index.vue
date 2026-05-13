<script lang="ts" setup>
import type { DataTableColumns, UploadFileInfo } from 'naive-ui';

import type {
  DimensionConfig,
  FileLibrary,
  ImportResult,
  MonitorExecution,
  MonitorTask,
  WordLibrary,
} from '#/api/sitemonitor';

import { computed, h, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';

import { BarChart, LineChart } from 'echarts/charts';
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
  NAlert,
  NButton,
  NCard,
  NCol,
  NCollapse,
  NCollapseItem,
  NDataTable,
  NDatePicker,
  NDescriptions,
  NDescriptionsItem,
  NDivider,
  NDrawer,
  NDrawerContent,
  NDropdown,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NRadio,
  NRadioGroup,
  NRow,
  NSelect,
  NSpace,
  NSpin,
  NStatistic,
  NSwitch,
  NTag,
  NUpload,
  NUploadDragger,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import { useErrorHandler } from '#/composables/useErrorHandler';
import {
  batchDeleteExecutions,
  batchDeleteTasks,
  batchSyncNames,
  batchToggleEnabled,
  batchUpdateConfigs,
  createTask,
  deleteExecution,
  deleteTask,
  downloadImportTemplate,
  exportImportResultUrl,
  fetchTaskMeta,
  getDefaultConfigList,
  getExecutionDetail,
  getExecutionList,
  getFileLibraryList,
  getTaskList,
  getTaskTrend,
  getWordLibraryList,
  importTasks,
  runTask,
  updateDisposition,
  updateTask,
} from '#/api/sitemonitor';

import AvailabilityDetail from '../executions/components/AvailabilityDetail.vue';
import BlacklinkDetail from '../executions/components/BlacklinkDetail.vue';
import DomainHijackDetail from '../executions/components/DomainHijackDetail.vue';
import SensitiveFileDetail from '../executions/components/SensitiveFileDetail.vue';
import SensitiveWordDetail from '../executions/components/SensitiveWordDetail.vue';
import TamperDetail from '../executions/components/TamperDetail.vue';
import DimensionConfigForm from './components/DimensionConfigForm.vue';

defineOptions({ name: 'MonitorTasks' });

const router = useRouter();
const { handleError } = useErrorHandler();
const loading = ref(false);
const dataList = ref<MonitorTask[]>([]);
const safeDataList = computed(() =>
  Array.isArray(dataList.value) ? dataList.value : [],
);
const checkedRowKeys = ref<string[]>([]);

const form = reactive({ enabled: '', name: '' });

const pagination = reactive({
  itemCount: 0,
  page: 1,
  pageSize: 15,
  pageSizes: [15, 30, 50, 100],
  showSizePicker: true,
});

const dimensions = [
  { key: 'availability', label: '可用性' },
  { key: 'domain_hijack', label: '域名劫持' },
  { key: 'tamper', label: '篡改' },
  { key: 'sensitive_word', label: '敏感词' },
  { key: 'sensitive_file', label: '敏感文件' },
  { key: 'blacklink', label: '黑链/挂马' },
];

const dimLabelMap: Record<string, string> = {
  availability: '可用性',
  blacklink: '暗链监测',
  domain_hijack: '域名劫持',
  sensitive_file: '敏感文件',
  sensitive_word: '敏感词',
  tamper: '篡改监测',
};

type TagType = 'default' | 'error' | 'info' | 'primary' | 'success' | 'warning';

const execStatusType = (s: string): TagType => {
  if (s === 'success') return 'success';
  if (s === 'failed') return 'error';
  if (s === 'running') return 'warning';
  return 'info';
};

const execStatusLabel = (s: string) =>
  ({
    failed: '失败',
    pending: '等待中',
    running: '运行中',
    success: '成功',
  })[s] || s;

const cycleRender = (row: MonitorTask, dimKey: string) => {
  const cfg = row[`config_${dimKey}` as keyof MonitorTask] as
    | DimensionConfig
    | undefined;
  if (!cfg?.enabled) return h('span', { class: 'text-muted-foreground' }, '关');
  let text = '开';
  if (cfg.cycle_minutes) text = `${cfg.cycle_minutes}`;
  else if (cfg.cycle_type) {
    const map: Record<string, string> = {
      daily: '日',
      monthly: '月',
      quarterly: '季',
      semi_annual: '半年',
      weekly: '周',
    };
    text = map[cfg.cycle_type] || cfg.cycle_type;
  }
  return h('span', { class: 'font-medium text-success' }, text);
};

const columns = computed<DataTableColumns<MonitorTask>>(() => [
  { type: 'selection' },
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
    key: 'asset_id',
    title: '关联资产',
    width: 90,
    render: (row: MonitorTask) => row.asset_id
      ? h(NButton, { text: true, type: 'info', size: 'small', onClick: () => { window.open(`/asset/ledger?id=${row.asset_id}`, '_blank'); } }, { default: () => '查看' })
      : h('span', { style: 'color: #ccc' }, '-'),
  },
  {
    key: 'target_ips',
    title: 'IP',
    minWidth: 140,
    ellipsis: { tooltip: true },
    render: (row) => row.target_ips || '-',
  },
  {
    key: 'frequency',
    title: '监测频率',
    align: 'center',
    children: dimensions.map((dim) => ({
      align: 'center' as const,
      key: `dim_${dim.key}`,
      render: (row: MonitorTask) => cycleRender(row, dim.key),
      title: dim.label,
      width: 80,
    })),
  },
  {
    key: 'enabled',
    title: '状态',
    width: 70,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        {
          type: row.enabled ? 'success' : 'default',
          size: 'small',
          bordered: false,
        },
        { default: () => (row.enabled ? '启用' : '停止') },
      ),
  },
  {
    key: 'schedule',
    title: '定时调度',
    width: 120,
    align: 'center',
    render: (row) => {
      const se = (row as any).schedule_enabled;
      if (!se)
        return h(NTag, { size: 'small', bordered: false }, { default: () => '未启用' });
      return h(
        NTag,
        { type: 'info', size: 'small', bordered: false },
        { default: () => '已启用' },
      );
    },
  },
  {
    key: 'op',
    title: '操作',
    width: 380,
    fixed: 'right',
    align: 'center',
    render: (row) =>
      h(NSpace, { size: 'small', justify: 'center' }, () => [
        h(
          NButton,
          {
            text: true,
            type: 'primary',
            size: 'small',
            onClick: () => openDrawer(row),
          },
          { default: () => '配置' },
        ),
        h(
          NButton,
          {
            text: true,
            type: 'info',
            size: 'small',
            onClick: () => {
              router.push(`/monitor/records/${row.id}`);
            },
          },
          { default: () => '记录' },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleRun(row) },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, type: 'primary', size: 'small' },
                { default: () => '监测' },
              ),
            default: () => '确认执行一次全维度检测？',
          },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleToggleEnabled(row) },
          {
            trigger: () =>
              h(
                NButton,
                {
                  text: true,
                  type: row.enabled ? 'warning' : 'success',
                  size: 'small',
                },
                { default: () => (row.enabled ? '停止' : '启动') },
              ),
            default: () =>
              row.enabled
                ? `确认停止任务「${row.task_name}」？`
                : `确认启动任务「${row.task_name}」？`,
          },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDelete(row) },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, type: 'error', size: 'small' },
                { default: () => '删除' },
              ),
            default: () =>
              `确认删除任务「${row.task_name}」？此操作不可恢复！`,
          },
        ),
      ]),
  },
]);

async function onSearch() {
  loading.value = true;
  try {
    const res = await getTaskList({
      enabled: form.enabled,
      index: pagination.page,
      name: form.name,
      size: pagination.pageSize,
    });
    dataList.value = res.data || [];
    pagination.itemCount = (res as any).count || 0;
  } catch (e) {
    handleError(e, '获取列表失败');
    dataList.value = [];
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  form.name = '';
  form.enabled = '';
  pagination.page = 1;
  onSearch();
}

const createVisible = ref(false);
const fetchingTitle = ref(false);
const highFreqPresets = [
  { label: '每1分钟', value: '0 */1 * * * *' },
  { label: '每2分钟', value: '0 */2 * * * *' },
  { label: '每5分钟', value: '0 */5 * * * *' },
  { label: '每10分钟', value: '0 */10 * * * *' },
  { label: '每15分钟', value: '0 */15 * * * *' },
  { label: '每30分钟', value: '0 */30 * * * *' },
  { label: '每1小时', value: '0 0 * * * *' },
  { label: '每2小时', value: '0 0 */2 * * *' },
  { label: '每6小时', value: '0 0 */6 * * *' },
  { label: '每12小时', value: '0 0 */12 * * *' },
  { label: '每天0点', value: '0 0 0 * * *' },
  { label: '每天8点', value: '0 0 8 * * *' },
  { label: '每周一0点', value: '0 0 0 * * 1' },
  { label: '自定义', value: 'custom' },
];

const dimScheduleDefaults: Record<string, string> = {
  availability: '0 */5 * * * *',
  blacklink: '0 0 */6 * * *',
  domain_hijack: '0 0 */6 * * *',
  sensitive_file: '0 0 0 * * *',
  sensitive_word: '0 0 0 * * *',
  tamper: '0 0 */2 * * *',
};

const createForm = reactive({
  dim_availability: true,
  dim_blacklink: true,
  dim_domain_hijack: true,
  dim_sensitive_file: true,
  dim_sensitive_word: true,
  dim_tamper: true,
  cron_availability: '0 */5 * * * *',
  cron_blacklink: '0 0 */6 * * *',
  cron_domain_hijack: '0 0 */6 * * *',
  cron_sensitive_file: '0 0 0 * * *',
  cron_sensitive_word: '0 0 0 * * *',
  cron_tamper: '0 0 */2 * * *',
  custom_cron_availability: '',
  custom_cron_blacklink: '',
  custom_cron_domain_hijack: '',
  custom_cron_sensitive_file: '',
  custom_cron_sensitive_word: '',
  custom_cron_tamper: '',
  schedule_cron: '0 */5 * * * *',
  schedule_enabled: true,
  target_domain: '',
  target_homepage: '',
  target_ips: '',
  task_name: '',
});

function resetCreateForm() {
  createForm.target_homepage = '';
  createForm.task_name = '';
  createForm.target_domain = '';
  createForm.target_ips = '';
  createForm.schedule_enabled = true;
  createForm.schedule_cron = '0 */5 * * * *';
  for (const d of dimensions) {
    (createForm as any)[`dim_${d.key}`] = true;
    (createForm as any)[`cron_${d.key}`] = dimScheduleDefaults[d.key] || '0 */30 * * * *';
    (createForm as any)[`custom_cron_${d.key}`] = '';
  }
}

async function handleFetchTitle() {
  if (!createForm.target_homepage) {
    message.warning('请先输入首页URL');
    return;
  }
  fetchingTitle.value = true;
  try {
    const res = await fetchTaskMeta(createForm.target_homepage);
    const meta = (res as any)?.data ?? res;
    if (meta?.title) createForm.task_name = meta.title;
  } catch {
    message.warning('无法获取页面标题，请手动填写系统名称');
  } finally {
    fetchingTitle.value = false;
  }
}

const defaultConfigs = ref<Record<string, DimensionConfig>>({});
const wordLibraries = ref<WordLibrary[]>([]);
const fileLibraries = ref<FileLibrary[]>([]);

async function loadDefaultConfigs() {
  try {
    const res = await getDefaultConfigList();
    const cfgList = Array.isArray(res) ? res : ((res as any)?.data || []);
    for (const cfg of cfgList) {
      defaultConfigs.value[cfg.dimension] = { ...cfg.config_json };
    }
  } catch {
    // ignore
  }
}

async function loadLibraries() {
  try {
    const [wRes, fRes] = await Promise.all([
      getWordLibraryList({ size: 100 }),
      getFileLibraryList({ size: 100 }),
    ]);
    wordLibraries.value = wRes?.data || [];
    fileLibraries.value = fRes?.data || [];
  } catch {
    // ignore
  }
}

async function handleCreate() {
  if (!createForm.target_homepage) {
    message.warning('请填写首页URL');
    return;
  }
  if (!createForm.task_name) {
    message.warning('请填写系统名称');
    return;
  }
  function resolveCron(dimKey: string): string {
    const sel = (createForm as any)[`cron_${dimKey}`];
    if (sel === 'custom') return (createForm as any)[`custom_cron_${dimKey}`] || '0 */30 * * * *';
    return sel || '0 */30 * * * *';
  }
  const payload: any = {
    enabled: true,
    config_availability: createForm.dim_availability ? { enabled: true, cron: resolveCron('availability') } : { enabled: false },
    config_blacklink: createForm.dim_blacklink ? { enabled: true, cron: resolveCron('blacklink') } : { enabled: false },
    config_domain_hijack: createForm.dim_domain_hijack ? { enabled: true, cron: resolveCron('domain_hijack') } : { enabled: false },
    config_sensitive_file: createForm.dim_sensitive_file ? { enabled: true, cron: resolveCron('sensitive_file') } : { enabled: false },
    config_sensitive_word: createForm.dim_sensitive_word ? { enabled: true, cron: resolveCron('sensitive_word') } : { enabled: false },
    config_tamper: createForm.dim_tamper ? { enabled: true, cron: resolveCron('tamper') } : { enabled: false },
    schedule_cron: createForm.schedule_cron,
    schedule_enabled: createForm.schedule_enabled,
    target_domain: createForm.target_domain,
    target_homepage: createForm.target_homepage,
    target_ips: createForm.target_ips,
    task_name: createForm.task_name,
  };
  try {
    await createTask(payload);
    message.success('任务创建成功，定时调度已启用');
    createVisible.value = false;
    onSearch();
  } catch (e) {
    handleError(e, '创建失败');
  }
}

const drawerVisible = ref(false);
const drawerTask = reactive({
  configs: {} as Record<string, DimensionConfig>,
  dimCrons: {} as Record<string, string>,
  customCrons: {} as Record<string, string>,
  id: '',
  schedule_cron: '0 */5 * * * *',
  schedule_enabled: true,
  target_domain: '',
  target_homepage: '',
  target_ips: '',
  task_name: '',
});

function openDrawer(row: MonitorTask) {
  drawerTask.id = row.id;
  drawerTask.task_name = row.task_name;
  drawerTask.target_homepage = row.target_homepage;
  drawerTask.target_domain = row.target_domain;
  drawerTask.target_ips = row.target_ips;
  drawerTask.schedule_enabled = (row as any).schedule_enabled ?? true;
  drawerTask.schedule_cron = (row as any).schedule_cron || '0 */5 * * * *';
  drawerTask.configs = {};
  drawerTask.dimCrons = {};
  drawerTask.customCrons = {};
  for (const d of dimensions) {
    const cfg = (row as any)[`config_${d.key}`] || {};
    drawerTask.configs[d.key] = { ...cfg };
    const cronVal = cfg.cron || dimScheduleDefaults[d.key] || '0 */30 * * * *';
    const isPreset = highFreqPresets.some((p) => p.value === cronVal);
    drawerTask.dimCrons[d.key] = isPreset ? cronVal : 'custom';
    drawerTask.customCrons[d.key] = isPreset ? '' : cronVal;
  }
  drawerVisible.value = true;
}

async function handleDrawerSave() {
  const payload: any = {
    schedule_cron: drawerTask.schedule_cron,
    schedule_enabled: drawerTask.schedule_enabled,
    target_domain: drawerTask.target_domain,
    target_ips: drawerTask.target_ips,
    task_name: drawerTask.task_name,
  };
  for (const d of dimensions) {
    const cfg = { ...(drawerTask.configs[d.key] || {}) };
    const cronSel = drawerTask.dimCrons[d.key];
    if (cronSel === 'custom') {
      cfg.cron = drawerTask.customCrons[d.key] || '0 */30 * * * *';
    } else if (cronSel) {
      cfg.cron = cronSel;
    }
    payload[`config_${d.key}`] = cfg;
  }
  try {
    await updateTask(drawerTask.id, payload);
    message.success('配置已保存');
    drawerVisible.value = false;
    onSearch();
  } catch (e) {
    handleError(e, '保存失败');
  }
}

async function handleDelete(row: MonitorTask) {
  try {
    await deleteTask(row.id);
    message.success('删除成功');
    onSearch();
  } catch (e) {
    handleError(e, '删除失败');
  }
}

async function handleRun(row: MonitorTask) {
  try {
    const res = await runTask(row.id);
    const runRes = (res as any)?.data ?? res;
    if (runRes?.execution_ids?.length) {
      message.success(`已触发 ${runRes.execution_ids.length} 个维度`);
    } else {
      message.warning((res as any)?.msg || '无可监测维度');
    }
    onSearch();
  } catch (e) {
    handleError(e, '触发失败');
  }
}

async function handleToggleEnabled(row: MonitorTask) {
  try {
    await updateTask(row.id, { enabled: !row.enabled } as any);
    message.success(row.enabled ? '已停止' : '已启动');
    onSearch();
  } catch (e) {
    handleError(e, '操作失败');
  }
}

function handleBatchToggle() {
  if (!checkedRowKeys.value.length) {
    message.warning('请先勾选任务');
    return;
  }
  dialog.warning({
    title: '提示',
    content: `确认批量启停已选的 ${checkedRowKeys.value.length} 个任务？（当前启用→停用，停用→启用）`,
    positiveText: '确认',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await batchToggleEnabled(checkedRowKeys.value);
        message.success('批量启停成功');
        checkedRowKeys.value = [];
        onSearch();
      } catch (e) {
        handleError(e, '批量启停失败');
      }
    },
  });
}

function handleBatchSyncNames() {
  if (!checkedRowKeys.value.length) {
    message.warning('请先勾选任务');
    return;
  }
  dialog.info({
    title: '提示',
    content: `确认批量同步已选 ${checkedRowKeys.value.length} 个任务的系统名称？将从 URL 抓取页面标题回填。`,
    positiveText: '确认',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const res = await batchSyncNames(checkedRowKeys.value);
        message.success(`已同步 ${(res as any).data?.updated || 0} 个任务名称`);
        checkedRowKeys.value = [];
        onSearch();
      } catch (e) {
        handleError(e, '批量同步失败');
      }
    },
  });
}

function handleBatchDelete() {
  if (!checkedRowKeys.value.length) {
    message.warning('请先勾选任务');
    return;
  }
  dialog.error({
    title: '危险操作',
    content: `确认批量删除已选的 ${checkedRowKeys.value.length} 个任务？此操作将删除任务及所有关联数据，不可恢复！`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await batchDeleteTasks(checkedRowKeys.value);
        message.success('批量删除成功');
        checkedRowKeys.value = [];
        onSearch();
      } catch (e) {
        handleError(e, '批量删除失败');
      }
    },
  });
}

const importDialogVisible = ref(false);
const importUploading = ref(false);
const importResultVisible = ref(false);
const importResult = ref<ImportResult | null>(null);

function handleDownloadTemplate() {
  window.open(downloadImportTemplate(), '_blank');
}

async function handleImportFile({ file }: { file: UploadFileInfo }) {
  if (!file.file) return false;
  importUploading.value = true;
  try {
    const res = await importTasks(file.file);
    importResult.value = (res as any)?.data ?? res;
    importDialogVisible.value = false;
    importResultVisible.value = true;
    onSearch();
  } catch (e) {
    handleError(e, '导入失败');
  } finally {
    importUploading.value = false;
  }
  return false;
}

function handleExportImportResult() {
  if (!importResult.value?.id) return;
  window.open(exportImportResultUrl(importResult.value.id), '_blank');
}

const importSuccessRate = computed(() => {
  if (!importResult.value || !importResult.value.total) return '0%';
  return `${(
    (importResult.value.success / importResult.value.total) *
    100
  ).toFixed(1)}%`;
});

const batchModifyVisible = ref(false);
const batchConfigs = reactive<Record<string, DimensionConfig>>({});

function openBatchModifyDialog() {
  if (!checkedRowKeys.value.length) {
    message.warning('请先勾选任务');
    return;
  }
  for (const d of dimensions) {
    batchConfigs[d.key] = { ...(defaultConfigs.value[d.key] || {}) };
  }
  batchModifyVisible.value = true;
}

async function handleBatchModifySave() {
  const cfgs: Partial<Record<string, DimensionConfig>> = {};
  for (const d of dimensions) {
    if (batchConfigs[d.key]) cfgs[d.key] = batchConfigs[d.key];
  }
  try {
    await batchUpdateConfigs(checkedRowKeys.value, cfgs);
    message.success('批量修改配置成功');
    batchModifyVisible.value = false;
    checkedRowKeys.value = [];
    onSearch();
  } catch (e) {
    handleError(e, '批量修改失败');
  }
}

const batchModifyOptions = [
  { key: 'modify', label: '修改任务参数' },
  { key: 'sync-names', label: '同步系统名称' },
];

function handleBatchModifyCommand(key: string) {
  if (key === 'modify') openBatchModifyDialog();
  else if (key === 'sync-names') handleBatchSyncNames();
}

const importMenuOptions = [
  { key: 'download', label: '下载导入模板' },
  { key: 'upload', label: '上传导入文件' },
];

function handleImportMenuCommand(key: string) {
  if (key === 'download') handleDownloadTemplate();
  else if (key === 'upload') importDialogVisible.value = true;
}

const recordsTask = ref<MonitorTask | null>(null);
const recordsVisible = ref(false);
const recordsLoading = ref(false);
const recordsList = ref<MonitorExecution[]>([]);
const safeRecordsList = computed(() =>
  Array.isArray(recordsList.value) ? recordsList.value : [],
);
const recordsPagination = reactive({
  itemCount: 0,
  page: 1,
  pageSize: 15,
  pageSizes: [15, 30, 50, 100],
  showSizePicker: true,
});
const recordsFilter = reactive<{
  dateRange: [number, number] | null;
  dimension: string;
  disposition: string;
  hasIssue: string;
}>({
  dateRange: null,
  dimension: '',
  disposition: '',
  hasIssue: '',
});

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
const dispositionTagType: Record<string, TagType> = {
  false_positive: 'default',
  invalid: 'default',
  pending: 'warning',
  valid: 'success',
};

const recordsColumns = computed<DataTableColumns<MonitorExecution>>(() => [
  {
    key: 'dimension',
    title: '维度',
    width: 100,
    align: 'center',
    render: (row) =>
      dimLabelMap[row.dimension] || row.dimension || '-',
  },
  {
    key: 'status',
    title: '状态',
    width: 80,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        {
          type: execStatusType(row.status),
          size: 'small',
          bordered: false,
        },
        { default: () => execStatusLabel(row.status) },
      ),
  },
  {
    key: 'has_issue',
    title: '安全问题',
    width: 90,
    align: 'center',
    render: (row) =>
      h(
        'span',
        {
          class: row.has_issue
            ? 'text-error font-medium'
            : 'text-success',
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
      return h(
        NTag,
        {
          type: dispositionTagType[d] || 'default',
          size: 'small',
          bordered: false,
        },
        { default: () => dispositionLabelMap[d] || d },
      );
    },
  },
  { key: 'url', title: 'URL', minWidth: 180, ellipsis: { tooltip: true } },
  {
    key: 'created_at',
    title: '创建时间',
    width: 160,
    align: 'center',
    render: (row) =>
      row.created_at
        ? dayjs(row.created_at).format('YYYY-MM-DD HH:mm:ss')
        : '-',
  },
  {
    key: 'op',
    title: '操作',
    width: 200,
    align: 'center',
    fixed: 'right',
    render: (row) =>
      h(NSpace, { size: 'small', justify: 'center' }, () => [
        row.has_issue
          ? h(
              NButton,
              {
                text: true,
                type: 'warning',
                size: 'small',
                onClick: () => openDispDialog(row),
              },
              { default: () => '处置' },
            )
          : null,
        h(
          NButton,
          {
            text: true,
            type: 'primary',
            size: 'small',
            onClick: () => openDetailDialog(row),
          },
          { default: () => '详情' },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDeleteExecution(row) },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, type: 'error', size: 'small' },
                { default: () => '删除' },
              ),
            default: () => '确认删除该条记录及相关证据文件？',
          },
        ),
      ]),
  },
]);

const trendData = ref<any>(null);
const trendLoading = ref(false);
const trendHours = ref(24);

const trendHoursOptions = [
  { label: '近24小时', value: 24 },
  { label: '近3天', value: 72 },
  { label: '近7天', value: 168 },
  { label: '近30天', value: 720 },
];

async function loadTrend(taskId: string) {
  trendLoading.value = true;
  try {
    const res: any = await getTaskTrend(taskId, trendHours.value);
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
    grid: { left: 50, right: 16, top: 16, bottom: 36 },
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
  } catch (e) {
    handleError(e, '加载监测记录失败');
    recordsList.value = [];
  } finally {
    recordsLoading.value = false;
  }
}

function resetRecordsFilter() {
  recordsFilter.dimension = '';
  recordsFilter.hasIssue = '';
  recordsFilter.disposition = '';
  recordsFilter.dateRange = null;
  recordsPagination.page = 1;
  loadRecords();
}

const dispDialogVisible = ref(false);
const dispTarget = ref<MonitorExecution | null>(null);
const dispForm = reactive({ disposition: 'valid', remark: '' });
const dispLoading = ref(false);

function openDispDialog(row: MonitorExecution) {
  dispTarget.value = row;
  dispForm.disposition = row.disposition || 'pending';
  dispForm.remark = (row as any).disposition_remark || '';
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
  } catch (e) {
    handleError(e, '处置失败');
  } finally {
    dispLoading.value = false;
  }
}

async function handleDeleteExecution(row: MonitorExecution) {
  try {
    await deleteExecution(row.id);
    message.success('删除成功');
    loadRecords();
  } catch (e) {
    handleError(e, '删除失败');
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
        const ids = (res.data || []).map((r) => r.id);
        if (!ids.length) return;
        await batchDeleteExecutions(ids);
        message.success(`已删除 ${ids.length} 条记录`);
        loadRecords();
      } catch (e) {
        handleError(e, '批量删除失败');
      }
    },
  });
}

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

async function openDetailDialog(row: MonitorExecution) {
  detailData.value = null;
  detailExecId.value = row.id;
  detailVisible.value = true;
  detailLoading.value = true;
  try {
    const res: any = await getExecutionDetail(row.id);
    detailData.value = res?.data ?? res;
  } catch (e) {
    handleError(e, '加载详情失败');
  } finally {
    detailLoading.value = false;
  }
}

const dimensionFilterOptions = dimensions.map((d) => ({
  label: d.label,
  value: d.key,
}));

const hasIssueOptions = [
  { label: '有问题', value: 'true' },
  { label: '正常', value: 'false' },
];

const enabledOptions = [
  { label: '启用', value: 'true' },
  { label: '停止', value: 'false' },
];

const fmtTime = (t: string) =>
  t ? dayjs(t).format('YYYY-MM-DD HH:mm:ss') : '-';

onMounted(() => {
  loadDefaultConfigs();
  loadLibraries();
  onSearch();
});
</script>

<template>
  <Page title="监测任务" description="网站监测任务的增删改查、批量配置、导入导出">
    <NCard size="small" class="mb-3">
      <NSpace align="center" wrap>
        <span>系统名称</span>
        <NInput
          v-model:value="form.name"
          placeholder="请输入系统名称"
          clearable
          style="width: 180px"
        />
        <span>状态</span>
        <NSelect
          v-model:value="form.enabled"
          placeholder="请选择"
          clearable
          :options="enabledOptions"
          style="width: 120px"
        />
        <NButton type="primary" :loading="loading" @click="onSearch">
          搜索
        </NButton>
        <NButton @click="resetForm">重置</NButton>
      </NSpace>
    </NCard>

    <NCard title="监测任务">
      <template #header-extra>
        <NSpace size="small">
          <NButton
            type="primary"
            @click="
              () => {
                resetCreateForm();
                createVisible = true;
              }
            "
          >
            创建任务
          </NButton>
          <NButton
            type="warning"
            :disabled="!checkedRowKeys.length"
            @click="handleBatchToggle"
          >
            启动 / 停止
          </NButton>
          <NDropdown
            trigger="click"
            :disabled="!checkedRowKeys.length"
            :options="batchModifyOptions"
            @select="handleBatchModifyCommand"
          >
            <NButton type="primary" :disabled="!checkedRowKeys.length">
              批量修改 ▾
            </NButton>
          </NDropdown>
          <NButton
            type="error"
            :disabled="!checkedRowKeys.length"
            @click="handleBatchDelete"
          >
            批量删除
          </NButton>
          <NDivider vertical />
          <NDropdown
            trigger="click"
            :options="importMenuOptions"
            @select="handleImportMenuCommand"
          >
            <NButton type="success">批量导入 ▾</NButton>
          </NDropdown>
          <NButton size="small" @click="onSearch">刷新</NButton>
        </NSpace>
      </template>

      <NDataTable
        v-model:checked-row-keys="checkedRowKeys"
        :columns="columns"
        :data="safeDataList"
        :loading="loading"
        :pagination="pagination"
        :row-key="(r: MonitorTask) => r.id"
        remote
        size="small"
        scroll-x="1500"
        @update:page="
          (p: number) => {
            pagination.page = p;
            onSearch();
          }
        "
        @update:page-size="
          (s: number) => {
            pagination.pageSize = s;
            pagination.page = 1;
            onSearch();
          }
        "
      />
    </NCard>

    <!-- 创建任务弹窗 -->
    <NModal
      v-model:show="createVisible"
      preset="card"
      title="创建监测任务"
      style="width: 600px"
      :on-after-leave="resetCreateForm"
    >
      <NForm :model="createForm" label-width="100px" label-placement="left">
        <NFormItem label="首页(URL)" required>
          <NSpace style="width: 100%">
            <NInput
              v-model:value="createForm.target_homepage"
              placeholder="https://www.example.com"
              style="width: 360px"
              @keyup.enter="handleFetchTitle"
            />
            <NButton :loading="fetchingTitle" @click="handleFetchTitle">
              自动填充
            </NButton>
          </NSpace>
        </NFormItem>
        <NFormItem label="系统名称" required>
          <NInput
            v-model:value="createForm.task_name"
            placeholder="输入URL后点自动填充，或手动输入"
          />
        </NFormItem>
        <NFormItem label="域名">
          <NInput
            v-model:value="createForm.target_domain"
            placeholder="example.com"
          />
        </NFormItem>
        <NFormItem label="IP">
          <NInput
            v-model:value="createForm.target_ips"
            placeholder="多个IP用英文逗号分隔，如：1.1.1.1,2.2.2.2"
          />
        </NFormItem>

        <NDivider title-placement="left">
          <span class="text-sm font-bold">监测功能与调度频率</span>
        </NDivider>
        <NFormItem label="启用调度">
          <NSwitch v-model:value="createForm.schedule_enabled" />
          <span class="ml-2 text-xs text-gray-400">开启后将按设定频率自动执行监测</span>
        </NFormItem>
        <div v-for="dim in dimensions" :key="dim.key" class="mb-3 flex items-center gap-3 pl-4">
          <div class="flex w-24 items-center gap-1">
            <NSwitch
              v-model:value="(createForm as any)[`dim_${dim.key}`]"
              size="small"
            />
            <span class="text-sm">{{ dim.label }}</span>
          </div>
          <NSelect
            v-if="(createForm as any)[`dim_${dim.key}`] && createForm.schedule_enabled"
            v-model:value="(createForm as any)[`cron_${dim.key}`]"
            :options="highFreqPresets"
            size="small"
            style="width: 150px"
          />
          <NInput
            v-if="(createForm as any)[`cron_${dim.key}`] === 'custom' && (createForm as any)[`dim_${dim.key}`] && createForm.schedule_enabled"
            v-model:value="(createForm as any)[`custom_cron_${dim.key}`]"
            placeholder="秒 分 时 日 月 周"
            size="small"
            style="width: 180px"
          />
        </div>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="createVisible = false">取消</NButton>
          <NButton type="primary" @click="handleCreate">确定</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 配置抽屉 -->
    <NDrawer v-model:show="drawerVisible" :width="860" placement="right">
      <NDrawerContent title="任务参数配置" closable>
        <div class="mb-4">
          <div class="mb-3 text-base font-bold">基本信息</div>
          <NForm :model="drawerTask" label-width="80px" label-placement="left">
            <NRow :gutter="16">
              <NCol :span="12">
                <NFormItem label="系统名称">
                  <NInput v-model:value="drawerTask.task_name" />
                </NFormItem>
              </NCol>
              <NCol :span="12">
                <NFormItem label="域名">
                  <NInput v-model:value="drawerTask.target_domain" />
                </NFormItem>
              </NCol>
              <NCol :span="12">
                <NFormItem label="IP">
                  <NInput v-model:value="drawerTask.target_ips" />
                </NFormItem>
              </NCol>
              <NCol :span="12">
                <NFormItem label="URL">
                  <NInput :value="drawerTask.target_homepage" disabled />
                </NFormItem>
              </NCol>
            </NRow>
          </NForm>
        </div>
        <NDivider />
        <div class="mb-3 text-base font-bold">定时调度</div>
        <NForm label-width="80px" label-placement="left" class="mb-4">
          <NFormItem label="启用调度">
            <NSwitch v-model:value="drawerTask.schedule_enabled" />
          </NFormItem>
          <template v-if="drawerTask.schedule_enabled">
            <div
              v-for="dim in dimensions"
              :key="dim.key"
              class="mb-2 flex items-center gap-3 pl-2"
            >
              <span class="w-20 text-sm">{{ dim.label }}</span>
              <NSelect
                v-model:value="drawerTask.dimCrons[dim.key]"
                :options="highFreqPresets"
                size="small"
                style="width: 150px"
              />
              <NInput
                v-if="drawerTask.dimCrons[dim.key] === 'custom'"
                v-model:value="drawerTask.customCrons[dim.key]"
                placeholder="秒 分 时 日 月 周"
                size="small"
                style="width: 180px"
              />
            </div>
          </template>
        </NForm>
        <NDivider />
        <div class="mb-3 text-base font-bold">任务参数</div>
        <NAlert type="info" class="mb-4">
          敏感词/文件/黑链/挂马扫描会进行全站页面爬虫，建议错开"网站遍扫"、"敏感词/文件/黑链/挂马"的周期扫描时间。
        </NAlert>
        <DimensionConfigForm
          :configs="drawerTask.configs"
          :dimensions="dimensions"
          :word-libraries="wordLibraries"
          :file-libraries="fileLibraries"
        />
        <template #footer>
          <NSpace justify="end">
            <NButton @click="drawerVisible = false">取消</NButton>
            <NButton type="primary" @click="handleDrawerSave">确认</NButton>
          </NSpace>
        </template>
      </NDrawerContent>
    </NDrawer>

    <!-- 批量修改任务参数弹窗 -->
    <NModal
      v-model:show="batchModifyVisible"
      preset="card"
      title="批量修改任务参数"
      style="width: 720px"
    >
      <NAlert type="info" class="mb-4">
        将以下参数应用到已选的 {{ checkedRowKeys.length }} 个任务（默认读取全局默认配置）。
      </NAlert>
      <DimensionConfigForm
        :configs="batchConfigs"
        :dimensions="dimensions"
        :word-libraries="wordLibraries"
        :file-libraries="fileLibraries"
      />
      <template #footer>
        <NSpace justify="end">
          <NButton @click="batchModifyVisible = false">取消</NButton>
          <NButton type="primary" @click="handleBatchModifySave">
            确认修改
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 监测记录弹窗 -->
    <NModal
      v-model:show="recordsVisible"
      preset="card"
      :title="`监测记录 — ${recordsTask?.task_name || ''}`"
      style="width: 1200px"
    >
      <!-- 趋势概览 -->
      <NSpin :show="trendLoading" size="small">
        <template v-if="trendData">
          <div class="mb-3">
            <div class="mb-2 flex items-center justify-between">
              <span class="text-base font-bold">可用性概览</span>
              <NSelect
                v-model:value="trendHours"
                :options="trendHoursOptions"
                size="small"
                style="width: 120px"
                @update:value="() => recordsTask && loadTrend(recordsTask.id)"
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

            <!-- 可用性状态条 -->
            <div v-if="availBarOption" class="mb-2">
              <div class="text-muted-foreground mb-1 text-xs">可用性状态（绿=正常 黄=有问题 红=不可用）</div>
              <VChart :option="availBarOption" style="height: 28px; width: 100%" autoresize />
            </div>

            <!-- 响应时间趋势折线图 -->
            <div v-if="trendChartOption" class="mb-3">
              <div class="text-muted-foreground mb-1 text-xs">响应时间趋势</div>
              <VChart :option="trendChartOption" style="height: 220px; width: 100%" autoresize />
            </div>

            <!-- 各维度概要 -->
            <div v-if="(trendData.dimensions || []).length" class="mb-3">
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
          </div>
          <NDivider style="margin: 8px 0" />
        </template>
      </NSpin>

      <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
        <NSpace align="center" wrap>
          <NSelect
            v-model:value="recordsFilter.dimension"
            placeholder="维度类型"
            clearable
            :options="dimensionFilterOptions"
            style="width: 130px"
          />
          <NSelect
            v-model:value="recordsFilter.hasIssue"
            placeholder="安全问题"
            clearable
            :options="hasIssueOptions"
            style="width: 110px"
          />
          <NSelect
            v-model:value="recordsFilter.disposition"
            placeholder="处置状态"
            clearable
            :options="dispositionOptions"
            style="width: 110px"
          />
          <NDatePicker
            v-model:value="recordsFilter.dateRange"
            type="datetimerange"
            clearable
            style="width: 360px"
          />
          <NButton
            type="primary"
            @click="
              () => {
                recordsPagination.page = 1;
                loadRecords();
              }
            "
          >
            查询
          </NButton>
          <NButton @click="resetRecordsFilter">重置</NButton>
        </NSpace>
        <NSpace size="small">
          <NButton type="error" @click="handleDeleteAllExecutions">
            全部删除
          </NButton>
          <NButton circle @click="loadRecords">↻</NButton>
        </NSpace>
      </div>

      <NDataTable
        :columns="recordsColumns"
        :data="safeRecordsList"
        :loading="recordsLoading"
        :pagination="
          recordsPagination.itemCount > 0 ? recordsPagination : false
        "
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

    <!-- 监测详情抽屉 -->
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
                    {{ execStatusLabel(detailData.status) }}
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
          <NEmpty
            v-else-if="!detailLoading"
            description="暂无数据"
          />
        </NSpin>
      </NDrawerContent>
    </NDrawer>

    <!-- 导入上传弹窗 -->
    <NModal
      v-model:show="importDialogVisible"
      preset="card"
      title="批量导入任务"
      style="width: 520px"
    >
      <NAlert type="info" class="mb-4">
        请先下载模板，按格式填写后上传。首页URL为必填项，系统名称为空时自动获取。
      </NAlert>
      <NUpload
        :default-upload="false"
        :max="1"
        accept=".xlsx,.xls"
        :on-change="handleImportFile"
      >
        <NUploadDragger>
          <div style="margin-bottom: 8px; font-size: 16px">
            将文件拖到此处，或<em style="color: var(--primary-color)">点击上传</em>
          </div>
          <div class="text-muted-foreground text-xs">
            仅支持 .xlsx / .xls 格式，文件大小不超过10MB
          </div>
        </NUploadDragger>
      </NUpload>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="importDialogVisible = false">取消</NButton>
          <NButton type="primary" @click="handleDownloadTemplate">
            下载模板
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 导入结果弹窗 -->
    <NModal
      v-model:show="importResultVisible"
      preset="card"
      title="导入结果"
      style="width: 800px"
    >
      <template v-if="importResult">
        <NSpace align="center" size="large" class="mb-4">
          <NStatistic label="总计" :value="importResult.total" />
          <NStatistic label="成功" :value="importResult.success" />
          <NStatistic label="失败" :value="importResult.failed" />
          <NStatistic label="成功率" :value="importSuccessRate" />
        </NSpace>
        <NDataTable
          :columns="[
            { key: 'row', title: '行号', width: 60, align: 'center' },
            { key: 'name', title: '系统名称', width: 150, ellipsis: { tooltip: true } },
            { key: 'url', title: '首页URL', minWidth: 200, ellipsis: { tooltip: true } },
            {
              key: 'success',
              title: '状态',
              width: 80,
              align: 'center',
              render: (row: any) =>
                h(
                  NTag,
                  { type: row.success ? 'success' : 'error', size: 'small', bordered: false },
                  { default: () => (row.success ? '成功' : '失败') },
                ),
            },
            {
              key: 'error',
              title: '错误信息',
              minWidth: 180,
              ellipsis: { tooltip: true },
              render: (row: any) =>
                row.error
                  ? h('span', { class: 'text-error text-xs' }, row.error)
                  : h('span', { class: 'text-muted-foreground' }, '-'),
            },
          ]"
          :data="importResult?.results ?? []"
          :max-height="400"
          size="small"
        />
      </template>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="importResultVisible = false">关闭</NButton>
          <NButton type="primary" @click="handleExportImportResult">
            下载导入结果
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 处置弹窗 -->
    <NModal
      v-model:show="dispDialogVisible"
      preset="card"
      title="问题处置"
      style="width: 480px"
    >
      <NForm label-width="80px" label-placement="left">
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
