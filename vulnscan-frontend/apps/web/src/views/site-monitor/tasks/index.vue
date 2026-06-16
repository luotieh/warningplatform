<script lang="ts" setup>
import type { DataTableColumns, UploadFileInfo } from 'naive-ui';

import type {
  DimensionConfig,
  FileLibrary,
  ImportResult,
  MonitorTask,
} from '#/api/sitemonitor';

import { computed, h, onMounted, reactive, ref } from 'vue';
import { useOpenTaskRecordsTab } from '../composables/useOpenTaskRecordsTab';

import { Page } from '@vben/common-ui';

import dayjs from 'dayjs';
import {
  NAlert,
  NButton,
  NCard,
  NCol,
  NDataTable,
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
  NProgress,
  NRadio,
  NRadioGroup,
  NRow,
  NSelect,
  NSpace,
  NStatistic,
  NSwitch,
  NTag,
  NUpload,
  NUploadDragger,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import { useErrorHandler } from '#/composables/useErrorHandler';
import {
  batchDeleteTasks,
  batchSyncNames,
  batchToggleEnabled,
  batchUpdateConfigs,
  createTask,
  deleteTask,
  downloadImportResult,
  downloadImportTemplate,
  fetchTaskMeta,
  getDefaultConfigList,
  getFileLibraryList,
  getTaskExecutionStats,
  getTaskList,
  getImportResult,
  importTasks,
  runTask,
  updateTask,
} from '#/api/sitemonitor';

import DimensionConfigForm from './components/DimensionConfigForm.vue';

defineOptions({ name: 'MonitorTasks' });

const { openTaskRecordsTab } = useOpenTaskRecordsTab();
const { handleError } = useErrorHandler();
const loading = ref(false);
const dataList = ref<MonitorTask[]>([]);
const safeDataList = computed(() =>
  Array.isArray(dataList.value) ? dataList.value : [],
);
const checkedRowKeys = ref<string[]>([]);

const statsMap = ref<
  Record<
    string,
    Record<
      string,
      {
        total: number;
        issue_count: number;
        pending_count?: number;
        valid_count?: number;
      }
    >
  >
>({});

const form = reactive({ enabled: '', name: '', target_homepage: '' });

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

function dimStatRender(dimKey: string) {
  return (row: MonitorTask) => {
    const cfg = row[`config_${dimKey}` as keyof MonitorTask] as
      | DimensionConfig
      | undefined;
    if (!cfg?.enabled) {
      return h('span', { class: 'text-muted-foreground' }, '-');
    }
    const stat = statsMap.value[row.id]?.[dimKey];
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
            class: pendingCount > 0 ? 'text-error font-medium cursor-pointer' : 'text-muted-foreground cursor-pointer',
            title: '点击查看未处置的问题记录',
            onClick: (e: Event) => {
              e.stopPropagation();
              openRecordsWithFilter(row, dimKey, 'true', 'pending');
            },
          },
          String(pendingCount),
        ),
        h('span', { class: 'text-muted-foreground', style: { margin: '0 1px' } }, '/'),
        h(
          'span',
          {
            class: validCount > 0 ? 'text-warning font-medium cursor-pointer' : 'text-muted-foreground cursor-pointer',
            title: '点击查看有效问题记录',
            onClick: (e: Event) => {
              e.stopPropagation();
              openRecordsWithFilter(row, dimKey, 'true', 'valid');
            },
          },
          String(validCount),
        ),
        h('span', { class: 'text-muted-foreground', style: { margin: '0 1px' } }, '/'),
        h(
          'span',
          {
            class: 'text-primary cursor-pointer font-medium',
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
    key: 'stats',
    title: '未处置 / 问题 / 总检测',
    align: 'center',
    children: dimensions.map((dim) => ({
      key: `stat_${dim.key}`,
      title: dim.label,
      width: 108,
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
            onClick: () => openRecordsDrawer(row),
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
    const [taskRes, statsRes] = await Promise.all([
      getTaskList({
        enabled: form.enabled,
        page: pagination.page,
        name: form.name,
        target_homepage: form.target_homepage,
        page_size: pagination.pageSize,
      }),
      getTaskExecutionStats(),
    ]);
    const res = taskRes;
    dataList.value = res.data || [];
    pagination.itemCount = (res as any).count || 0;
    statsMap.value = (statsRes as any)?.data ?? statsRes ?? {};
  } catch (e) {
    handleError(e, '获取列表失败');
    dataList.value = [];
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  form.name = '';
  form.target_homepage = '';
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
  availability: '0 */1 * * * *',
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
  cron_availability: '0 */1 * * * *',
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
  schedule_cron: '0 */1 * * * *',
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
  createForm.schedule_cron = '0 */1 * * * *';
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
    const fRes = await getFileLibraryList({ page: 1, page_size: 100 });
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
  schedule_cron: '0 */1 * * * *',
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
  drawerTask.schedule_cron = (row as any).schedule_cron || '0 */1 * * * *';
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
  const payload: any = {};
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
    const skipped = runRes?.skipped || [];
    if (runRes?.execution_ids?.length) {
      let msg = `已触发 ${runRes.execution_ids.length} 个维度`;
      if (skipped.length) {
        const detail = skipped
          .map((s: { dimension: string; reason: string }) =>
            `${dimLabelMap[s.dimension] || s.dimension}: ${s.reason}`,
          )
          .join('；');
        msg += `；未触发 ${skipped.length} 项（${detail}）`;
      }
      message.success(msg, { duration: skipped.length ? 8000 : 3000 });
    } else if (skipped.length) {
      const detail = skipped
        .map((s: { dimension: string; reason: string }) =>
          `${dimLabelMap[s.dimension] || s.dimension}: ${s.reason}`,
        )
        .join('；');
      message.warning(`无可监测维度：${detail}`);
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

const templateDownloading = ref(false);

async function handleDownloadTemplate() {
  templateDownloading.value = true;
  try {
    const blob = await downloadImportTemplate();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'import_template.xlsx';
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    handleError(e, '下载模板失败');
  } finally {
    templateDownloading.value = false;
  }
}

async function handleImportFile({ file }: { file: UploadFileInfo }) {
  if (!file.file) return false;
  importUploading.value = true;
  importResult.value = null;
  try {
    const res = await importTasks(file.file);
    const startData = (res as any)?.data ?? res;
    const importId = startData.id;
    if (!importId) {
      message.error('导入启动失败');
      return false;
    }
    importResult.value = {
      id: importId,
      status: 'running',
      total: startData.total || 0,
      success: 0,
      failed: 0,
      processed: 0,
      results: [],
      created_at: '',
    };
    importDialogVisible.value = false;
    importResultVisible.value = true;
    await pollImportProgress(importId);
  } catch (e) {
    handleError(e, '导入失败');
  } finally {
    importUploading.value = false;
  }
  return false;
}

async function pollImportProgress(importId: string) {
  const maxAttempts = 600;
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      const res = await getImportResult(importId);
      const data = (res as any)?.data ?? res;
      importResult.value = data;
      if (data.status === 'completed' || data.status === 'failed') {
        if (data.status === 'completed') {
          message.success(`导入完成：成功 ${data.success}，失败 ${data.failed}`);
        } else {
          message.error(`导入异常：${data.error || '未知错误'}`);
        }
        onSearch();
        return;
      }
    } catch {
      // 轮询失败不中断
    }
  }
  message.warning('导入轮询超时，请稍后查看结果');
}

async function handleExportImportResult() {
  if (!importResult.value?.id) return;
  try {
    const blob = await downloadImportResult(importResult.value.id);
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `导入结果_${importResult.value.id}.xlsx`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    handleError(e, '导出失败');
  }
}

const importSuccessRate = computed(() => {
  if (!importResult.value || !importResult.value.total) return '0%';
  return `${(
    (importResult.value.success / importResult.value.total) *
    100
  ).toFixed(1)}%`;
});

const importResultFilter = ref<'all' | 'failed'>('all');
const filteredImportResults = computed(() => {
  const rows = importResult.value?.results ?? [];
  if (importResultFilter.value === 'failed') return rows.filter((r) => !r.success);
  return rows;
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

function openRecordsWithFilter(
  row: MonitorTask,
  dimension: string,
  hasIssue: string,
  disposition = '',
) {
  openTaskRecordsTab(row, { dimension, hasIssue, disposition });
}

function openRecordsDrawer(row: MonitorTask) {
  openTaskRecordsTab(row);
}

const enabledOptions = [
  { label: '启用', value: 'true' },
  { label: '停止', value: 'false' },
];

onMounted(async () => {
  loadDefaultConfigs();
  loadLibraries();
  await onSearch();
});
</script>

<template>
  <Page
    title="网站监测"
    description="任务配置与启停、六维监测统计（未处置/问题/总检测），点击数字可查看记录并处置"
  >
    <NCard size="small" class="mb-3">
      <NSpace align="center" wrap>
        <span>系统名称</span>
        <NInput
          v-model:value="form.name"
          placeholder="模糊搜索系统名称"
          clearable
          style="width: 180px"
        />
        <span>首页URL</span>
        <NInput
          v-model:value="form.target_homepage"
          placeholder="模糊搜索首页 URL"
          clearable
          style="width: 220px"
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

    <NCard title="监测列表">
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
        scroll-x="2200"
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

    <!-- 配置抽屉（仅点击「配置」时从右侧弹出） -->
    <NDrawer
      v-model:show="drawerVisible"
      :width="860"
      placement="right"
      :trap-focus="false"
    >
      <NDrawerContent title="任务参数配置" closable>
        <NAlert type="info" class="mb-4">
          敏感词/文件/黑链/挂马扫描会进行全站页面爬虫，建议错开"网站遍扫"、"敏感词/文件/黑链/挂马"的周期扫描时间。
        </NAlert>
        <DimensionConfigForm
          :configs="drawerTask.configs"
          :dimensions="dimensions"
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
          <NButton type="primary" :loading="templateDownloading" @click="handleDownloadTemplate">
            下载模板
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 导入结果弹窗 -->
    <NModal
      v-model:show="importResultVisible"
      preset="card"
      :title="importResult?.status === 'running' || importResult?.status === 'pending' ? '导入中...' : '导入结果'"
      style="width: 800px"
      :mask-closable="importResult?.status !== 'running'"
    >
      <template v-if="importResult">
        <div v-if="importResult.status === 'running' || importResult.status === 'pending'" class="mb-4">
          <NProgress
            type="line"
            :percentage="importResult.total ? Math.round((importResult.processed / importResult.total) * 100) : 0"
          />
          <p class="mt-2 text-sm text-gray-500">
            进度：{{ importResult.processed }} / {{ importResult.total }}
            （成功 {{ importResult.success }}，失败 {{ importResult.failed }}）
          </p>
        </div>
        <NSpace align="center" size="large" class="mb-4">
          <NStatistic label="总计" :value="importResult.total" />
          <NStatistic label="成功" :value="importResult.success" />
          <NStatistic label="失败" :value="importResult.failed" />
          <NStatistic label="成功率" :value="importSuccessRate" />
        </NSpace>
        <div class="mb-2 flex items-center gap-2">
          <NRadioGroup v-model:value="importResultFilter" size="small">
            <NRadio value="all">全部 ({{ importResult?.results?.length ?? 0 }})</NRadio>
            <NRadio value="failed">仅失败 ({{ importResult?.failed ?? 0 }})</NRadio>
          </NRadioGroup>
        </div>
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
          :data="filteredImportResults"
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

  </Page>
</template>
