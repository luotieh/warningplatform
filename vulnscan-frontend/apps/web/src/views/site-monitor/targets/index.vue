<script lang="ts" setup>
import type { DataTableColumns, DataTableRowKey, UploadFileInfo } from 'naive-ui';

import type { MonitorPathTask, MonitorTarget } from '#/api/sitemonitor';

import { computed, h, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';

import {
  NAlert,
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NProgress,
  NSelect,
  NSpace,
  NSpin,
  NTag,
  NTooltip,
  NUpload,
  NUploadDragger,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import { useErrorHandler } from '#/composables/useErrorHandler';
import {
  batchDeleteTargets,
  createPathTask,
  createTarget,
  deleteTarget,
  downloadImportResult,
  downloadImportTemplate,
  fetchPageMeta,
  getImportResult,
  getPathTaskList,
  getTargetList,
  importTargets,
  runTarget,
  updateTarget,
} from '#/api/sitemonitor';
import type { ImportResult, ImportRowResult } from '#/api/sitemonitor/types';

defineOptions({ name: 'MonitorTargets' });

const router = useRouter();
const { handleError } = useErrorHandler();

const loading = ref(false);
const dataList = ref<MonitorTarget[]>([]);
const checkedKeys = ref<DataTableRowKey[]>([]);
const form = reactive({
  enabled: '',
  name: '',
  target_type: '',
  target_value: '',
});

const pagination = reactive({
  itemCount: 0,
  page: 1,
  pageSize: 15,
  pageSizes: [15, 30, 50],
  showSizePicker: true,
});

const targetTypeOptions = [
  { label: '域名', value: 'domain' },
  { label: 'IP', value: 'ip' },
];

const enabledOptions = [
  { label: '全部', value: '' },
  { label: '启用', value: 'true' },
  { label: '停用', value: 'false' },
];

function getTargetAddress(row: MonitorTarget) {
  const scheme = row.default_scheme || 'https';
  if (row.target_type === 'domain') {
    return `${scheme}://${row.target_value}`;
  }
  return row.target_value;
}

function getHostHeaderText(row: MonitorTarget) {
  if (row.target_type === 'domain') {
    return '同目标域名';
  }
  return row.virtual_host || '未配置';
}

function getHostHeaderHint(row: MonitorTarget) {
  if (row.target_type === 'domain') {
    return '域名目标会直接使用目标域名作为请求 Host';
  }
  return row.virtual_host
    ? '访问 IP 时发送给服务端的 HTTP Host 头'
    : 'IP 目标建议配置站点域名，否则部分站点无法命中正确虚拟主机';
}

const columns = computed<DataTableColumns<MonitorTarget>>(() => [
  { type: 'selection' },
  {
    key: 'name',
    title: '名称',
    minWidth: 220,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('div', { class: 'flex flex-col gap-0.5' }, [
        h(
          'a',
          {
            class: 'cursor-pointer font-medium text-primary hover:underline',
            onClick: () =>
              router.push({ name: 'MonitorTargetDetail', params: { id: row.id } }),
          },
          row.name,
        ),
        h('span', { class: 'text-xs text-gray-400' }, `更新于 ${row.updated_at?.slice(0, 16) || '-'}`),
      ]),
  },
  {
    key: 'target',
    title: '监测目标',
    minWidth: 220,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('div', { class: 'flex flex-col gap-0.5' }, [
        h('span', { class: 'font-medium text-gray-700 dark:text-gray-100' }, getTargetAddress(row)),
        h('span', { class: 'text-xs text-gray-400' }, row.target_type === 'ip' ? '按 IP 访问' : '按域名访问'),
      ]),
  },
  {
    key: 'target_type',
    title: '类型',
    width: 72,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        {
          size: 'tiny',
          bordered: false,
          round: true,
          type: row.target_type === 'ip' ? 'warning' : 'info',
        },
        { default: () => (row.target_type === 'ip' ? 'IP' : '域名') },
      ),
  },
  {
    key: 'virtual_host',
    title: () =>
      h('div', { class: 'inline-flex items-center gap-1' }, [
        h('span', '请求 Host'),
        h(
          NTooltip,
          {},
          {
            trigger: () => h('span', { class: 'cursor-help text-xs text-gray-400' }, '?'),
            default: () => 'HTTP 请求的 Host 头。常用于访问 IP:端口时指定实际站点域名。',
          },
        ),
      ]),
    minWidth: 180,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('div', { class: 'flex flex-col gap-0.5' }, [
        h(
          'span',
          {
            class:
              row.target_type === 'ip' && !row.virtual_host
                ? 'font-medium text-orange-500'
                : 'text-gray-700 dark:text-gray-100',
          },
          getHostHeaderText(row),
        ),
        h('span', { class: 'text-xs text-gray-400' }, getHostHeaderHint(row)),
      ]),
  },
  {
    key: 'expected_ips',
    title: 'DNS 期望 IP',
    minWidth: 160,
    ellipsis: { tooltip: true },
    render: (row) =>
      h('div', { class: 'flex flex-col gap-0.5' }, [
        h(
          'span',
          { class: row.expected_ips ? 'text-gray-700 dark:text-gray-100' : 'text-gray-300' },
          row.expected_ips || '-',
        ),
        h('span', { class: 'text-xs text-gray-400' }, row.expected_ips ? '用于域名劫持判断' : '未配置劫持基线'),
      ]),
  },
  {
    key: 'enabled',
    title: '状态',
    width: 72,
    align: 'center',
    render: (row) =>
      h('div', { class: 'flex items-center justify-center gap-1.5' }, [
        h('span', {
          class: `inline-block h-2 w-2 rounded-full ${row.enabled ? 'bg-green-500' : 'bg-gray-300'}`,
        }),
        h('span', { class: 'text-xs' }, row.enabled ? '监测中' : '已停用'),
      ]),
  },
  {
    key: 'op',
    title: '操作',
    width: 190,
    fixed: 'right',
    align: 'center',
    render: (row) =>
      h(NSpace, { size: 8, justify: 'center', wrap: false }, () => [
        h(
          NButton,
          {
            text: true,
            type: 'primary',
            size: 'tiny',
            onClick: () =>
              router.push({ name: 'MonitorTargetDetail', params: { id: row.id } }),
          },
          { default: () => '管理' },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleRunTarget(row) },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, type: 'info', size: 'tiny' },
                { default: () => '检测' },
              ),
            default: () => '立即执行域名劫持/敏感文件检测？',
          },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleToggle(row) },
          {
            trigger: () =>
              h(
                NButton,
                {
                  text: true,
                  type: row.enabled ? 'warning' : 'success',
                  size: 'tiny',
                },
                { default: () => (row.enabled ? '停用' : '启用') },
              ),
            default: () => `确认${row.enabled ? '停用' : '启用'}该目标？`,
          },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDelete(row) },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, type: 'error', size: 'tiny' },
                { default: () => '删除' },
              ),
            default: () => '将删除目标及全部路径任务，不可恢复',
          },
        ),
      ]),
  },
]);

async function onSearch() {
  loading.value = true;
  try {
    const res = await getTargetList({
      enabled: form.enabled,
      page: pagination.page,
      name: form.name,
      target_type: form.target_type,
      target_value: form.target_value,
      page_size: pagination.pageSize,
    });
    dataList.value = res.data || [];
    pagination.itemCount = (res as any).count || 0;
  } catch (e) {
    handleError(e, '加载目标列表失败');
    dataList.value = [];
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  form.name = '';
  form.target_type = '';
  form.target_value = '';
  form.enabled = '';
  pagination.page = 1;
  onSearch();
}

const createVisible = ref(false);
const createMode = ref<'single_url' | 'advanced'>('single_url');
const singleHomepageUrl = ref('');

const createForm = reactive({
  name: '',
  target_type: 'domain' as 'domain' | 'ip',
  target_value: '',
  virtual_host: '',
  expected_ips: '',
  default_scheme: 'https',
  path: '/',
  url_override: '',
});

function resetCreateForm() {
  createMode.value = 'single_url';
  singleHomepageUrl.value = '';
  createForm.name = '';
  createForm.target_type = 'domain';
  createForm.target_value = '';
  createForm.virtual_host = '';
  createForm.expected_ips = '';
  createForm.default_scheme = 'https';
  createForm.path = '/';
  createForm.url_override = '';
}

function applySingleUrlToForm(url: string) {
  try {
    const u = new URL(url);
    const host = u.hostname;
    const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    createForm.target_type = isIP ? 'ip' : 'domain';
    createForm.target_value = host;
    createForm.default_scheme = u.protocol.replace(':', '') || 'https';
    createForm.path = u.pathname || '/';
    createForm.url_override = url;
    if (isIP) {
      createForm.virtual_host = u.port ? `${host}:${u.port}` : host;
    }
  } catch {
    return false;
  }
  return true;
}

async function handleFetchTitle() {
  const seed =
    createMode.value === 'single_url'
      ? singleHomepageUrl.value
      : createForm.url_override || createForm.target_value;
  if (!seed) {
    message.warning('请先填写目标值或完整 URL');
    return;
  }
  try {
    const url =
      seed.startsWith('http://') || seed.startsWith('https://')
        ? seed
        : `${createForm.default_scheme}://${seed}${createForm.path || '/'}`;
    const res = await fetchPageMeta(url);
    const meta = (res as any)?.data ?? res;
    if (meta?.title) createForm.name = meta.title;
  } catch {
    message.warning('无法获取页面标题');
  }
}

async function handleCreate() {
  if (createMode.value === 'single_url') {
    if (!singleHomepageUrl.value.trim()) {
      message.warning('请填写监测 URL');
      return;
    }
    if (!applySingleUrlToForm(singleHomepageUrl.value.trim())) {
      message.warning('URL 格式无效');
      return;
    }
    if (!createForm.name.trim()) {
      await handleFetchTitle();
    }
  }
  if (!createForm.name.trim()) {
    message.warning('请填写名称');
    return;
  }
  if (!createForm.target_value.trim()) {
    message.warning('请填写目标值');
    return;
  }
  if (createForm.target_type === 'ip' && !createForm.virtual_host.trim()) {
    message.warning('IP 目标必须填写请求 Host');
    return;
  }
  try {
    const target = await createTarget({
      name: createForm.name.trim(),
      target_type: createForm.target_type,
      target_value: createForm.target_value.trim(),
      virtual_host: createForm.virtual_host.trim(),
      expected_ips: createForm.expected_ips.trim(),
      default_scheme: createForm.default_scheme,
      enabled: true,
      config_domain_hijack: { enabled: true },
      config_sensitive_file: { enabled: true },
    });
    const t = (target as any)?.data ?? target;
    await createPathTask({
      target_id: t.id,
      name: createForm.name.trim(),
      path: createForm.path || '/',
      url_override: createForm.url_override.trim(),
      enabled: true,
      schedule_enabled: true,
      config_availability: { enabled: true, cycle_minutes: 5 },
      config_tamper: { enabled: true },
      config_sensitive_word: { enabled: true },
      config_blacklink: { enabled: true },
    });
    message.success('创建成功');
    createVisible.value = false;
    onSearch();
  } catch (e) {
    handleError(e, '创建失败');
  }
}

async function handleDelete(row: MonitorTarget) {
  try {
    await deleteTarget(row.id);
    message.success('已删除');
    onSearch();
  } catch (e) {
    handleError(e, '删除失败');
  }
}

function handleBatchDelete() {
  if (checkedKeys.value.length === 0) {
    message.warning('请先选择要删除的目标');
    return;
  }
  dialog.error({
    title: '确认批量删除',
    content: `确定删除选中的 ${checkedKeys.value.length} 个目标？关联的路径任务和执行记录也会一并删除。`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await batchDeleteTargets(checkedKeys.value.map(String));
        message.success(`已删除 ${checkedKeys.value.length} 个目标`);
        checkedKeys.value = [];
        onSearch();
      } catch (e) {
        handleError(e, '批量删除失败');
      }
    },
  });
}

async function handleToggle(row: MonitorTarget) {
  try {
    await updateTarget(row.id, { enabled: !row.enabled });
    message.success('已更新');
    onSearch();
  } catch (e) {
    handleError(e, '更新失败');
  }
}

async function handleRunTarget(row: MonitorTarget) {
  try {
    const res = await runTarget(row.id);
    const data = (res as any)?.data ?? res;
    message.success(`已下发 ${data?.execution_ids?.length ?? 0} 条执行`);
  } catch (e) {
    handleError(e, '执行失败');
  }
}

const importVisible = ref(false);
const importUploading = ref(false);
const importProgress = ref<ImportResult | null>(null);
const templateDownloading = ref(false);

const failedResults = computed(() =>
  importProgress.value?.results?.filter((r) => !r.success) ?? [],
);

const importResultColumns = computed<DataTableColumns<ImportRowResult>>(() => [
  { key: 'row', title: '行号', width: 60, align: 'center' },
  { key: 'name', title: '名称', width: 140, ellipsis: { tooltip: true } },
  { key: 'url', title: 'URL', minWidth: 200, ellipsis: { tooltip: true } },
  { key: 'error', title: '失败原因', minWidth: 180, ellipsis: { tooltip: true },
    render: (row) => h('span', { class: 'text-red-500' }, row.error || '未知错误'),
  },
]);

async function handleExportImportResult() {
  if (!importProgress.value?.id) return;
  try {
    const blob = await downloadImportResult(importProgress.value.id);
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `导入结果_${importProgress.value.id}.xlsx`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    handleError(e, '导出失败');
  }
}

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

async function handleImportUpload(options: { file: UploadFileInfo }) {
  const raw = options.file.file;
  if (!raw) return;
  importUploading.value = true;
  importProgress.value = null;
  try {
    const res = await importTargets(raw);
    const startData = (res as any)?.data ?? res;
    const importId = startData.id;
    if (!importId) {
      message.error('导入启动失败');
      return;
    }
    importProgress.value = {
      id: importId,
      status: 'running',
      total: startData.total || 0,
      success: 0,
      failed: 0,
      processed: 0,
      results: [],
      created_at: '',
    };
    await pollImportResult(importId);
  } catch (e) {
    handleError(e, '导入失败');
  } finally {
    importUploading.value = false;
  }
}

async function pollImportResult(importId: string) {
  const maxAttempts = 600;
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      const res = await getImportResult(importId);
      const data = (res as any)?.data ?? res;
      importProgress.value = data;
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

// ═════ 展开行：显示路径任务与维度状态 ═════
const expandedRowKeys = ref<DataTableRowKey[]>([]);
const expandedPathTasks = ref<Record<string, MonitorPathTask[]>>({});
const expandLoading = ref<Record<string, boolean>>({});

const dimensionLabels: Record<string, string> = {
  availability: '可用性',
  tamper: '篡改',
  sensitive_word: '敏感词',
  blacklink: '暗链',
  domain_hijack: '域名劫持',
  sensitive_file: '敏感文件',
};

async function handleExpandChange(keys: DataTableRowKey[]) {
  expandedRowKeys.value = keys;
  for (const key of keys) {
    const id = String(key);
    if (expandedPathTasks.value[id]) continue;
    expandLoading.value[id] = true;
    try {
      const res = await getPathTaskList({ target_id: id, page_size: 200, page: 1 });
      expandedPathTasks.value[id] = res.data || [];
    } catch {
      expandedPathTasks.value[id] = [];
    } finally {
      expandLoading.value[id] = false;
    }
  }
}

function renderExpand(row: MonitorTarget) {
  const id = row.id;
  if (expandLoading.value[id]) {
    return h('div', { class: 'flex items-center justify-center py-4' }, [
      h(NSpin, { size: 'small' }),
      h('span', { class: 'ml-2 text-sm text-gray-400' }, '加载中...'),
    ]);
  }
  const tasks = expandedPathTasks.value[id] || [];

  const targetDims = ['domain_hijack', 'sensitive_file'];
  const targetDimTags = targetDims.map((dim) => {
    const cfg = row[`config_${dim}` as keyof MonitorTarget] as any;
    const enabled = cfg?.enabled;
    return h(
      NTooltip,
      {},
      {
        trigger: () =>
          h(
            NTag,
            {
              size: 'tiny',
              round: true,
              bordered: false,
              type: enabled ? 'success' : 'default',
              style: enabled ? '' : 'opacity: 0.5',
            },
            { default: () => dimensionLabels[dim] || dim },
          ),
        default: () => `目标级 · ${enabled ? '已启用' : '未启用'}`,
      },
    );
  });

  if (tasks.length === 0) {
    return h(
      'div',
      { class: 'rounded-lg bg-gray-50 p-4 dark:bg-gray-800/30' },
      [
        h('div', { class: 'mb-2 flex items-center gap-2' }, [
          h('span', { class: 'text-xs font-medium text-gray-500' }, '目标级维度：'),
          ...targetDimTags,
        ]),
        h(
          'div',
          { class: 'text-center text-sm text-gray-400' },
          '暂无路径任务，请点击"管理"添加',
        ),
      ],
    );
  }

  const pathDims = ['availability', 'tamper', 'sensitive_word', 'blacklink'];

  const taskRows = tasks.map((task) => {
    const dimTags = pathDims.map((dim) => {
      const cfg = task[`config_${dim}` as keyof MonitorPathTask] as any;
      const enabled = cfg?.enabled;
      return h(
        NTooltip,
        {},
        {
          trigger: () =>
            h(
              NTag,
              {
                size: 'tiny',
                round: true,
                bordered: false,
                type: enabled ? 'info' : 'default',
                style: enabled ? '' : 'opacity: 0.4',
              },
              { default: () => dimensionLabels[dim] || dim },
            ),
          default: () =>
            `${enabled ? '已启用' : '未启用'}${cfg?.cycle_minutes ? ` · ${cfg.cycle_minutes}分钟` : ''}`,
        },
      );
    });

    return h(
      'div',
      {
        class:
          'flex items-center gap-3 rounded px-3 py-2 transition-colors hover:bg-white dark:hover:bg-gray-700/30',
      },
      [
        h('span', {
          class: `inline-block h-1.5 w-1.5 flex-shrink-0 rounded-full ${task.enabled ? 'bg-green-400' : 'bg-gray-300'}`,
        }),
        h(
          'span',
          {
            class: 'w-32 flex-shrink-0 truncate text-sm font-medium',
            title: task.name,
          },
          task.name,
        ),
        h(
          'span',
          {
            class: 'min-w-0 flex-1 truncate text-xs text-gray-400',
            title: task.url_override || task.path || '/',
          },
          task.url_override || task.path || '/',
        ),
        h('div', { class: 'flex flex-shrink-0 gap-1' }, dimTags),
        h(
          NButton,
          {
            text: true,
            type: 'primary',
            size: 'tiny',
            class: 'flex-shrink-0',
            onClick: () =>
              router.push({
                name: 'MonitorRecords',
                params: { pathTaskId: task.id },
              }),
          },
          { default: () => '记录' },
        ),
      ],
    );
  });

  return h(
    'div',
    { class: 'rounded-lg bg-gray-50 p-3 dark:bg-gray-800/30' },
    [
      h('div', { class: 'mb-2 flex items-center gap-2' }, [
        h('span', { class: 'text-xs font-medium text-gray-500' }, '目标级维度：'),
        ...targetDimTags,
      ]),
      h('div', { class: 'mb-1.5 flex items-center justify-between' }, [
        h('span', { class: 'text-xs font-medium text-gray-500' }, `路径任务 (${tasks.length})`),
        h(
          NButton,
          {
            text: true,
            type: 'primary',
            size: 'tiny',
            onClick: () =>
              router.push({ name: 'MonitorTargetDetail', params: { id } }),
          },
          { default: () => '全部管理 →' },
        ),
      ]),
      h('div', { class: 'flex flex-col gap-0.5' }, taskRows),
    ],
  );
}

onMounted(onSearch);
</script>

<template>
  <Page auto-content-height>
    <NCard :bordered="false">
      <template #header>
        <div class="flex items-center gap-2">
          <span class="text-lg font-semibold">监测任务</span>
          <NTag size="small" :bordered="false" type="info" round>
            {{ pagination.itemCount }} 个目标
          </NTag>
        </div>
      </template>
      <template #header-extra>
        <NSpace>
          <NButton
            v-if="checkedKeys.length > 0"
            size="small"
            type="error"
            @click="handleBatchDelete"
          >
            批量删除 ({{ checkedKeys.length }})
          </NButton>
          <NButton size="small" @click="importVisible = true">批量导入</NButton>
          <NButton type="primary" size="small" @click="createVisible = true">+ 新建目标</NButton>
        </NSpace>
      </template>

      <div class="mb-4 flex flex-wrap items-center gap-3 rounded-lg bg-gray-50 px-4 py-3 dark:bg-gray-800/50">
        <NInput
          v-model:value="form.name"
          placeholder="搜索名称"
          clearable
          size="small"
          style="width: 160px"
          @keyup.enter="onSearch"
        >
          <template #prefix>
            <span class="text-xs text-gray-400">名称</span>
          </template>
        </NInput>
        <NInput
          v-model:value="form.target_value"
          placeholder="搜索域名/IP"
          clearable
          size="small"
          style="width: 200px"
          @keyup.enter="onSearch"
        >
          <template #prefix>
            <span class="text-xs text-gray-400">目标</span>
          </template>
        </NInput>
        <NSelect
          v-model:value="form.target_type"
          :options="targetTypeOptions"
          placeholder="全部类型"
          clearable
          size="small"
          style="width: 120px"
        />
        <NSelect
          v-model:value="form.enabled"
          :options="enabledOptions"
          size="small"
          style="width: 100px"
        />
        <NButton type="primary" size="small" @click="onSearch">查询</NButton>
        <NButton size="small" quaternary @click="resetForm">重置</NButton>
      </div>

      <div class="mb-3 rounded-lg border border-blue-100 bg-blue-50 px-4 py-3 text-sm text-blue-700 dark:border-blue-900/50 dark:bg-blue-950/30 dark:text-blue-200">
        <strong>请求 Host</strong>
        是发起 HTTP/HTTPS 检测时写入的 Host 头。域名目标默认使用目标域名；IP 目标用于“访问某个 IP:端口，但让服务端按指定站点域名响应”的场景。
      </div>

      <NDataTable
        v-model:checked-row-keys="checkedKeys"
        :columns="columns"
        :data="dataList"
        :loading="loading"
        :pagination="pagination"
        :row-key="(row: MonitorTarget) => row.id"
        :expanded-row-keys="expandedRowKeys"
        :render-expand="renderExpand as any"
        :bordered="false"
        :single-line="false"
        striped
        remote
        size="small"
        @update:expanded-row-keys="handleExpandChange"
        @update:page="(p: number) => { pagination.page = p; onSearch(); }"
        @update:page-size="(s: number) => { pagination.pageSize = s; pagination.page = 1; onSearch(); }"
      />
    </NCard>

    <NModal
      v-model:show="createVisible"
      preset="card"
      title="新建监测目标"
      style="width: 560px"
      @after-leave="resetCreateForm"
    >
      <div class="mb-4 flex gap-2">
        <div
          :class="[
            'flex-1 cursor-pointer rounded-lg border-2 p-3 text-center transition-all',
            createMode === 'single_url'
              ? 'border-primary bg-primary/5'
              : 'border-gray-200 hover:border-gray-300',
          ]"
          @click="createMode = 'single_url'"
        >
          <div class="text-sm font-medium">快速添加</div>
          <div class="text-xs text-gray-400">输入 URL 自动识别</div>
        </div>
        <div
          :class="[
            'flex-1 cursor-pointer rounded-lg border-2 p-3 text-center transition-all',
            createMode === 'advanced'
              ? 'border-primary bg-primary/5'
              : 'border-gray-200 hover:border-gray-300',
          ]"
          @click="createMode = 'advanced'"
        >
          <div class="text-sm font-medium">高级配置</div>
          <div class="text-xs text-gray-400">手动填写域名/IP</div>
        </div>
      </div>
      <NForm label-placement="left" label-width="100">
        <template v-if="createMode === 'single_url'">
          <NFormItem label="监测 URL" required>
            <NSpace style="width: 100%">
              <NInput
                v-model:value="singleHomepageUrl"
                placeholder="https://www.example.com"
                style="flex: 1"
                @keyup.enter="handleCreate"
              />
              <NButton size="small" @click="handleFetchTitle">自动填充</NButton>
            </NSpace>
          </NFormItem>
          <NFormItem label="名称">
            <NInput v-model:value="createForm.name" placeholder="留空将自动获取页面标题" />
          </NFormItem>
        </template>
        <template v-else>
        <NFormItem label="名称" required>
          <NSpace>
            <NInput v-model:value="createForm.name" placeholder="系统名称" />
            <NButton size="small" @click="handleFetchTitle">抓取标题</NButton>
          </NSpace>
        </NFormItem>
        <NFormItem label="目标类型" required>
          <NSelect v-model:value="createForm.target_type" :options="targetTypeOptions" />
        </NFormItem>
        <NFormItem label="目标值" required>
          <NInput
            v-model:value="createForm.target_value"
            :placeholder="createForm.target_type === 'ip' ? '1.2.3.4' : 'www.example.com'"
          />
        </NFormItem>
        <NFormItem v-if="createForm.target_type === 'ip'" label="请求 Host" required>
          <NInput
            v-model:value="createForm.virtual_host"
            placeholder="例如 www.example.com 或 www.example.com:8443"
          />
          <div class="mt-1 text-xs text-gray-400">
            访问 IP 时写入 HTTP Host 头，用于命中该 IP 上承载的具体站点。
          </div>
        </NFormItem>
        <NFormItem label="期望 IP">
          <NInput
            v-model:value="createForm.expected_ips"
            placeholder="劫持检测用，逗号分隔"
          />
        </NFormItem>
        <NFormItem label="协议">
          <NSelect
            v-model:value="createForm.default_scheme"
            :options="[
              { label: 'HTTPS', value: 'https' },
              { label: 'HTTP', value: 'http' },
            ]"
          />
        </NFormItem>
        <NFormItem label="路径">
          <NInput v-model:value="createForm.path" placeholder="默认 /" />
        </NFormItem>
        <NFormItem label="URL 覆盖">
          <NInput
            v-model:value="createForm.url_override"
            placeholder="可选，填写完整 URL 则忽略路径拼接"
          />
        </NFormItem>
        </template>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="createVisible = false">取消</NButton>
          <NButton type="primary" @click="handleCreate">创建</NButton>
        </NSpace>
      </template>
    </NModal>

    <NModal v-model:show="importVisible" preset="card" title="批量导入"
      :style="{ width: importProgress && importProgress.status === 'completed' && importProgress.failed > 0 ? '720px' : '520px' }"
      :mask-closable="!importUploading">
      <template v-if="importProgress && importProgress.status !== 'completed'">
        <div class="mb-3 text-sm">
          <p class="mb-2">正在导入，请勿关闭此窗口...</p>
          <NProgress
            type="line"
            :percentage="importProgress.total ? Math.round((importProgress.processed / importProgress.total) * 100) : 0"
            :status="importProgress.status === 'failed' ? 'error' : 'default'"
          />
          <p class="mt-2 text-xs text-gray-500">
            进度：{{ importProgress.processed }} / {{ importProgress.total }}
            （成功 {{ importProgress.success }}，失败 {{ importProgress.failed }}）
          </p>
        </div>
      </template>
      <template v-else-if="importProgress && importProgress.status === 'completed'">
        <div class="mb-3">
          <NAlert :type="importProgress.failed > 0 ? 'warning' : 'success'" class="mb-2">
            导入完成：共 {{ importProgress.total }} 条，成功 {{ importProgress.success }} 条，失败 {{ importProgress.failed }} 条
          </NAlert>
          <template v-if="importProgress.failed > 0 && failedResults.length > 0">
            <div class="mb-2 flex items-center justify-between">
              <span class="text-sm font-medium text-red-600">失败明细（{{ failedResults.length }} 条）</span>
              <NButton size="tiny" @click="handleExportImportResult">导出完整结果</NButton>
            </div>
            <NDataTable
              :columns="importResultColumns"
              :data="failedResults"
              :bordered="false"
              :single-line="false"
              size="small"
              :max-height="280"
              :row-key="(row: ImportRowResult) => row.row"
              striped
            />
          </template>
          <NSpace class="mt-3" size="small">
            <NButton size="small" @click="importProgress = null">重新导入</NButton>
            <NButton size="small" type="primary" @click="handleExportImportResult">导出导入结果</NButton>
          </NSpace>
        </div>
      </template>
      <template v-else>
        <div class="mb-3 text-sm text-gray-500">
          <p class="mb-1">
            <NButton
              text
              type="primary"
              :loading="templateDownloading"
              @click="handleDownloadTemplate"
            >
              下载模板
            </NButton>
            后按列填写；最简只需填写"监测URL"列即可，系统自动识别域名/IP并启用全部检测维度。
          </p>
          <p class="text-xs text-gray-400">支持域名或 IP 目标（IP 目标需填写请求 Host）。</p>
        </div>
        <NUpload :custom-request="handleImportUpload as any" :show-file-list="false">
          <NUploadDragger>
            <div>点击或拖拽 Excel 到此处上传</div>
          </NUploadDragger>
        </NUpload>
      </template>
    </NModal>
  </Page>
</template>
