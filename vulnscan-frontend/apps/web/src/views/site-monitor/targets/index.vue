<script lang="ts" setup>
import type { DataTableColumns, DataTableRowKey, UploadFileInfo } from 'naive-ui';

import type { MonitorPathTask, MonitorTarget } from '#/api/sitemonitor';

import { computed, h, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';

import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NRadioButton,
  NRadioGroup,
  NSelect,
  NSpace,
  NSpin,
  NTag,
  NTooltip,
  NUpload,
  NUploadDragger,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import { useErrorHandler } from '#/composables/useErrorHandler';
import {
  createPathTask,
  createTarget,
  deleteTarget,
  downloadImportTemplate,
  fetchPageMeta,
  getPathTaskList,
  getTargetList,
  importTargets,
  runTarget,
  updateTarget,
} from '#/api/sitemonitor';

defineOptions({ name: 'MonitorTargets' });

const router = useRouter();
const { handleError } = useErrorHandler();

const loading = ref(false);
const dataList = ref<MonitorTarget[]>([]);
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

const columns = computed<DataTableColumns<MonitorTarget>>(() => [
  {
    key: 'name',
    title: '名称',
    minWidth: 160,
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
        h('span', { class: 'text-xs text-gray-400' }, row.target_value),
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
    title: '虚拟 Host',
    minWidth: 140,
    ellipsis: { tooltip: true },
    render: (row) =>
      h(
        'span',
        { class: row.virtual_host ? '' : 'text-gray-300' },
        row.virtual_host || '-',
      ),
  },
  {
    key: 'expected_ips',
    title: '期望 IP',
    minWidth: 120,
    ellipsis: { tooltip: true },
    render: (row) =>
      h(
        'span',
        { class: row.expected_ips ? '' : 'text-gray-300' },
        row.expected_ips || '-',
      ),
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
    width: 220,
    fixed: 'right',
    align: 'center',
    render: (row) =>
      h(NSpace, { size: 4, justify: 'center' }, () => [
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
        h('span', { class: 'text-gray-200' }, '|'),
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
        h('span', { class: 'text-gray-200' }, '|'),
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
        h('span', { class: 'text-gray-200' }, '|'),
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
      index: pagination.page,
      name: form.name,
      target_type: form.target_type,
      target_value: form.target_value,
      size: pagination.pageSize,
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
    message.warning('IP 目标必须填写虚拟 Host');
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

async function handleImportUpload(options: { file: UploadFileInfo }) {
  const raw = options.file.file;
  if (!raw) return;
  importUploading.value = true;
  try {
    const res = await importTargets(raw);
    const data = (res as any)?.data ?? res;
    message.success(`导入完成：成功 ${data.success}，失败 ${data.failed}`);
    importVisible.value = false;
    onSearch();
  } catch (e) {
    handleError(e, '导入失败');
  } finally {
    importUploading.value = false;
  }
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
      const res = await getPathTaskList({ target_id: id, size: 200, index: 1 });
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

      <NDataTable
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
        <NFormItem v-if="createForm.target_type === 'ip'" label="虚拟 Host" required>
          <NInput
            v-model:value="createForm.virtual_host"
            placeholder="访问 IP 时 HTTP Host 头"
          />
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

    <NModal v-model:show="importVisible" preset="card" title="批量导入" style="width: 480px">
      <p class="text-muted-foreground mb-3 text-sm">
        <a :href="downloadImportTemplate()" target="_blank">下载模板</a>
        后按列填写；支持域名或 IP（IP 需填虚拟 Host）。
      </p>
      <NUpload :custom-request="handleImportUpload as any" :show-file-list="false">
        <NUploadDragger>
          <div>点击或拖拽 Excel 到此处上传</div>
        </NUploadDragger>
      </NUpload>
    </NModal>
  </Page>
</template>
