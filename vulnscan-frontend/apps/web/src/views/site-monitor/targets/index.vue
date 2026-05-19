<script lang="ts" setup>
import type { DataTableColumns, UploadFileInfo } from 'naive-ui';

import type { MonitorTarget } from '#/api/sitemonitor';

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
  NTag,
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
    minWidth: 140,
    ellipsis: { tooltip: true },
  },
  {
    key: 'target_type',
    title: '类型',
    width: 80,
    render: (row) =>
      h(
        NTag,
        { size: 'small', bordered: false },
        { default: () => (row.target_type === 'ip' ? 'IP' : '域名') },
      ),
  },
  {
    key: 'target_value',
    title: '目标值',
    minWidth: 160,
    ellipsis: { tooltip: true },
  },
  {
    key: 'virtual_host',
    title: '虚拟 Host',
    minWidth: 140,
    ellipsis: { tooltip: true },
    render: (row) => row.virtual_host || '-',
  },
  {
    key: 'expected_ips',
    title: '期望 IP',
    minWidth: 120,
    ellipsis: { tooltip: true },
    render: (row) => row.expected_ips || '-',
  },
  {
    key: 'enabled',
    title: '状态',
    width: 72,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        {
          type: row.enabled ? 'success' : 'default',
          size: 'small',
          bordered: false,
        },
        { default: () => (row.enabled ? '启用' : '停用') },
      ),
  },
  {
    key: 'op',
    title: '操作',
    width: 280,
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
            onClick: () =>
              router.push({ name: 'MonitorTargetDetail', params: { id: row.id } }),
          },
          { default: () => '路径任务' },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleRunTarget(row) },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, type: 'info', size: 'small' },
                { default: () => '目标检测' },
              ),
            default: () => '执行域名劫持 / 敏感文件等目标级维度？',
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
                  size: 'small',
                },
                { default: () => (row.enabled ? '停用' : '启用') },
              ),
            default: () => `确认${row.enabled ? '停用' : '启用'}？`,
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

onMounted(onSearch);
</script>

<template>
  <Page auto-content-height>
    <NCard title="监测目标" :bordered="false">
      <template #header-extra>
        <NSpace>
          <NButton @click="importVisible = true">批量导入</NButton>
          <NButton type="primary" @click="createVisible = true">新建目标</NButton>
        </NSpace>
      </template>

      <NSpace class="mb-4" wrap>
        <NInput
          v-model:value="form.name"
          placeholder="名称"
          clearable
          style="width: 160px"
          @keyup.enter="onSearch"
        />
        <NSelect
          v-model:value="form.target_type"
          :options="targetTypeOptions"
          placeholder="类型"
          clearable
          style="width: 120px"
        />
        <NInput
          v-model:value="form.target_value"
          placeholder="目标值"
          clearable
          style="width: 180px"
          @keyup.enter="onSearch"
        />
        <NSelect
          v-model:value="form.enabled"
          :options="enabledOptions"
          style="width: 100px"
        />
        <NButton type="primary" @click="onSearch">查询</NButton>
        <NButton @click="resetForm">重置</NButton>
      </NSpace>

      <NDataTable
        :columns="columns"
        :data="dataList"
        :loading="loading"
        :pagination="pagination"
        :row-key="(row: MonitorTarget) => row.id"
        remote
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
      <NForm label-placement="left" label-width="100">
        <NFormItem label="创建方式">
          <NRadioGroup v-model:value="createMode">
            <NRadioButton value="single_url">单 URL（推荐）</NRadioButton>
            <NRadioButton value="advanced">高级（域名/IP）</NRadioButton>
          </NRadioGroup>
        </NFormItem>
        <template v-if="createMode === 'single_url'">
          <NFormItem label="监测 URL" required>
            <NSpace style="width: 100%">
              <NInput
                v-model:value="singleHomepageUrl"
                placeholder="https://www.example.com"
                style="flex: 1"
              />
              <NButton @click="handleFetchTitle">自动填充</NButton>
            </NSpace>
          </NFormItem>
          <NFormItem label="名称" required>
            <NInput v-model:value="createForm.name" placeholder="系统名称" />
          </NFormItem>
        </template>
        <template v-else>
        <NFormItem label="名称" required>
          <NSpace>
            <NInput v-model:value="createForm.name" placeholder="系统名称" />
            <NButton @click="handleFetchTitle">抓取标题</NButton>
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
            placeholder="访问 IP 时 HTTP Host 头，如 www.example.com"
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
