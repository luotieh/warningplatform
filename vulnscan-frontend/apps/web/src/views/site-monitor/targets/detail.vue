<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import type {
  DimensionConfig,
  FileLibrary,
  MonitorCrawlJob,
  MonitorPathTask,
  MonitorTarget,
} from '#/api/sitemonitor';

import { computed, h, onMounted, reactive, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useOpenTaskRecordsTab } from '../composables/useOpenTaskRecordsTab';

import { Page } from '@vben/common-ui';

import {
  NAlert,
  NButton,
  NCard,
  NDataTable,
  NDrawer,
  NDrawerContent,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NModal,
  NPopconfirm,
  NRadioButton,
  NRadioGroup,
  NSpace,
  NSpin,
  NSwitch,
  NTag,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import { useErrorHandler } from '#/composables/useErrorHandler';
import {
  applyCrawlPaths,
  createPathTask,
  deletePathTask,
  fetchPageMeta,
  getCrawlJob,
  getFileLibraryList,
  getPathTaskExecutionStats,
  getPathTaskList,
  getTargetDetail,
  runPathTask,
  startCrawl,
  updatePathTask,
  updateTarget,
} from '#/api/sitemonitor';

import DimensionConfigForm from '../tasks/components/DimensionConfigForm.vue';

defineOptions({ name: 'MonitorTargetDetail' });

const route = useRoute();
const router = useRouter();
const { openTaskRecordsTab } = useOpenTaskRecordsTab();
const { handleError } = useErrorHandler();

const targetId = computed(() => String(route.params.id ?? ''));
const target = ref<MonitorTarget | null>(null);
const pathTasks = ref<MonitorPathTask[]>([]);
const loading = ref(false);
const statsMap = ref<Record<string, Record<string, { total: number; issue_count: number }>>>({});
const fileLibraries = ref<FileLibrary[]>([]);

const pathDimensions = [
  { key: 'availability', label: '可用性' },
  { key: 'tamper', label: '篡改' },
  { key: 'sensitive_word', label: '敏感词' },
  { key: 'blacklink', label: '黑链' },
];

const targetDimensions = [
  { key: 'domain_hijack', label: '域名劫持' },
  { key: 'sensitive_file', label: '敏感文件' },
];

async function loadTarget() {
  if (!targetId.value) return;
  try {
    const res = await getTargetDetail(targetId.value);
    target.value = (res as any)?.data ?? res;
  } catch (e) {
    handleError(e, '加载目标失败');
  }
}

async function loadPathTasks() {
  if (!targetId.value) return;
  loading.value = true;
  try {
    const [listRes, statsRes] = await Promise.all([
      getPathTaskList({ target_id: targetId.value, size: 200, index: 1 }),
      getPathTaskExecutionStats(),
    ]);
    pathTasks.value = listRes.data || [];
    statsMap.value = (statsRes as any)?.data ?? statsRes ?? {};
  } catch (e) {
    handleError(e, '加载路径任务失败');
    pathTasks.value = [];
  } finally {
    loading.value = false;
  }
}

async function refresh() {
  await loadTarget();
  await loadPathTasks();
}

const columns = computed<DataTableColumns<MonitorPathTask>>(() => [
  { key: 'name', title: '名称', minWidth: 120, ellipsis: { tooltip: true } },
  {
    key: 'url',
    title: '访问地址',
    minWidth: 200,
    ellipsis: { tooltip: true },
    render: (row) => row.url_override || row.path || '/',
  },
  {
    key: 'enabled',
    title: '状态',
    width: 72,
    render: (row) =>
      h(
        NTag,
        { size: 'small', type: row.enabled ? 'success' : 'default', bordered: false },
        { default: () => (row.enabled ? '启用' : '停用') },
      ),
  },
  {
    key: 'stats',
    title: '记录数',
    width: 80,
    render: (row) => {
      const total = Object.values(statsMap.value[row.id] || {}).reduce(
        (s, v) => s + (v?.total ?? 0),
        0,
      );
      return String(total);
    },
  },
  {
    key: 'op',
    title: '操作',
    width: 300,
    fixed: 'right',
    render: (row) =>
      h(NSpace, { size: 'small' }, () => [
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
            onClick: () => openTaskRecordsTab(row),
          },
          { default: () => '记录' },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleRunPath(row) },
          {
            trigger: () =>
              h(NButton, { text: true, size: 'small' }, { default: () => '执行' }),
            default: () => '执行全部已启用路径维度？',
          },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDeletePath(row) },
          {
            trigger: () =>
              h(NButton, { text: true, type: 'error', size: 'small' }, { default: () => '删除' }),
            default: () => '确认删除？',
          },
        ),
      ]),
  },
]);

const drawerVisible = ref(false);
const editingPath = ref<MonitorPathTask | null>(null);
const pathConfigs = reactive<Record<string, DimensionConfig>>({});

function normalizePathDimConfig(
  dim: string,
  cfg?: DimensionConfig,
): DimensionConfig {
  const base: DimensionConfig = { ...(cfg || {}), enabled: cfg?.enabled ?? false };
  if (['availability', 'tamper', 'sensitive_word', 'blacklink'].includes(dim)) {
    const mins = base.cycle_minutes ?? 1;
    const cronMin = mins > 59 ? 59 : mins;
    base.cycle_minutes = mins;
    base.cron = base.cron || `0 */${cronMin} * * * *`;
  }
  return base;
}

function openDrawer(row?: MonitorPathTask) {
  pathInputMode.value = row?.url_override ? 'single_url' : 'path';
  if (row) {
    editingPath.value = row;
    for (const d of pathDimensions) {
      const cfg = row[`config_${d.key}` as keyof MonitorPathTask] as DimensionConfig;
      pathConfigs[d.key] = normalizePathDimConfig(d.key, cfg);
    }
  } else {
    editingPath.value = null;
    pathInputMode.value = 'single_url';
    for (const d of pathDimensions) {
      pathConfigs[d.key] = normalizePathDimConfig(d.key, { enabled: true });
    }
  }
  drawerVisible.value = true;
}

const pathInputMode = ref<'path' | 'single_url'>('path');
const fetchingPathTitle = ref(false);

const pathForm = reactive({
  name: '',
  path: '/',
  url_override: '',
  enabled: true,
});

async function fetchTitleForPath() {
  const url = pathForm.url_override.trim();
  if (!url) {
    message.warning('请先填写监测 URL');
    return;
  }
  fetchingPathTitle.value = true;
  try {
    const res = await fetchPageMeta(url);
    const meta = (res as any)?.data ?? res;
    if (meta?.title) pathForm.name = meta.title;
  } catch {
    message.warning('无法获取页面标题，请手动填写名称');
  } finally {
    fetchingPathTitle.value = false;
  }
}

watch(editingPath, (row) => {
  if (row) {
    pathForm.name = row.name;
    pathForm.path = row.path || '/';
    pathForm.url_override = row.url_override || '';
    pathForm.enabled = row.enabled;
  } else {
    pathForm.name = '';
    pathForm.path = '/';
    pathForm.url_override = '';
    pathForm.enabled = true;
  }
});

async function savePathTask() {
  if (!pathForm.name.trim()) {
    message.warning('请填写名称');
    return;
  }
  if (pathInputMode.value === 'single_url') {
    if (!pathForm.url_override.trim()) {
      message.warning('请填写完整监测 URL');
      return;
    }
    pathForm.path = '/';
  } else if (!pathForm.path.trim() && !pathForm.url_override.trim()) {
    message.warning('请填写路径或 URL 覆盖');
    return;
  }
  const payload: Record<string, any> = {
    name: pathForm.name,
    path: pathForm.path,
    url_override: pathForm.url_override,
    enabled: pathForm.enabled,
    schedule_enabled: true,
    config_availability: normalizePathDimConfig('availability', pathConfigs.availability),
    config_tamper: normalizePathDimConfig('tamper', pathConfigs.tamper),
    config_sensitive_word: normalizePathDimConfig('sensitive_word', pathConfigs.sensitive_word),
    config_blacklink: normalizePathDimConfig('blacklink', pathConfigs.blacklink),
  };
  try {
    if (editingPath.value) {
      await updatePathTask(editingPath.value.id, payload);
      message.success('已保存');
    } else {
      await createPathTask({
        target_id: targetId.value,
        ...payload,
      } as any);
      message.success('已创建');
    }
    drawerVisible.value = false;
    loadPathTasks();
  } catch (e) {
    handleError(e, '保存失败');
  }
}

async function handleDeletePath(row: MonitorPathTask) {
  try {
    await deletePathTask(row.id);
    message.success('已删除');
    loadPathTasks();
  } catch (e) {
    handleError(e, '删除失败');
  }
}

async function handleRunPath(row: MonitorPathTask) {
  try {
    const res = await runPathTask(row.id);
    const data = (res as any)?.data ?? res;
    message.success(`已下发 ${data?.execution_ids?.length ?? 0} 条执行`);
  } catch (e) {
    handleError(e, '执行失败');
  }
}

const targetDrawerVisible = ref(false);
const targetConfigs = reactive<Record<string, DimensionConfig>>({});

function openTargetConfig() {
  if (!target.value) return;
  for (const d of targetDimensions) {
    const cfg = target.value[`config_${d.key}` as keyof MonitorTarget] as DimensionConfig;
    targetConfigs[d.key] = { ...(cfg || {}), enabled: cfg?.enabled ?? false };
  }
  targetDrawerVisible.value = true;
}

async function saveTargetConfig() {
  if (!target.value) return;
  try {
    await updateTarget(target.value.id, {
      config_domain_hijack: targetConfigs.domain_hijack,
      config_sensitive_file: targetConfigs.sensitive_file,
    });
    message.success('目标配置已保存');
    targetDrawerVisible.value = false;
    loadTarget();
  } catch (e) {
    handleError(e, '保存失败');
  }
}

const crawlVisible = ref(false);
const crawlForm = reactive({
  use_headless: true,
  max_depth: 2,
  max_pages: 50,
});
const crawlJob = ref<MonitorCrawlJob | null>(null);
const crawlPolling = ref(false);

async function handleStartCrawl() {
  if (!targetId.value) return;
  try {
    const res = await startCrawl(targetId.value, {
      use_headless: crawlForm.use_headless,
      max_depth: crawlForm.max_depth,
      max_pages: crawlForm.max_pages,
      same_host: true,
    });
    crawlJob.value = (res as any)?.data ?? res;
    crawlPolling.value = true;
    pollCrawlJob();
  } catch (e) {
    handleError(e, '启动爬虫失败');
  }
}

async function pollCrawlJob() {
  if (!crawlJob.value?.id) return;
  const tick = async () => {
    try {
      const res = await getCrawlJob(crawlJob.value!.id);
      crawlJob.value = (res as any)?.data ?? res;
      if (
        crawlJob.value?.status === 'success' ||
        crawlJob.value?.status === 'failed'
      ) {
        crawlPolling.value = false;
        return;
      }
      setTimeout(tick, 2000);
    } catch {
      crawlPolling.value = false;
    }
  };
  tick();
}

async function handleApplyCrawl() {
  if (!crawlJob.value?.id) return;
  try {
    const res = await applyCrawlPaths(crawlJob.value.id, { skip_existing: true });
    const n = (res as any)?.data?.created ?? (res as any)?.created ?? 0;
    message.success(`已创建 ${n} 条路径任务`);
    crawlVisible.value = false;
    loadPathTasks();
  } catch (e) {
    handleError(e, '应用路径失败');
  }
}

async function loadLibraries() {
  try {
    const f = await getFileLibraryList({ size: 100 });
    fileLibraries.value = f.data || [];
  } catch {
    // ignore
  }
}

onMounted(() => {
  loadLibraries();
  refresh();
});
watch(targetId, refresh);
</script>

<template>
  <Page auto-content-height>
    <NSpin :show="!target && loading">
      <NCard v-if="target" :bordered="false" class="mb-4">
        <template #header>
          <NSpace align="center">
            <NButton text @click="router.push({ name: 'MonitorTargets' })">← 返回</NButton>
            <span class="text-lg font-medium">{{ target.name }}</span>
            <NTag size="small" :type="target.target_type === 'ip' ? 'warning' : 'info'">
              {{ target.target_type === 'ip' ? 'IP' : '域名' }}
            </NTag>
          </NSpace>
        </template>
        <template #header-extra>
          <NSpace>
            <NButton @click="openTargetConfig">目标级配置</NButton>
            <NButton type="primary" @click="crawlVisible = true">站点爬虫</NButton>
          </NSpace>
        </template>
        <NSpace wrap>
          <span>目标值：<b>{{ target.target_value }}</b></span>
          <span v-if="target.virtual_host">虚拟 Host：<b>{{ target.virtual_host }}</b></span>
          <span v-if="target.expected_ips">期望 IP：{{ target.expected_ips }}</span>
        </NSpace>
      </NCard>

      <NCard title="路径监测任务" :bordered="false">
        <template #header-extra>
          <NSpace>
            <NButton type="primary" @click="openDrawer()">单 URL 添加</NButton>
            <NButton @click="() => { pathInputMode = 'path'; openDrawer(); }">添加路径</NButton>
          </NSpace>
        </template>
        <NDataTable
          :columns="columns"
          :data="pathTasks"
          :loading="loading"
          :row-key="(r: MonitorPathTask) => r.id"
        />
      </NCard>
    </NSpin>

    <NDrawer v-model:show="drawerVisible" :width="640" placement="right">
      <NDrawerContent :title="editingPath ? '编辑路径任务' : '新建路径任务'" closable>
        <NAlert type="info" class="mb-3" :bordered="false">
          单 URL 模式：填写完整地址即可监测该页面（等同旧版「首页 URL」任务）；路径模式：按目标主机 + 路径拼接访问。
        </NAlert>
        <NForm label-placement="left" label-width="96">
          <NFormItem label="配置模式">
            <NRadioGroup v-model:value="pathInputMode">
              <NRadioButton value="single_url">单 URL</NRadioButton>
              <NRadioButton value="path">路径模式</NRadioButton>
            </NRadioGroup>
          </NFormItem>
          <NFormItem label="名称">
            <NInput v-model:value="pathForm.name" placeholder="任务显示名称" />
          </NFormItem>
          <template v-if="pathInputMode === 'single_url'">
            <NFormItem label="监测 URL" required>
              <NSpace style="width: 100%">
                <NInput
                  v-model:value="pathForm.url_override"
                  placeholder="https://www.example.com/page"
                  style="flex: 1"
                />
                <NButton :loading="fetchingPathTitle" @click="fetchTitleForPath">自动填充</NButton>
              </NSpace>
            </NFormItem>
          </template>
          <template v-else>
            <NFormItem label="路径">
              <NInput v-model:value="pathForm.path" placeholder="/" />
            </NFormItem>
            <NFormItem label="URL 覆盖">
              <NInput
                v-model:value="pathForm.url_override"
                placeholder="可选，填写完整 URL 后忽略路径拼接"
              />
            </NFormItem>
          </template>
          <NFormItem label="启用">
            <NSwitch v-model:value="pathForm.enabled" />
          </NFormItem>
        </NForm>
        <DimensionConfigForm
          :configs="pathConfigs"
          :dimensions="pathDimensions"
          :file-libraries="fileLibraries"
        />
        <template #footer>
          <NSpace justify="end">
            <NButton @click="drawerVisible = false">取消</NButton>
            <NButton type="primary" @click="savePathTask">保存</NButton>
          </NSpace>
        </template>
      </NDrawerContent>
    </NDrawer>

    <NDrawer v-model:show="targetDrawerVisible" :width="640">
      <NDrawerContent title="目标级监测配置" closable>
        <DimensionConfigForm
          :configs="targetConfigs"
          :dimensions="targetDimensions"
          :file-libraries="fileLibraries"
        />
        <template #footer>
          <NButton type="primary" @click="saveTargetConfig">保存</NButton>
        </template>
      </NDrawerContent>
    </NDrawer>

    <NModal v-model:show="crawlVisible" preset="card" title="站点爬虫" style="width: 480px">
      <NForm label-placement="left" label-width="120">
        <NFormItem label="无头浏览器(SPA)">
          <NSwitch v-model:value="crawlForm.use_headless" />
        </NFormItem>
        <NFormItem label="最大深度">
          <NInputNumber v-model:value="crawlForm.max_depth" :min="1" :max="5" />
        </NFormItem>
        <NFormItem label="最大页面数">
          <NInputNumber v-model:value="crawlForm.max_pages" :min="1" :max="200" />
        </NFormItem>
      </NForm>
      <div v-if="crawlJob" class="mt-3 text-sm">
        状态：<NTag size="small">{{ crawlJob.status }}</NTag>
        <span v-if="crawlPolling" class="ml-2 text-muted-foreground">轮询中…</span>
      </div>
      <template #footer>
        <NSpace justify="end">
          <NButton
            v-if="crawlJob?.status === 'success'"
            type="primary"
            @click="handleApplyCrawl"
          >
            导入为路径任务
          </NButton>
          <NButton :loading="crawlPolling" type="primary" @click="handleStartCrawl">
            {{ crawlJob ? '重新爬取' : '开始爬取' }}
          </NButton>
        </NSpace>
      </template>
    </NModal>
  </Page>
</template>
