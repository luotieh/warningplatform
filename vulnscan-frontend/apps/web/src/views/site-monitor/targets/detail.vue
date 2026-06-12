<script lang="ts" setup>
import type { DataTableColumns, DataTableRowKey } from 'naive-ui';

import type {
  DimensionConfig,
  FileLibrary,
  MonitorCrawlJob,
  MonitorPathTask,
  MonitorTarget,
} from '#/api/sitemonitor';

import {
  computed,
  h,
  onBeforeUnmount,
  onMounted,
  reactive,
  ref,
  watch,
} from 'vue';
import { useRoute, useRouter } from 'vue-router';

import RecordDrawer from './RecordDrawer.vue';

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
import { fetchAuthImageObjectUrl } from '#/composables/useAuthImageObjectUrl';
import {
  applyCrawlPaths,
  batchDeletePathTasks,
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
const { handleError } = useErrorHandler();

const recordDrawerVisible = ref(false);
const recordDrawerTaskId = ref('');

const targetId = computed(() => String(route.params.id ?? ''));
const target = ref<MonitorTarget | null>(null);
const pathTasks = ref<MonitorPathTask[]>([]);
const loading = ref(false);
const statsMap = ref<
  Record<string, Record<string, { total: number; issue_count: number }>>
>({});
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

const pathPagination = reactive({
  page: 1,
  pageSize: 15,
  itemCount: 0,
  pageSizes: [15, 30, 50, 100],
  showSizePicker: true,
});

async function loadPathTasks() {
  if (!targetId.value) return;
  loading.value = true;
  try {
    const [listRes, statsRes] = await Promise.all([
      getPathTaskList({
        target_id: targetId.value,
        page_size: pathPagination.pageSize,
        page: pathPagination.page,
      }),
      getPathTaskExecutionStats(),
    ]);
    pathTasks.value = listRes.data || [];
    pathPagination.itemCount = (listRes as any).count || 0;
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

// ═════ 批量操作 ═════
const checkedRowKeys = ref<DataTableRowKey[]>([]);

async function handleBatchDelete() {
  if (checkedRowKeys.value.length === 0) return;
  try {
    await batchDeletePathTasks(checkedRowKeys.value.map(String));
    message.success(`已删除 ${checkedRowKeys.value.length} 条路径任务`);
    checkedRowKeys.value = [];
    loadPathTasks();
  } catch (e) {
    handleError(e, '批量删除失败');
  }
}

const columns = computed<DataTableColumns<MonitorPathTask>>(() => [
  { type: 'selection' },
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
        {
          size: 'small',
          type: row.enabled ? 'success' : 'default',
          bordered: false,
        },
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
            onClick: () => {
              recordDrawerTaskId.value = row.id;
              recordDrawerVisible.value = true;
            },
          },
          { default: () => '记录' },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleRunPath(row) },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, size: 'small' },
                { default: () => '执行' },
              ),
            default: () => '执行全部已启用路径维度？',
          },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDeletePath(row) },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, type: 'error', size: 'small' },
                { default: () => '删除' },
              ),
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
  const base: DimensionConfig = {
    ...(cfg || {}),
    enabled: cfg?.enabled ?? false,
  };
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
      const cfg = row[
        `config_${d.key}` as keyof MonitorPathTask
      ] as DimensionConfig;
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
    config_availability: normalizePathDimConfig(
      'availability',
      pathConfigs.availability,
    ),
    config_tamper: normalizePathDimConfig('tamper', pathConfigs.tamper),
    config_sensitive_word: normalizePathDimConfig(
      'sensitive_word',
      pathConfigs.sensitive_word,
    ),
    config_blacklink: normalizePathDimConfig(
      'blacklink',
      pathConfigs.blacklink,
    ),
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
    const cfg = target.value[
      `config_${d.key}` as keyof MonitorTarget
    ] as DimensionConfig;
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
  start_url: '',
  screenshot_width: 1920,
  screenshot_height: 1080,
  screenshot_quality: 80,
});

const resolutionOptions = [
  { label: '1280 × 720 (HD)', value: '1280x720' },
  { label: '1920 × 1080 (FHD)', value: '1920x1080' },
  { label: '2560 × 1440 (2K)', value: '2560x1440' },
  { label: '3840 × 2160 (4K)', value: '3840x2160' },
];

function detectScreenResolution() {
  const dpr = window.devicePixelRatio || 1;
  const sw = Math.round(window.screen.width * dpr);
  const sh = Math.round(window.screen.height * dpr);
  const exact = resolutionOptions.find((o) => o.value === `${sw}x${sh}`);
  if (exact) {
    crawlForm.screenshot_width = sw;
    crawlForm.screenshot_height = sh;
  } else {
    const candidates = resolutionOptions.map((o) => {
      const [w, h] = o.value.split('x').map(Number);
      return { w, h, diff: Math.abs(sw - w) + Math.abs(sh - h) };
    });
    candidates.sort((a, b) => a.diff - b.diff);
    const best = candidates[0]!;
    crawlForm.screenshot_width = best.w;
    crawlForm.screenshot_height = best.h;
  }
}
detectScreenResolution();
const qualityOptions = [
  { label: '60%', value: 60 },
  { label: '70%', value: 70 },
  { label: '80%', value: 80 },
  { label: '90%', value: 90 },
  { label: '100%', value: 100 },
];
function onResolutionChange(val: string) {
  const [w, h] = val.split('x').map(Number);
  crawlForm.screenshot_width = w || 1920;
  crawlForm.screenshot_height = h || 1080;
}
const crawlJob = ref<MonitorCrawlJob | null>(null);
const crawlPolling = ref(false);
const screenshotBaseUrl = ref('');

interface CrawlPage {
  url: string;
  title: string;
  status_code: number;
  depth: number;
  source: string;
  thumbnail?: string;
}

const crawlPages = ref<CrawlPage[]>([]);
const crawlSelectedUrls = ref<string[]>([]);

function parseCrawlPages() {
  if (!crawlJob.value?.result_json) {
    crawlPages.value = [];
    return;
  }
  try {
    const result = JSON.parse(crawlJob.value.result_json);
    const newPages: CrawlPage[] = result.pages || [];
    const existingUrls = new Set(crawlPages.value.map((p) => p.url));
    const newlyDiscovered = newPages.filter(
      (p: CrawlPage) => !existingUrls.has(p.url),
    );
    crawlPages.value = newPages;
    for (const p of newlyDiscovered) {
      if (!crawlSelectedUrls.value.includes(p.url)) {
        crawlSelectedUrls.value.push(p.url);
      }
      if (p.thumbnail && !isBase64(p.thumbnail) && screenshotBaseUrl.value) {
        loadThumbnailFromStorage(p.thumbnail);
      }
    }
  } catch {
    crawlPages.value = [];
  }
}

async function handleStartCrawl() {
  if (!targetId.value) return;
  crawlPages.value = [];
  crawlSelectedUrls.value = [];
  try {
    const res = await startCrawl(targetId.value, {
      use_headless: crawlForm.use_headless,
      max_depth: crawlForm.max_depth,
      max_pages: crawlForm.max_pages,
      same_host: true,
      start_url: crawlForm.start_url.trim() || undefined,
      screenshot_width: crawlForm.screenshot_width,
      screenshot_height: crawlForm.screenshot_height,
      screenshot_quality: crawlForm.screenshot_quality,
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
      const jobData = (res as any)?.data ?? res;
      crawlJob.value = jobData;
      if (jobData.screenshot_base_url) {
        screenshotBaseUrl.value = jobData.screenshot_base_url;
      }
      parseCrawlPages();
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
  if (crawlSelectedUrls.value.length === 0) {
    message.warning('请至少选择一个页面');
    return;
  }
  try {
    const res = await applyCrawlPaths(crawlJob.value.id, {
      skip_existing: true,
      selected_urls: crawlSelectedUrls.value,
    });
    const n = (res as any)?.data?.created ?? (res as any)?.created ?? 0;
    message.success(`已创建 ${n} 条路径任务`);
    crawlVisible.value = false;
    loadPathTasks();
  } catch (e) {
    handleError(e, '应用路径失败');
  }
}

function toggleCrawlSelectAll() {
  if (crawlSelectedUrls.value.length === crawlPages.value.length) {
    crawlSelectedUrls.value = [];
  } else {
    crawlSelectedUrls.value = crawlPages.value.map((p) => p.url);
  }
}

const previewImage = ref('');
const previewTitle = ref('');
const previewVisible = ref(false);

function isBase64(val: string): boolean {
  return val.length > 200;
}

const thumbnailObjectUrls = ref<Record<string, string>>({});

async function loadThumbnailFromStorage(fileId: string): Promise<string> {
  if (thumbnailObjectUrls.value[fileId])
    return thumbnailObjectUrls.value[fileId];
  if (!screenshotBaseUrl.value) return '';
  try {
    const url = await fetchAuthImageObjectUrl(
      `${screenshotBaseUrl.value}/${fileId}/content`,
    );
    thumbnailObjectUrls.value[fileId] = url;
    return url;
  } catch {
    return '';
  }
}

function getThumbnailSrc(page: CrawlPage): string {
  if (!page.thumbnail) return '';
  if (isBase64(page.thumbnail))
    return `data:image/jpeg;base64,${page.thumbnail}`;
  return thumbnailObjectUrls.value[page.thumbnail] || '';
}

async function openThumbnailPreview(page: CrawlPage) {
  if (!page.thumbnail) return;
  previewTitle.value = page.title || page.url;
  if (isBase64(page.thumbnail)) {
    previewImage.value = `data:image/jpeg;base64,${page.thumbnail}`;
  } else {
    const url = await loadThumbnailFromStorage(page.thumbnail);
    if (!url) return;
    previewImage.value = url;
  }
  previewVisible.value = true;
}

async function loadLibraries() {
  try {
    const f = await getFileLibraryList({ page: 1, page_size: 100 });
    fileLibraries.value = f.data || [];
  } catch {
    // ignore
  }
}

onMounted(() => {
  loadLibraries();
  refresh();
});
onBeforeUnmount(() => {
  Object.values(thumbnailObjectUrls.value).forEach(URL.revokeObjectURL);
});
watch(targetId, refresh);
</script>

<template>
  <Page auto-content-height>
    <NSpin :show="!target && loading">
      <NCard v-if="target" :bordered="false" class="mb-4">
        <template #header>
          <NSpace align="center">
            <NButton text @click="router.push({ name: 'MonitorTargets' })"
              >← 返回</NButton
            >
            <span class="text-lg font-medium">{{ target.name }}</span>
            <NTag
              size="small"
              :type="target.target_type === 'ip' ? 'warning' : 'info'"
            >
              {{ target.target_type === 'ip' ? 'IP' : '域名' }}
            </NTag>
          </NSpace>
        </template>
        <template #header-extra>
          <NSpace>
            <NButton @click="openTargetConfig">目标级配置</NButton>
            <NButton type="primary" @click="crawlVisible = true"
              >站点爬虫</NButton
            >
          </NSpace>
        </template>
        <NSpace wrap>
          <span
            >目标值：<b>{{ target.target_value }}</b></span
          >
          <span v-if="target.virtual_host"
            >请求 Host：<b>{{ target.virtual_host }}</b></span
          >
          <span v-if="target.expected_ips"
            >期望 IP：{{ target.expected_ips }}</span
          >
        </NSpace>
      </NCard>

      <NCard title="路径监测任务" :bordered="false">
        <template #header-extra>
          <NSpace>
            <NPopconfirm
              v-if="checkedRowKeys.length > 0"
              @positive-click="handleBatchDelete"
            >
              <template #trigger>
                <NButton type="error" size="small">
                  批量删除 ({{ checkedRowKeys.length }})
                </NButton>
              </template>
              确定删除选中的 {{ checkedRowKeys.length }} 条路径任务？
            </NPopconfirm>
            <NButton type="primary" @click="openDrawer()">单 URL 添加</NButton>
            <NButton
              @click="
                () => {
                  pathInputMode = 'path';
                  openDrawer();
                }
              "
              >添加路径</NButton
            >
          </NSpace>
        </template>
        <NDataTable
          v-model:checked-row-keys="checkedRowKeys"
          :columns="columns"
          :data="pathTasks"
          :loading="loading"
          :pagination="pathPagination"
          :row-key="(r: MonitorPathTask) => r.id"
          remote
          size="small"
          @update:page="
            (p: number) => {
              pathPagination.page = p;
              loadPathTasks();
            }
          "
          @update:page-size="
            (s: number) => {
              pathPagination.pageSize = s;
              pathPagination.page = 1;
              loadPathTasks();
            }
          "
        />
      </NCard>
    </NSpin>

    <NDrawer v-model:show="drawerVisible" :width="640" placement="right">
      <NDrawerContent
        :title="editingPath ? '编辑路径任务' : '新建路径任务'"
        closable
      >
        <NAlert type="info" class="mb-3" :bordered="false">
          单 URL 模式：填写完整地址即可监测该页面（等同旧版「首页
          URL」任务）；路径模式：按目标主机 + 路径拼接访问。
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
                <NButton :loading="fetchingPathTitle" @click="fetchTitleForPath"
                  >自动填充</NButton
                >
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

    <NModal
      v-model:show="crawlVisible"
      preset="card"
      title="站点爬虫"
      style="width: 860px; max-height: 85vh"
    >
      <div class="mb-3 flex items-center gap-2">
        <NInput
          v-model:value="crawlForm.start_url"
          :placeholder="`起始 URL（留空默认 ${target?.default_scheme || 'https'}://${target?.target_value || ''}/）`"
          clearable
          size="small"
          class="flex-1"
        />
        <NSwitch v-model:value="crawlForm.use_headless" class="flex-shrink-0">
          <template #checked>无头</template>
          <template #unchecked>HTTP</template>
        </NSwitch>
        <span class="text-xs text-gray-500 whitespace-nowrap">深度</span>
        <NInputNumber
          v-model:value="crawlForm.max_depth"
          :min="1"
          :max="5"
          size="small"
          style="width: 70px"
        />
        <span class="text-xs text-gray-500 whitespace-nowrap">页数</span>
        <NInputNumber
          v-model:value="crawlForm.max_pages"
          :min="1"
          :max="200"
          size="small"
          style="width: 80px"
        />
        <NButton
          :loading="crawlPolling"
          type="primary"
          size="small"
          class="flex-shrink-0"
          @click="handleStartCrawl"
        >
          {{ crawlJob ? '重新爬取' : '开始爬取' }}
        </NButton>
      </div>

      <!-- 截图配置（仅无头模式显示） -->
      <div
        v-if="crawlForm.use_headless"
        class="mt-2 flex items-center gap-2 text-xs text-gray-500"
      >
        <span>截图分辨率</span>
        <NSelect
          :value="`${crawlForm.screenshot_width}x${crawlForm.screenshot_height}`"
          :options="resolutionOptions"
          size="tiny"
          style="width: 180px"
          filterable
          tag
          placeholder="宽x高，如 1440x900"
          @update:value="onResolutionChange"
        />
        <span>质量</span>
        <NSelect
          v-model:value="crawlForm.screenshot_quality"
          :options="qualityOptions"
          size="tiny"
          style="width: 90px"
        />
      </div>

      <div v-if="crawlJob" class="mt-2 text-sm">
        状态：
        <NTag
          size="small"
          :type="
            crawlJob.status === 'success'
              ? 'success'
              : crawlJob.status === 'failed'
                ? 'error'
                : 'default'
          "
        >
          {{
            crawlJob.status === 'success'
              ? '完成'
              : crawlJob.status === 'failed'
                ? '失败'
                : crawlJob.status === 'running'
                  ? '爬取中...'
                  : crawlJob.status
          }}
        </NTag>
        <span v-if="crawlJob.error" class="ml-2 text-red-500">{{
          crawlJob.error
        }}</span>
        <span v-if="crawlPolling" class="ml-2 text-gray-400">轮询中…</span>
      </div>

      <!-- 爬虫结果列表 -->
      <div v-if="crawlPages.length > 0" class="mt-3">
        <div class="mb-2 flex items-center justify-between">
          <span class="text-sm font-medium">
            发现 {{ crawlPages.length }} 个页面，已选
            {{ crawlSelectedUrls.length }} 个
          </span>
          <NButton
            text
            type="primary"
            size="small"
            @click="toggleCrawlSelectAll"
          >
            {{
              crawlSelectedUrls.length === crawlPages.length
                ? '取消全选'
                : '全选'
            }}
          </NButton>
        </div>
        <div
          style="max-height: 400px; overflow-y: auto"
          class="rounded border border-gray-200 dark:border-gray-700"
        >
          <div
            v-for="(page, idx) in crawlPages"
            :key="page.url"
            :class="[
              'flex cursor-pointer items-center gap-3 px-3 py-2 text-sm transition-colors hover:bg-gray-50 dark:hover:bg-gray-800',
              idx !== crawlPages.length - 1
                ? 'border-b border-gray-100 dark:border-gray-700'
                : '',
              crawlSelectedUrls.includes(page.url)
                ? 'bg-blue-50/50 dark:bg-blue-900/10'
                : '',
            ]"
            @click="
              () => {
                const i = crawlSelectedUrls.indexOf(page.url);
                if (i >= 0) crawlSelectedUrls.splice(i, 1);
                else crawlSelectedUrls.push(page.url);
              }
            "
          >
            <input
              type="checkbox"
              :checked="crawlSelectedUrls.includes(page.url)"
              class="flex-shrink-0"
              @click.stop
              @change="
                () => {
                  const i = crawlSelectedUrls.indexOf(page.url);
                  if (i >= 0) crawlSelectedUrls.splice(i, 1);
                  else crawlSelectedUrls.push(page.url);
                }
              "
            />
            <img
              v-if="page.thumbnail && getThumbnailSrc(page)"
              :src="getThumbnailSrc(page)"
              alt=""
              class="h-10 w-16 flex-shrink-0 cursor-zoom-in rounded border border-gray-200 object-cover transition-shadow hover:shadow-md dark:border-gray-600"
              @click.stop="openThumbnailPreview(page)"
            />
            <div
              v-else
              class="flex h-10 w-16 flex-shrink-0 items-center justify-center rounded border border-gray-200 bg-gray-100 text-xs text-gray-300 dark:border-gray-600 dark:bg-gray-700"
            >
              无图
            </div>
            <div class="min-w-0 flex-1">
              <div class="truncate font-medium" :title="page.title || page.url">
                {{ page.title || '(无标题)' }}
              </div>
              <div class="truncate text-xs text-gray-400" :title="page.url">
                {{ page.url }}
              </div>
            </div>
            <NTag size="tiny" :bordered="false" round>
              深度 {{ page.depth }}
            </NTag>
          </div>
        </div>
      </div>

      <template #footer>
        <NSpace justify="end">
          <NButton @click="crawlVisible = false">关闭</NButton>
          <NButton
            v-if="crawlPages.length > 0"
            type="primary"
            :disabled="crawlSelectedUrls.length === 0"
            @click="handleApplyCrawl"
          >
            导入选中 ({{ crawlSelectedUrls.length }})
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <RecordDrawer
      v-model:show="recordDrawerVisible"
      :path-task-id="recordDrawerTaskId"
    />

    <!-- 截图预览 -->
    <NModal
      v-model:show="previewVisible"
      preset="card"
      :title="previewTitle"
      style="width: auto; max-width: 90vw"
    >
      <img
        :src="previewImage"
        alt="页面截图"
        class="max-h-[75vh] max-w-full rounded"
      />
    </NModal>
  </Page>
</template>
