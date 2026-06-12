<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import { computed, h, onBeforeUnmount, ref, watch } from 'vue';

import {
  NAlert,
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NModal,
  NTag,
} from 'naive-ui';

import { fetchAuthImageObjectUrl } from '#/composables/useAuthImageObjectUrl';

const props = defineProps<{ result: any }>();
const r = computed(() => props.result || {});

const blacklinks = computed(() => r.value.blacklink_matches || []);
const backdoors = computed(() => r.value.backdoor_findings || []);
const hiddenIframes = computed(() => r.value.hidden_iframes || []);
const jsRedirects = computed(() => r.value.js_redirects || []);
const maliciousJS = computed(() => r.value.malicious_js || []);
const metaRedirects = computed(() => r.value.meta_redirects || []);
const cloakingFindings = computed(() => r.value.cloaking || []);

const allFindingsCount = computed(
  () =>
    blacklinks.value.length +
    backdoors.value.length +
    hiddenIframes.value.length +
    jsRedirects.value.length +
    maliciousJS.value.length +
    metaRedirects.value.length +
    cloakingFindings.value.length,
);

const annotatedScreenshotUrl = computed(
  () => r.value.tamper_screenshot_url || '',
);
const extraScreenshots = computed<
  Array<{ file_id: string; url: string; label: string; target_url: string }>
>(() => r.value.extra_screenshots || []);

const screenshotObjectUrls = ref<Record<string, string>>({});
const screenshotErrors = ref<Record<string, string>>({});
const previewVisible = ref(false);
const previewImage = ref('');
const previewTitle = ref('');

function screenshotKey(url: string, fallback = '') {
  return url || fallback;
}

function revokeScreenshot(key: string) {
  const url = screenshotObjectUrls.value[key];
  if (url) {
    URL.revokeObjectURL(url);
    delete screenshotObjectUrls.value[key];
  }
}

async function loadScreenshot(url: string, fallbackKey = '') {
  const key = screenshotKey(url, fallbackKey);
  if (!url || !key || screenshotObjectUrls.value[key]) return;
  try {
    screenshotObjectUrls.value[key] = await fetchAuthImageObjectUrl(url);
    delete screenshotErrors.value[key];
  } catch (error: any) {
    screenshotErrors.value[key] = error?.message || String(error);
  }
}

function openImage(key: string, title: string) {
  const url = screenshotObjectUrls.value[key];
  if (!url) return;
  previewImage.value = url;
  previewTitle.value = title;
  previewVisible.value = true;
}

watch(
  annotatedScreenshotUrl,
  async (url, oldUrl) => {
    if (oldUrl && oldUrl !== url) revokeScreenshot(oldUrl);
    if (url) await loadScreenshot(url);
  },
  { immediate: true },
);

watch(
  extraScreenshots,
  async (items) => {
    const activeKeys = new Set(
      items.map((item) => screenshotKey(item.url, item.file_id)),
    );
    for (const key of Object.keys(screenshotObjectUrls.value)) {
      if (key !== annotatedScreenshotUrl.value && !activeKeys.has(key)) {
        revokeScreenshot(key);
      }
    }
    await Promise.all(
      items.map((item) => loadScreenshot(item.url, item.file_id)),
    );
  },
  { immediate: true },
);

onBeforeUnmount(() => {
  Object.values(screenshotObjectUrls.value).forEach(URL.revokeObjectURL);
});

const blacklinkCols: DataTableColumns<any> = [
  {
    key: 'url',
    title: '链接地址',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render: (row) => h('span', { class: 'font-mono text-xs' }, row.url || '-'),
  },
  {
    key: 'domain',
    title: '域名',
    width: 180,
    ellipsis: { tooltip: true },
  },
  {
    key: 'hidden',
    title: '隐藏链接',
    width: 90,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        {
          type: row.hidden ? 'error' : 'default',
          size: 'small',
          bordered: false,
        },
        { default: () => (row.hidden ? '是' : '否') },
      ),
  },
  {
    key: 'pattern',
    title: '匹配规则',
    width: 160,
    ellipsis: { tooltip: true },
    render: (row) => row.pattern || '-',
  },
];

const backdoorCols: DataTableColumns<any> = [
  {
    key: 'path',
    title: '后门路径',
    width: 200,
    ellipsis: { tooltip: true },
  },
  {
    key: 'src',
    title: '资源地址',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render: (row) => h('span', { class: 'font-mono text-xs' }, row.src || '-'),
  },
  {
    key: 'context',
    title: '上下文',
    width: 120,
    render: (row) => row.context || '-',
  },
];

const sevTag = (sev: string) =>
  sev === 'critical'
    ? 'error'
    : sev === 'high'
      ? 'warning'
      : sev === 'medium'
        ? 'info'
        : 'default';

const iframeCols: DataTableColumns<any> = [
  {
    key: 'src',
    title: 'iframe 地址',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render: (row) => h('span', { class: 'font-mono text-xs' }, row.src || '-'),
  },
  { key: 'domain', title: '域名', width: 160, ellipsis: { tooltip: true } },
  {
    key: 'hidden',
    title: '隐藏',
    width: 80,
    align: 'center',
    render: (row) =>
      h(NTag, { type: row.hidden ? 'error' : 'default', size: 'small', bordered: false }, { default: () => (row.hidden ? '是' : '否') }),
  },
  {
    key: 'size',
    title: '尺寸',
    width: 120,
    render: (row) => `${row.width ?? '?'} × ${row.height ?? '?'}`,
  },
];

const jsRedirectCols: DataTableColumns<any> = [
  { key: 'type', title: '类型', width: 160 },
  {
    key: 'target',
    title: '跳转目标',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render: (row) => h('span', { class: 'font-mono text-xs' }, row.target || '-'),
  },
  { key: 'domain', title: '目标域名', width: 160, ellipsis: { tooltip: true } },
  {
    key: 'delay',
    title: '延迟(ms)',
    width: 100,
    render: (row) => (row.delay != null ? `${row.delay}ms` : '-'),
  },
  {
    key: 'severity',
    title: '严重程度',
    width: 100,
    render: (row) =>
      h(NTag, { type: sevTag(row.severity), size: 'small', bordered: false }, { default: () => row.severity || '-' }),
  },
];

const maliciousJSCols: DataTableColumns<any> = [
  { key: 'desc', title: '描述', width: 180 },
  { key: 'category', title: '分类', width: 140 },
  {
    key: 'severity',
    title: '严重程度',
    width: 100,
    render: (row) =>
      h(NTag, { type: sevTag(row.severity), size: 'small', bordered: false }, { default: () => row.severity || '-' }),
  },
  {
    key: 'src',
    title: '脚本来源',
    width: 140,
    ellipsis: { tooltip: true },
    render: (row) => row.src || '内联脚本',
  },
  {
    key: 'snippet',
    title: '代码片段',
    minWidth: 200,
    render: (row) =>
      h(
        'pre',
        {
          class: 'text-xs break-all whitespace-pre-wrap m-0',
          style: 'max-height: 80px; overflow-y: auto; font-family: monospace',
        },
        row.snippet || '-',
      ),
  },
];
</script>

<template>
  <div class="space-y-3">
    <NCard size="small" title="暗链检测结果">
      <NDescriptions :column="4" bordered size="small">
        <NDescriptionsItem label="检测结果">
          <NTag
            :type="r.has_black ? 'error' : 'success'"
            size="small"
            :bordered="false"
          >
            {{ r.has_black ? '⚠ 发现暗链/后门' : '未发现异常' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="目标URL">
          <span class="font-mono break-all text-xs">{{ r.url || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="页面链接总数">
          {{ r.total_links ?? '-' }}
        </NDescriptionsItem>
        <NDescriptionsItem label="外部链接">
          {{ r.external_links ?? '-' }}
        </NDescriptionsItem>
      </NDescriptions>
      <div v-if="allFindingsCount > 0" class="mt-3 flex flex-wrap gap-2">
        <NTag v-if="blacklinks.length > 0" type="error" size="small">
          暗链 {{ blacklinks.length }}
        </NTag>
        <NTag v-if="backdoors.length > 0" type="error" size="small">
          后门 {{ backdoors.length }}
        </NTag>
        <NTag v-if="hiddenIframes.length > 0" type="warning" size="small">
          隐藏iframe {{ hiddenIframes.length }}
        </NTag>
        <NTag v-if="jsRedirects.length > 0" type="warning" size="small">
          JS重定向 {{ jsRedirects.length }}
        </NTag>
        <NTag v-if="maliciousJS.length > 0" type="info" size="small">
          可疑JS {{ maliciousJS.length }}
        </NTag>
        <NTag v-if="metaRedirects.length > 0" type="warning" size="small">
          Meta重定向 {{ metaRedirects.length }}
        </NTag>
        <NTag v-if="cloakingFindings.length > 0" type="error" size="small">
          伪装 {{ cloakingFindings.length }}
        </NTag>
      </div>
    </NCard>

    <NCard
      v-if="blacklinks.length > 0"
      size="small"
      :title="`暗链命中（${blacklinks.length} 条）`"
    >
      <NDataTable
        :columns="blacklinkCols"
        :data="blacklinks"
        size="small"
      />
    </NCard>

    <NCard
      v-if="backdoors.length > 0"
      size="small"
      :title="`后门文件命中（${backdoors.length} 条）`"
    >
      <NDataTable
        :columns="backdoorCols"
        :data="backdoors"
        size="small"
      />
    </NCard>

    <NCard
      v-if="hiddenIframes.length > 0"
      size="small"
      :title="`隐藏 iframe（${hiddenIframes.length} 个）`"
    >
      <NDataTable
        :columns="iframeCols"
        :data="hiddenIframes"
        size="small"
      />
    </NCard>

    <NCard
      v-if="jsRedirects.length > 0"
      size="small"
      :title="`JS/页面重定向（${jsRedirects.length} 条）`"
    >
      <NDataTable
        :columns="jsRedirectCols"
        :data="jsRedirects"
        size="small"
      />
    </NCard>

    <NCard
      v-if="maliciousJS.length > 0"
      size="small"
      :title="`可疑 JS 行为（${maliciousJS.length} 条）`"
    >
      <NAlert type="info" :bordered="false" class="mb-2">
        以下为页面 JS 中检测到的可疑模式，部分可能是正常的动态加载行为，请结合上下文判断。
      </NAlert>
      <NDataTable
        :columns="maliciousJSCols"
        :data="maliciousJS"
        size="small"
      />
    </NCard>

    <NCard
      v-if="metaRedirects.length > 0"
      size="small"
      :title="`Meta 重定向（${metaRedirects.length} 条）`"
    >
      <div
        v-for="(mr, idx) in metaRedirects"
        :key="idx"
        class="mb-1 text-sm"
      >
        <NTag type="warning" size="small" :bordered="false">重定向</NTag>
        <span class="font-mono text-xs ml-2">{{ mr.url }}</span>
        <span class="text-gray-400 text-xs ml-2">延迟 {{ mr.seconds ?? 0 }}s</span>
      </div>
    </NCard>

    <NCard
      v-if="cloakingFindings.length > 0"
      size="small"
      title="伪装检测 (Cloaking)"
    >
      <NAlert type="error" :bordered="false" class="mb-2">
        检测到页面对搜索引擎爬虫展示不同内容（伪装行为），这通常是 SEO 黑帽手段。
      </NAlert>
      <div
        v-for="(cf, idx) in cloakingFindings"
        :key="idx"
        class="mb-2 text-sm"
      >
        <NTag type="error" size="small">{{ cf.bot_name }}</NTag>
        <span class="text-xs text-gray-500 ml-2">
          相似度: {{ ((cf.similarity ?? 0) * 100).toFixed(1) }}%
        </span>
        <span v-if="cf.bot_title" class="text-xs text-gray-400 ml-2">
          爬虫标题: {{ cf.bot_title }}
        </span>
      </div>
    </NCard>

    <NCard v-if="annotatedScreenshotUrl" size="small" title="页面标注截图">
      <p class="mb-2 text-xs text-gray-500">
        以下截图标注了在原始页面上发现的暗链/后门位置，红色边框标注了异常区域。
      </p>
      <NAlert
        v-if="screenshotErrors[annotatedScreenshotUrl]"
        type="warning"
        :bordered="false"
        class="mb-2"
      >
        截图引用存在，但文件下载失败：{{
          screenshotErrors[annotatedScreenshotUrl]
        }}
      </NAlert>
      <div class="rounded border border-gray-200 bg-gray-50 p-2">
        <div
          v-if="
            !screenshotObjectUrls[annotatedScreenshotUrl] &&
            !screenshotErrors[annotatedScreenshotUrl]
          "
          class="py-8 text-center text-sm text-gray-400"
        >
          正在加载截图...
        </div>
        <img
          v-else-if="screenshotObjectUrls[annotatedScreenshotUrl]"
          :src="screenshotObjectUrls[annotatedScreenshotUrl]"
          alt="页面标注截图"
          class="max-w-full cursor-pointer rounded shadow-sm transition hover:shadow-md"
          style="max-height: 600px"
          @click="openImage(annotatedScreenshotUrl, '页面标注截图')"
        />
      </div>
    </NCard>

    <NCard
      v-if="extraScreenshots.length > 0"
      size="small"
      :title="`暗链目标页面截图（${extraScreenshots.length} 张）`"
    >
      <p class="mb-2 text-xs text-gray-500">以下为暗链跳转到的目标站点截图。</p>
      <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
        <div
          v-for="(s, idx) in extraScreenshots"
          :key="idx"
          class="rounded border border-gray-200 bg-gray-50 p-2"
        >
          <div class="mb-1 text-xs font-medium text-gray-600">
            {{ s.label }}：<span class="font-mono">{{ s.target_url }}</span>
          </div>
          <img
            v-if="screenshotObjectUrls[screenshotKey(s.url, s.file_id)]"
            :src="screenshotObjectUrls[screenshotKey(s.url, s.file_id)]"
            :alt="`${s.label} - ${s.target_url}`"
            class="max-w-full cursor-pointer rounded shadow-sm transition hover:shadow-md"
            style="max-height: 400px"
            @click="
              openImage(
                screenshotKey(s.url, s.file_id),
                `${s.label} - ${s.target_url}`,
              )
            "
          />
          <NAlert
            v-else-if="screenshotErrors[screenshotKey(s.url, s.file_id)]"
            type="warning"
            :bordered="false"
          >
            截图下载失败：{{
              screenshotErrors[screenshotKey(s.url, s.file_id)]
            }}
          </NAlert>
          <div v-else class="py-8 text-center text-sm text-gray-400">
            正在加载截图...
          </div>
        </div>
      </div>
    </NCard>

    <NModal
      v-model:show="previewVisible"
      preset="card"
      :title="previewTitle || '截图预览'"
      class="blacklink-preview-modal"
      :bordered="false"
      :segmented="{ content: true }"
    >
      <div class="blacklink-preview-frame">
        <img
          v-if="previewImage"
          :src="previewImage"
          alt="截图预览"
          class="blacklink-preview-image"
        />
        <NEmpty v-else description="截图已失效，请重新打开详情" />
      </div>
    </NModal>

    <NEmpty
      v-if="!r.has_black && allFindingsCount === 0"
      description="未发现暗链或后门"
      class="py-8"
    />
  </div>
</template>

<style scoped>
.blacklink-preview-frame {
  display: flex;
  max-height: min(78vh, 900px);
  align-items: center;
  justify-content: center;
  overflow: auto;
  border-radius: 10px;
  background: var(--n-color);
}

.blacklink-preview-image {
  max-width: 100%;
  height: auto;
  border-radius: 8px;
  box-shadow: 0 12px 32px rgb(0 0 0 / 18%);
}

:global(.blacklink-preview-modal) {
  width: min(92vw, 1280px);
}
</style>
