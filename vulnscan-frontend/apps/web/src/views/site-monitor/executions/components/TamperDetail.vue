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

import { getEvidenceAssetUrl } from '#/api/sitemonitor';
import { fetchAuthImageObjectUrl } from '#/composables/useAuthImageObjectUrl';

const props = defineProps<{ executionId?: string; result: any }>();

const r = computed(() => props.result || {});
const diffs = computed(() => r.value.diffs || r.value.diff?.diffs || []);
const baselineUpdate = computed(() => r.value.baseline_update || null);
const isFirstRun = computed(
  () =>
    r.value.is_first_run === true || baselineUpdate.value?.action === 'init',
);

const evidence = computed(() => r.value.evidence || null);

const tamperScreenshotUrl = computed(() => r.value.tamper_screenshot_url || '');
const tamperScreenshotId = computed(() => r.value.tamper_screenshot_id || '');
const hasScreenshotEvidence = computed(() =>
  Boolean(tamperScreenshotUrl.value || tamperScreenshotId.value),
);
const screenshotObjectUrl = ref('');
const screenshotLoading = ref(false);
const screenshotError = ref('');
const previewVisible = ref(false);

function revokeScreenshotObjectUrl() {
  if (screenshotObjectUrl.value) {
    URL.revokeObjectURL(screenshotObjectUrl.value);
    screenshotObjectUrl.value = '';
  }
}

function openScreenshot() {
  if (screenshotObjectUrl.value) {
    previewVisible.value = true;
  }
}

async function loadScreenshot() {
  revokeScreenshotObjectUrl();
  screenshotError.value = '';

  const urls = [
    props.executionId
      ? getEvidenceAssetUrl(props.executionId, 'annotated_screenshot')
      : '',
    tamperScreenshotUrl.value,
  ].filter(Boolean);

  if (urls.length === 0) return;

  screenshotLoading.value = true;
  try {
    let lastError = '';
    for (const url of urls) {
      try {
        screenshotObjectUrl.value = await fetchAuthImageObjectUrl(url);
        return;
      } catch (error: any) {
        lastError = error?.message || String(error);
      }
    }
    screenshotError.value = `截图引用存在，但文件下载失败：${lastError || 'unknown error'}`;
  } finally {
    screenshotLoading.value = false;
  }
}

watch(
  () => [
    tamperScreenshotUrl.value,
    tamperScreenshotId.value,
    props.executionId,
  ],
  loadScreenshot,
  { immediate: true },
);

onBeforeUnmount(revokeScreenshotObjectUrl);

const showCompareEvidence = computed(() => {
  const ev = evidence.value;
  if (!ev) return false;
  return Boolean(ev.baseline_html || ev.current_html);
});

type TagType = 'default' | 'error' | 'info' | 'primary' | 'success' | 'warning';

function sevTag(s: string): TagType {
  const m: Record<string, TagType> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'info',
  };
  return m[s] || 'info';
}

function sevLabel(s: string) {
  const m: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
  };
  return m[s] || s || '-';
}

function diffTypeLabel(t: string) {
  const m: Record<string, string> = {
    content_hash: '内容Hash变化',
    title: '标题变化',
    status_code: 'HTTP状态码变化',
    text_length: '文本长度异常',
    injected_elements: '注入元素',
  };
  return m[t] || t;
}

const diffCols: DataTableColumns<any> = [
  {
    key: 'type',
    title: '变化类型',
    width: 160,
    render: (row) => diffTypeLabel(row.type),
  },
  {
    key: 'baseline',
    title: '基线值',
    minWidth: 160,
    ellipsis: { tooltip: true },
    render: (row) => {
      if (row.type === 'injected_elements') return '-';
      return String(row.baseline ?? '-');
    },
  },
  {
    key: 'current',
    title: '当前值',
    minWidth: 160,
    ellipsis: { tooltip: true },
    render: (row) => {
      if (row.type === 'injected_elements')
        return `${(row.elements || []).length} 个可疑元素`;
      return String(row.current ?? '-');
    },
  },
  {
    key: 'severity',
    title: '严重程度',
    width: 100,
    render: (row) => {
      if (row.type === 'injected_elements')
        return h(
          NTag,
          { type: 'error', size: 'small', bordered: false },
          { default: () => '严重' },
        );
      if (row.ratio != null && row.ratio > 0.5)
        return h(
          NTag,
          { type: 'error', size: 'small', bordered: false },
          { default: () => '高危' },
        );
      return h(
        NTag,
        { type: 'warning', size: 'small', bordered: false },
        { default: () => '中危' },
      );
    },
  },
];

const injectedElements = computed(() => {
  const inj = diffs.value.find((d: any) => d.type === 'injected_elements');
  return inj?.elements || [];
});

const injectedCols: DataTableColumns<any> = [
  { key: 'type', title: '类型', width: 120 },
  {
    key: 'src',
    title: '资源地址',
    minWidth: 280,
    ellipsis: { tooltip: true },
    render: (row) => h('span', { class: 'font-mono text-xs' }, row.src || '-'),
  },
  {
    key: 'domain',
    title: '域名',
    width: 180,
    ellipsis: { tooltip: true },
  },
];
</script>

<template>
  <div class="space-y-3">
    <NCard size="small" title="篡改检测结果">
      <NDescriptions :column="4" bordered size="small">
        <NDescriptionsItem label="是否篡改">
          <NTag
            :type="r.tampered ? 'error' : 'success'"
            size="small"
            :bordered="false"
          >
            {{ r.tampered ? '⚠ 检测到篡改' : '未检测到篡改' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem v-if="r.severity" label="严重程度">
          <NTag :type="sevTag(r.severity)" size="small" :bordered="false">
            {{ sevLabel(r.severity) }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="HTTP状态">
          <span class="font-mono">{{ r.status_code ?? '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="页面标题">
          {{ r.title || '-' }}
        </NDescriptionsItem>
        <NDescriptionsItem label="目标URL" :span="4">
          <span class="font-mono break-all text-xs">{{ r.url || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="内容Hash">
          <span class="font-mono text-xs">{{ r.content_hash || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="文本长度">
          {{ r.visible_text_length ?? '-' }} 字符
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard v-if="hasScreenshotEvidence" size="small" title="篡改截图证据">
      <p class="mb-2 text-xs text-gray-500">
        以下截图为检测到篡改时自动抓取，红色边框标注了发生变化的区域。
      </p>
      <NAlert
        v-if="screenshotError"
        type="warning"
        :bordered="false"
        class="mb-2"
      >
        {{ screenshotError }}
      </NAlert>
      <div class="rounded border border-gray-200 bg-gray-50 p-2">
        <div
          v-if="screenshotLoading"
          class="py-8 text-center text-sm text-gray-400"
        >
          正在加载截图...
        </div>
        <img
          v-else-if="screenshotObjectUrl"
          :src="screenshotObjectUrl"
          alt="篡改截图"
          class="max-w-full cursor-pointer rounded shadow-sm transition hover:shadow-md"
          style="max-height: 600px"
          @click="openScreenshot"
        />
        <NEmpty v-else description="暂无可展示截图" />
      </div>
    </NCard>

    <NModal
      v-model:show="previewVisible"
      preset="card"
      title="篡改截图预览"
      class="tamper-preview-modal"
      :bordered="false"
      :segmented="{ content: true }"
    >
      <div class="tamper-preview-frame">
        <img
          v-if="screenshotObjectUrl"
          :src="screenshotObjectUrl"
          alt="篡改截图预览"
          class="tamper-preview-image"
        />
        <NEmpty v-else description="截图已失效，请重新打开详情" />
      </div>
    </NModal>

    <NCard
      v-if="showCompareEvidence"
      size="small"
      :title="isFirstRun ? '基线内容（首次建立）' : '篡改对比证据'"
    >
      <p v-if="!isFirstRun" class="mb-2 text-xs text-gray-500">
        左侧为上一次基线内容（<span class="text-red-600">删除</span>
        标记为本次移除部分）； 右侧为本次抓取内容（<span class="text-green-600"
          >新增</span
        >
        标记为本次新增部分）。
      </p>
      <p v-else class="mb-2 text-xs text-gray-500">
        首次运行已保存以下全文作为后续篡改对比基线。
      </p>
      <p v-if="evidence?.truncated" class="mb-2 text-xs text-amber-600">
        内容较长，展示已截断。
      </p>
      <div
        class="grid gap-3"
        :class="isFirstRun ? 'grid-cols-1' : 'grid-cols-1 lg:grid-cols-2'"
      >
        <div v-if="!isFirstRun || evidence?.baseline_html">
          <div class="mb-1 text-xs font-medium text-gray-600">
            {{ isFirstRun ? '基线全文' : '上一次（基线）' }}
          </div>
          <div
            class="tp-evidence-scroll tp-evidence rounded border border-gray-200 bg-gray-50 p-3 text-sm leading-relaxed text-gray-800"
            v-html="evidence?.baseline_html || ''"
          />
        </div>
        <div v-if="!isFirstRun">
          <div class="mb-1 text-xs font-medium text-gray-600">
            这一次（当前）
          </div>
          <div
            class="tp-evidence-scroll tp-evidence rounded border border-gray-200 bg-gray-50 p-3 text-sm leading-relaxed text-gray-800"
            v-html="evidence?.current_html || ''"
          />
        </div>
      </div>
    </NCard>

    <NCard
      v-if="isFirstRun && !showCompareEvidence"
      size="small"
      title="首次运行"
    >
      <div class="text-sm text-gray-500">
        首次运行，已建立基线。后续监测将以此为基准进行对比。
      </div>
      <NDescriptions
        v-if="baselineUpdate"
        :column="2"
        bordered
        size="small"
        class="mt-2"
      >
        <NDescriptionsItem label="基线Hash">
          <span class="font-mono text-xs">
            {{ baselineUpdate.content_hash || '-' }}
          </span>
        </NDescriptionsItem>
        <NDescriptionsItem label="基线标题">
          {{ baselineUpdate.title || '-' }}
        </NDescriptionsItem>
        <NDescriptionsItem label="基线状态码">
          {{ baselineUpdate.status_code ?? '-' }}
        </NDescriptionsItem>
        <NDescriptionsItem label="基线文本长度">
          {{ baselineUpdate.visible_text_length ?? '-' }} 字符
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard
      v-if="diffs.length > 0"
      size="small"
      :title="`变化详情（${diffs.length} 项）`"
    >
      <NDataTable
        :columns="diffCols"
        :data="diffs"
        size="small"
        :max-height="300"
      />
    </NCard>

    <NCard
      v-if="injectedElements.length > 0"
      size="small"
      :title="`可疑注入元素（${injectedElements.length} 项）`"
    >
      <NDataTable
        :columns="injectedCols"
        :data="injectedElements"
        size="small"
        :max-height="300"
      />
    </NCard>

    <NEmpty
      v-if="!r.tampered && !isFirstRun && diffs.length === 0"
      description="未检测到篡改"
      class="py-8"
    />
  </div>
</template>

<style scoped>
.tp-evidence-scroll {
  max-height: min(50vh, 400px);
  overflow-y: auto;
  overflow-x: hidden;
  white-space: pre-wrap;
  word-break: break-word;
}

.tp-evidence :deep(.tp-del) {
  background: #fee2e2;
  color: #b91c1c;
  text-decoration: line-through;
}

.tp-evidence :deep(.tp-ins) {
  background: #dcfce7;
  color: #15803d;
  font-weight: 600;
}

.tamper-preview-frame {
  display: flex;
  max-height: min(78vh, 900px);
  align-items: center;
  justify-content: center;
  overflow: auto;
  border-radius: 10px;
  background: var(--n-color);
}

.tamper-preview-image {
  max-width: 100%;
  height: auto;
  border-radius: 8px;
  box-shadow: 0 12px 32px rgb(0 0 0 / 18%);
}

:global(.tamper-preview-modal) {
  width: min(92vw, 1280px);
}
</style>
