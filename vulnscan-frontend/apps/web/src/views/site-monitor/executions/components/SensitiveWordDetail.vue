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

const annotatedScreenshotUrl = computed(
  () =>
    r.value.annotated_screenshot_url ||
    r.value.tamper_screenshot_url ||
    '',
);
const annotatedScreenshotId = computed(
  () =>
    r.value.annotated_screenshot_id ||
    r.value.tamper_screenshot_id ||
    '',
);
const hasScreenshot = computed(() =>
  Boolean(annotatedScreenshotUrl.value || annotatedScreenshotId.value),
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
    annotatedScreenshotUrl.value,
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
    screenshotError.value = `截图加载失败：${lastError || 'unknown error'}`;
  } finally {
    screenshotLoading.value = false;
  }
}

watch(
  () => [
    annotatedScreenshotUrl.value,
    annotatedScreenshotId.value,
    props.executionId,
  ],
  loadScreenshot,
  { immediate: true },
);

onBeforeUnmount(revokeScreenshotObjectUrl);

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

function matchContext(row: Record<string, any>) {
  if (row.context) return row.context;
  const list = row.contexts;
  if (Array.isArray(list) && list.length > 0) return String(list[0]);
  return '';
}

function markClassForSeverity(severity: string) {
  const s = String(severity || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'sw-hit sw-hit--high';
  if (s === 'low') return 'sw-hit sw-hit--low';
  return 'sw-hit sw-hit--medium';
}

function highlightWord(context: string, word: string, severity?: string) {
  if (!context || !word) {
    return [h('span', { class: 'text-xs text-gray-600' }, context || '-')];
  }
  const lowerCtx = context.toLowerCase();
  const lowerWord = word.toLowerCase();
  const idx = lowerCtx.indexOf(lowerWord);
  if (idx === -1) {
    return [h('span', { class: 'text-xs text-gray-600' }, context)];
  }
  const before = context.slice(0, idx);
  const match = context.slice(idx, idx + word.length);
  const after = context.slice(idx + word.length);
  return [
    h('span', { class: 'text-xs text-gray-600' }, before),
    h(
      'mark',
      { class: markClassForSeverity(severity || 'medium') },
      match,
    ),
    h('span', { class: 'text-xs text-gray-600' }, after),
  ];
}

const textLength = computed(() => {
  const v = r.value.text_length ?? r.value.preprocessing?.text_length;
  return v == null || v === '' ? '-' : String(v);
});

const matches = computed(() => r.value.matches || []);

const pageEvidenceHtml = computed(
  () => r.value.page_evidence_html || '',
);

const matchCols: DataTableColumns<any> = [
  {
    key: 'word',
    title: '敏感词',
    width: 140,
    render: (row) =>
      h('span', { class: 'font-bold text-red-500' }, row.word || '-'),
  },
  {
    key: 'category',
    title: '分类',
    width: 120,
  },
  {
    key: 'severity',
    title: '严重程度',
    width: 100,
    render: (row) =>
      h(
        NTag,
        { type: sevTag(row.severity), size: 'small', bordered: false },
        { default: () => sevLabel(row.severity) },
      ),
  },
  {
    key: 'count',
    title: '命中次数',
    width: 90,
    align: 'center',
    render: (row) =>
      h(
        'span',
        { class: 'font-mono font-bold' },
        String(row.count ?? 0),
      ),
  },
  {
    key: 'context',
    title: '上下文',
    minWidth: 260,
    render: (row) =>
      h(
        'span',
        { class: 'inline' },
        highlightWord(matchContext(row), row.word, row.severity),
      ),
  },
];
</script>

<template>
  <div class="space-y-3">
    <NCard size="small" title="敏感词检测结果">
      <NDescriptions :column="4" bordered size="small">
        <NDescriptionsItem label="检测结果">
          <NTag
            :type="r.has_hit ? 'error' : 'success'"
            size="small"
            :bordered="false"
          >
            {{ r.has_hit ? '⚠ 发现敏感词' : '未发现敏感词' }}
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="目标URL">
          <span class="font-mono break-all text-xs">{{ r.url || '-' }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="命中敏感词">
          <span class="font-mono font-bold">
            {{ matches.length }} 个
          </span>
        </NDescriptionsItem>
        <NDescriptionsItem label="总命中次数">
          <span class="font-mono">{{ r.total_matches ?? 0 }} 次</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="页面文本长度">
          {{ textLength }} 字符
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard v-if="hasScreenshot" size="small" title="敏感词标注截图">
      <p class="mb-2 text-xs text-gray-500">
        以下截图为检测到敏感词时自动抓取，红色边框标注了命中敏感词的位置。
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
          alt="敏感词标注截图"
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
      title="敏感词标注截图预览"
      class="sw-preview-modal"
      :bordered="false"
      :segmented="{ content: true }"
    >
      <div class="sw-preview-frame">
        <img
          v-if="screenshotObjectUrl"
          :src="screenshotObjectUrl"
          alt="敏感词标注截图预览"
          class="sw-preview-image"
        />
        <NEmpty v-else description="截图已失效，请重新打开详情" />
      </div>
    </NModal>

    <NCard
      v-if="pageEvidenceHtml"
      size="small"
      title="页面全文证据（可滚动）"
    >
      <p class="mb-2 text-xs text-gray-500">
        展示监测抓取的全文，所有命中词已按严重程度分色高亮（红/橙/蓝）。
      </p>
      <div
        class="sw-evidence-scroll sw-evidence rounded border border-gray-200 bg-gray-50 p-3 text-sm leading-relaxed text-gray-800"
        v-html="pageEvidenceHtml"
      />
    </NCard>

    <NCard
      v-if="matches.length > 0"
      size="small"
      :title="`命中详情（${matches.length} 项）`"
    >
      <NDataTable
        :columns="matchCols"
        :data="matches"
        size="small"
        :max-height="400"
      />
    </NCard>

    <NEmpty
      v-if="!r.has_hit && matches.length === 0"
      description="未检测到敏感词"
      class="py-8"
    />
  </div>
</template>

<style scoped>
.sw-evidence-scroll {
  max-height: min(70vh, 560px);
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
}

:deep(.sw-hit) {
  padding: 0 2px;
  border-radius: 2px;
  font-weight: 600;
}

.sw-evidence :deep(.sw-hit--high) {
  background: #fee2e2;
  color: #dc2626;
}

.sw-evidence :deep(.sw-hit--medium) {
  background: #ffedd5;
  color: #ea580c;
}

.sw-evidence :deep(.sw-hit--low) {
  background: #dbeafe;
  color: #2563eb;
}

.sw-preview-frame {
  display: flex;
  max-height: min(78vh, 900px);
  align-items: center;
  justify-content: center;
  overflow: auto;
  border-radius: 10px;
  background: var(--n-color);
}

.sw-preview-image {
  max-width: 100%;
  height: auto;
  border-radius: 8px;
  box-shadow: 0 12px 32px rgb(0 0 0 / 18%);
}

:global(.sw-preview-modal) {
  width: min(92vw, 1280px);
}
</style>
