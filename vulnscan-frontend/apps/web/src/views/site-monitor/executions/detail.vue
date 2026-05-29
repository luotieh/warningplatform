<script lang="ts" setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';
import { useTabs } from '@vben/hooks';

import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NCollapse,
  NCollapseItem,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NInput,
  NModal,
  NSpace,
  NSpin,
  NTag,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import { createIncident, type CreateIncidentReq } from '#/api/incident';
import { getExecutionDetail, getEvidenceAssetUrl } from '#/api/sitemonitor';
import { fetchAuthImageObjectUrl } from '#/composables/useAuthImageObjectUrl';

import { buildMonitorIncidentDescription } from '../monitor-incident-description';

import AvailabilityDetail from './components/AvailabilityDetail.vue';
import BlacklinkDetail from './components/BlacklinkDetail.vue';
import DomainHijackDetail from './components/DomainHijackDetail.vue';
import SensitiveFileDetail from './components/SensitiveFileDetail.vue';
import SensitiveWordDetail from './components/SensitiveWordDetail.vue';
import TamperDetail from './components/TamperDetail.vue';

defineOptions({ name: 'ExecutionDetail' });

const route = useRoute();
const router = useRouter();
const { setTabTitle, resetTabTitle } = useTabs();
const execId = route.params.id as string;
const returnTaskId = computed(() => String(route.query.taskId ?? '').trim());
const returnTaskName = computed(() =>
  String(route.query.taskName ?? '').trim(),
);
const loading = ref(false);
const detail = ref<any>(null);

const dimensionOptions: Record<string, string> = {
  availability: '可用性监测',
  blacklink: '暗链监测',
  domain_hijack: '域名劫持监测',
  sensitive_file: '敏感文件监测',
  sensitive_word: '敏感词监测',
  tamper: '篡改监测',
};

const statusTagType = (
  s: string,
): 'default' | 'error' | 'info' | 'success' | 'warning' => {
  if (s === 'success') return 'success';
  if (s === 'failed') return 'error';
  if (s === 'running') return 'warning';
  return 'info';
};

const statusLabel = (s: string) => {
  const map: Record<string, string> = {
    failed: '失败',
    pending: '等待中',
    running: '运行中',
    success: '成功',
  };
  return map[s] || s;
};

const parsedResult = computed(() => {
  if (!detail.value?.result_json) return null;
  try {
    return JSON.parse(detail.value.result_json);
  } catch {
    return null;
  }
});

async function fetchDetail() {
  loading.value = true;
  try {
    const res: any = await getExecutionDetail(execId);
    detail.value = res?.data ?? res;
  } catch (e: any) {
    message.error(e?.msg || '获取执行详情失败');
  } finally {
    loading.value = false;
  }
}

const formatTime = (t?: string) =>
  t ? dayjs(t).format('YYYY-MM-DD HH:mm:ss') : '-';

const durationSec = computed(() => {
  if (!detail.value?.started_at || !detail.value?.finished_at) return null;
  const ms = dayjs(detail.value.finished_at).diff(
    dayjs(detail.value.started_at),
  );
  return ms >= 0 ? (ms / 1000).toFixed(1) : null;
});

const convertingToIncident = ref(false);

const dimensionToIncidentType: Record<string, string> = {
  tamper: 'web_attack',
  blacklink: 'web_attack',
  sensitive_word: 'data_leak',
  sensitive_file: 'data_leak',
  domain_hijack: 'intrusion',
  availability: 'dos',
};

const dimensionToLevel: Record<string, number> = {
  tamper: 4,
  blacklink: 3,
  sensitive_word: 3,
  sensitive_file: 3,
  domain_hijack: 4,
  availability: 3,
};

async function convertToIncident() {
  if (!detail.value) return;
  const d = detail.value;
  const result = parsedResult.value;
  const dimLabel = dimensionOptions[d.dimension] || d.dimension;

  const req: CreateIncidentReq = {
    name: `[${dimLabel}] ${d.url}`,
    level: dimensionToLevel[d.dimension] ?? 3,
    source: 1,
    report_time: d.started_at || d.created_at || undefined,
    asset: {
      domain_ip: d.url,
      asset_name: d.url,
    },
    metadata: {
      incident_type: dimensionToIncidentType[d.dimension] ?? 'other',
      incident_description: buildMonitorIncidentDescription(
        d,
        result,
        formatTime,
      ),
      incident_url: d.url,
      discovery_time: d.started_at || d.created_at || undefined,
    },
  };

  convertingToIncident.value = true;
  try {
    await createIncident(req);
    message.success('已转为安全事件');
  } catch (e: any) {
    message.error(e?.msg || '转为事件失败');
  } finally {
    convertingToIncident.value = false;
  }
}

watch(
  () => detail.value?.dimension,
  (dim) => {
    if (!dim) return;
    const label = dimensionOptions[dim] || dim;
    setTabTitle(`监测详情 — ${label}`);
  },
);

function goBack() {
  if (returnTaskId.value) {
    router.push({
      path: '/monitor/targets',
      query: { taskId: returnTaskId.value },
    });
    return;
  }
  router.back();
}

const screenshotUrl = computed(() =>
  detail.value?.status === 'success'
    ? getEvidenceAssetUrl(execId, 'screenshot')
    : '',
);
const screenshotFailed = ref(false);
const screenshotObjectUrl = ref('');
const showScreenshotPreview = ref(false);

const annotatedScreenshotUrl = computed(() =>
  detail.value?.status === 'success' && detail.value?.has_issue
    ? getEvidenceAssetUrl(execId, 'annotated_screenshot')
    : '',
);
const annotatedFailed = ref(false);
const annotatedObjectUrl = ref('');
const showAnnotatedPreview = ref(false);

onMounted(() => fetchDetail());

function revokeObjectUrl(value: string) {
  if (value) URL.revokeObjectURL(value);
}

watch(screenshotUrl, async (url) => {
  revokeObjectUrl(screenshotObjectUrl.value);
  screenshotObjectUrl.value = '';
  screenshotFailed.value = false;
  if (!url) return;
  try {
    screenshotObjectUrl.value = await fetchAuthImageObjectUrl(url);
  } catch {
    screenshotFailed.value = true;
  }
});

watch(annotatedScreenshotUrl, async (url) => {
  revokeObjectUrl(annotatedObjectUrl.value);
  annotatedObjectUrl.value = '';
  annotatedFailed.value = false;
  if (!url) return;
  try {
    annotatedObjectUrl.value = await fetchAuthImageObjectUrl(url);
  } catch {
    annotatedFailed.value = true;
  }
});

onBeforeUnmount(() => {
  resetTabTitle();
  revokeObjectUrl(screenshotObjectUrl.value);
  revokeObjectUrl(annotatedObjectUrl.value);
});
</script>

<template>
  <Page
    :title="
      detail
        ? `监测详情 — ${dimensionOptions[detail.dimension] || detail.dimension}`
        : '监测详情'
    "
    :description="
      returnTaskName
        ? `任务：${returnTaskName}`
        : returnTaskId
          ? '返回监测记录列表'
          : undefined
    "
  >
    <template #extra>
      <NSpace>
        <NButton
          v-if="detail?.has_issue"
          type="warning"
          :loading="convertingToIncident"
          @click="convertToIncident"
        >
          转为安全事件
        </NButton>
        <NButton @click="goBack">
          {{ returnTaskId ? '返回监测记录' : '返回' }}
        </NButton>
      </NSpace>
    </template>

    <NSpin :show="loading">
      <template v-if="detail">
        <!-- 头部状态条 -->
        <NCard class="mb-3" size="small">
          <NSpace align="center">
            <NTag
              :type="statusTagType(detail.status)"
              size="medium"
              :bordered="false"
            >
              {{ statusLabel(detail.status) }}
            </NTag>
            <NTag
              v-if="detail.dimension"
              type="primary"
              size="medium"
              :bordered="false"
            >
              {{ dimensionOptions[detail.dimension] || detail.dimension }}
            </NTag>
            <NTag
              v-if="detail.has_issue"
              type="error"
              size="medium"
              :bordered="false"
            >
              ⚠ 发现安全问题
            </NTag>
          </NSpace>
        </NCard>

        <!-- 基本信息 -->
        <NCard title="基本信息" class="mb-3" size="small">
          <NDescriptions :column="3" bordered size="small">
            <NDescriptionsItem label="执行ID">
              <span class="font-mono text-xs">{{ detail.id }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="任务ID">
              <span class="font-mono text-xs">{{ detail.task_id }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="Agent ID">
              <span class="font-mono text-xs">{{
                detail.agent_id || '-'
              }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="目标URL" :span="3">
              <span class="font-mono text-xs break-all">{{ detail.url }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="监测维度">
              <NTag type="primary" size="small" :bordered="false">
                {{ dimensionOptions[detail.dimension] || detail.dimension }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="执行状态">
              <NTag
                :type="statusTagType(detail.status)"
                size="small"
                :bordered="false"
              >
                {{ statusLabel(detail.status) }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="耗时">
              <span class="font-mono">
                {{ durationSec == null ? '-' : `${durationSec} 秒` }}
              </span>
            </NDescriptionsItem>
            <NDescriptionsItem label="开始时间">
              {{ formatTime(detail.started_at) }}
            </NDescriptionsItem>
            <NDescriptionsItem label="结束时间">
              {{ formatTime(detail.finished_at) }}
            </NDescriptionsItem>
            <NDescriptionsItem label="创建时间">
              {{ formatTime(detail.created_at) }}
            </NDescriptionsItem>
            <NDescriptionsItem v-if="detail.error" label="执行错误" :span="3">
              <span class="text-error font-mono text-sm">{{
                detail.error
              }}</span>
            </NDescriptionsItem>
          </NDescriptions>
        </NCard>

        <!-- 维度详情 -->
        <template v-if="parsedResult">
          <AvailabilityDetail
            v-if="detail.dimension === 'availability'"
            :result="parsedResult"
            class="mb-3"
          />
          <TamperDetail
            v-else-if="detail.dimension === 'tamper'"
            :result="parsedResult"
            :execution-id="execId"
            class="mb-3"
          />
          <BlacklinkDetail
            v-else-if="detail.dimension === 'blacklink'"
            :result="parsedResult"
            class="mb-3"
          />
          <SensitiveWordDetail
            v-else-if="detail.dimension === 'sensitive_word'"
            :result="parsedResult"
            :execution-id="execId"
            class="mb-3"
          />
          <SensitiveFileDetail
            v-else-if="detail.dimension === 'sensitive_file'"
            :result="parsedResult"
            class="mb-3"
          />
          <DomainHijackDetail
            v-else-if="detail.dimension === 'domain_hijack'"
            :result="parsedResult"
            class="mb-3"
          />
        </template>

        <NCard v-else-if="detail.status === 'failed'" class="mb-3" size="small">
          <NEmpty description="执行失败，无结果数据">
            <template #extra>
              <div class="text-error mt-2 text-sm">
                {{ detail.error || '执行异常，未返回结果' }}
              </div>
            </template>
          </NEmpty>
        </NCard>

        <!-- 标注截图（发现问题时显示，红框标注问题区域） -->
        <NCard
          v-if="annotatedScreenshotUrl && !annotatedFailed"
          class="mb-3"
          size="small"
        >
          <template #header>
            <div class="flex items-center gap-2">
              <span>问题标注截图</span>
              <NTag size="tiny" type="error" :bordered="false" round
                >红框标注</NTag
              >
            </div>
          </template>
          <div
            v-if="!annotatedObjectUrl"
            class="py-8 text-center text-sm text-gray-400"
          >
            正在加载截图...
          </div>
          <img
            v-else
            :src="annotatedObjectUrl"
            alt="问题标注截图"
            class="max-w-full cursor-zoom-in rounded border-2 border-red-200"
            @click="showAnnotatedPreview = true"
          />
        </NCard>

        <!-- 页面截图 -->
        <NCard
          v-if="screenshotUrl && !screenshotFailed"
          title="页面截图"
          class="mb-3"
          size="small"
        >
          <div
            v-if="!screenshotObjectUrl"
            class="py-8 text-center text-sm text-gray-400"
          >
            正在加载截图...
          </div>
          <img
            v-else
            :src="screenshotObjectUrl"
            alt="页面截图"
            class="max-w-full cursor-zoom-in rounded border border-gray-200"
            @click="showScreenshotPreview = true"
          />
        </NCard>

        <!-- 原始 JSON -->
        <NCard v-if="detail.result_json" class="mb-3" size="small">
          <NCollapse>
            <NCollapseItem title="原始 result_json（调试用）" name="raw">
              <NInput
                type="textarea"
                :value="JSON.stringify(parsedResult, null, 2)"
                readonly
                :rows="16"
                class="font-mono"
              />
            </NCollapseItem>
          </NCollapse>
        </NCard>
      </template>
    </NSpin>

    <!-- 标注截图放大预览 -->
    <NModal
      v-model:show="showAnnotatedPreview"
      preset="card"
      title="问题标注截图"
      style="width: auto; max-width: 95vw"
    >
      <img
        :src="annotatedObjectUrl"
        alt="问题标注截图"
        class="max-h-[80vh] max-w-full rounded"
      />
    </NModal>

    <NModal
      v-model:show="showScreenshotPreview"
      preset="card"
      title="页面截图"
      style="width: auto; max-width: 95vw"
    >
      <img
        :src="screenshotObjectUrl"
        alt="页面截图"
        class="max-h-[80vh] max-w-full rounded"
      />
    </NModal>
  </Page>
</template>
