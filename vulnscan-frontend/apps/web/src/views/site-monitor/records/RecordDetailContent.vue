<script lang="ts" setup>
import { computed, ref, watch } from 'vue';

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
  NSpace,
  NSpin,
  NTag,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import { getExecutionDetail } from '#/api/sitemonitor';
import { createIncident, type CreateIncidentReq } from '#/api/incident';

import { buildMonitorIncidentDescription } from '../monitor-incident-description';

import AvailabilityDetail from '../executions/components/AvailabilityDetail.vue';
import BlacklinkDetail from '../executions/components/BlacklinkDetail.vue';
import DomainHijackDetail from '../executions/components/DomainHijackDetail.vue';
import SensitiveFileDetail from '../executions/components/SensitiveFileDetail.vue';
import SensitiveWordDetail from '../executions/components/SensitiveWordDetail.vue';
import TamperDetail from '../executions/components/TamperDetail.vue';

const props = defineProps<{
  recordId: string;
}>();

const emit = defineEmits<{
  close: [];
}>();

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

const titleText = computed(() => {
  if (!detail.value) return '监测记录详情';
  return `监测记录 — ${dimensionOptions[detail.value.dimension] || detail.value.dimension}`;
});

async function fetchDetail() {
  if (!props.recordId) return;
  loading.value = true;
  try {
    const res: any = await getExecutionDetail(props.recordId);
    detail.value = res?.data ?? res;
  } catch (e: any) {
    message.error(e?.msg || '获取监测记录详情失败');
  } finally {
    loading.value = false;
  }
}

const formatTime = (t: string) =>
  t ? dayjs(t).format('YYYY-MM-DD HH:mm:ss') : '-';

const durationSec = computed(() => {
  if (!detail.value?.started_at || !detail.value?.finished_at) return null;
  const ms = dayjs(detail.value.finished_at).diff(dayjs(detail.value.started_at));
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
  const req: CreateIncidentReq = {
    name: `[${dimensionOptions[d.dimension] || d.dimension}] ${d.url}`,
    level: dimensionToLevel[d.dimension] ?? 3,
    source: 1,
    report_time: d.started_at || d.created_at || undefined,
    asset: { domain_ip: d.url, asset_name: d.url },
    metadata: {
      incident_type: dimensionToIncidentType[d.dimension] ?? 'other',
      incident_description: buildMonitorIncidentDescription(d, parsedResult.value, formatTime),
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
  () => props.recordId,
  (id) => {
    if (id) fetchDetail();
    else detail.value = null;
  },
  { immediate: true },
);
</script>

<template>
  <div class="record-detail-content">
    <div class="detail-toolbar">
      <span class="detail-title">{{ titleText }}</span>
      <NSpace>
        <NButton
          v-if="detail?.has_issue"
          type="warning"
          size="small"
          :loading="convertingToIncident"
          @click="convertToIncident"
        >
          转为安全事件
        </NButton>
        <NButton size="small" @click="emit('close')">关闭</NButton>
      </NSpace>
    </div>

    <NSpin :show="loading">
      <template v-if="detail">
        <NCard class="mb-3" size="small">
          <NSpace align="center">
            <NTag :type="statusTagType(detail.status)" size="medium" :bordered="false">
              {{ statusLabel(detail.status) }}
            </NTag>
            <NTag v-if="detail.dimension" size="medium" :bordered="false">
              {{ dimensionOptions[detail.dimension] || detail.dimension }}
            </NTag>
            <NTag v-if="detail.has_issue" type="error" size="medium" :bordered="false">
              发现安全问题
            </NTag>
          </NSpace>
        </NCard>

        <NCard title="记录信息" class="mb-3" size="small">
          <NDescriptions :column="2" bordered size="small">
            <NDescriptionsItem label="记录ID">
              <span class="font-mono text-xs">{{ detail.id }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="路径任务">
              <span class="font-mono text-xs">{{ detail.path_task_id || detail.task_id || '-' }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="目标URL" :span="2">
              <span class="font-mono text-xs break-all">{{ detail.url }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="开始时间">
              {{ formatTime(detail.started_at) }}
            </NDescriptionsItem>
            <NDescriptionsItem label="结束时间">
              {{ formatTime(detail.finished_at) }}
            </NDescriptionsItem>
            <NDescriptionsItem v-if="detail.error" label="错误信息" :span="2">
              <span class="text-error text-sm">{{ detail.error }}</span>
            </NDescriptionsItem>
          </NDescriptions>
        </NCard>

        <template v-if="parsedResult">
          <AvailabilityDetail
            v-if="detail.dimension === 'availability'"
            :result="parsedResult"
            class="mb-3"
          />
          <TamperDetail
            v-else-if="detail.dimension === 'tamper'"
            :result="parsedResult"
            :execution-id="recordId"
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
            :execution-id="recordId"
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
          <NEmpty description="监测失败，无结果数据" />
        </NCard>

        <NCard v-if="detail.result_json" size="small">
          <NCollapse>
            <NCollapseItem title="原始 JSON（调试）" name="raw">
              <NInput
                type="textarea"
                :value="JSON.stringify(parsedResult, null, 2)"
                readonly
                :rows="12"
                class="font-mono"
              />
            </NCollapseItem>
          </NCollapse>
        </NCard>
      </template>
    </NSpin>
  </div>
</template>

<style scoped>
.record-detail-content {
  max-height: calc(88vh - 80px);
  overflow-y: auto;
  padding-right: 4px;
}

.detail-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--n-border-color);
}

.detail-title {
  font-size: 16px;
  font-weight: 600;
}
</style>
