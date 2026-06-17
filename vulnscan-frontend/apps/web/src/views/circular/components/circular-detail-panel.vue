<script lang="ts" setup>
import { computed, onMounted, ref } from 'vue';
import { useMessage } from 'naive-ui';
import { useRouter } from 'vue-router';
import {
  NButton,
  NCard,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NGrid,
  NGridItem,
  NSpace,
  NStep,
  NSteps,
  NTag,
  NTimeline,
  NTimelineItem,
  NTooltip,
} from 'naive-ui';

import type { DynamicFormTemplate } from '#/api/formdesign';
import {
  CircularStatusLabels,
  CircularStatusTypes,
  DataSourceLabels,
  OperationTypeLabels,
  downloadCircularIncidentReport,
  type CircularDetailResp,
  type CircularOplog,
} from '#/api/circular';
import {
  getTargetList,
  getTargetStats,
  type MonitorTarget,
  type TargetSummary,
} from '#/api/sitemonitor';
import { downloadBlob } from '#/views/asset/ledger/file-utils';
import DynamicFormRenderer from '#/components/dynamic-form/DynamicFormRenderer.vue';

import { useCircularOrganizeMaps } from '../composables/use-circular-organize';
import {
  circularDataToFormMap,
  extractCircularUnitHint,
  formatCircularTime,
  isCircularReportDownload,
  pickCircularSummary,
} from '../utils';

const message = useMessage();

function reportFormatFromPath(path: string): 'docx' | 'pdf' | null {
  if (path.endsWith('/docx')) return 'docx';
  if (path.endsWith('/pdf')) return 'pdf';
  return null;
}

async function handleReportDownload(downloadPath: unknown, label: string) {
  const path = String(downloadPath ?? '').trim();
  const format = reportFormatFromPath(path);
  if (!format) return;
  try {
    const res = await downloadCircularIncidentReport(props.detail.id, format);
    const blob = (res as any)?.data ?? res;
    const ext = format === 'docx' ? 'docx' : 'pdf';
    downloadBlob(blob as Blob, `${props.detail.code || props.detail.id}_${label}.${ext}`);
  } catch (e: any) {
    message.error(e?.message || '下载报告失败');
  }
}

const props = defineProps<{
  detail: CircularDetailResp;
  oplogs: CircularOplog[];
  template: DynamicFormTemplate | null;
}>();

const emit = defineEmits<{ back: [] }>();

const { ensureLoaded, displayOrganize } = useCircularOrganizeMaps();

const stepMap: Record<string, number> = {
  to_be_submit: 0,
  to_be_verified: 1,
  to_be_distributed: 2,
  in_progress: 3,
  to_be_processed: 3,
  to_be_reviewed: 4,
  completed: 5,
};

const router = useRouter();
const formData = computed(() => circularDataToFormMap(props.detail.circular_data));
const summaryItems = computed(() => pickCircularSummary(formData.value));
const assetUnitHint = computed(() => extractCircularUnitHint(props.detail));

const monitorTargets = ref<MonitorTarget[]>([]);
const monitorStatsMap = ref<Record<string, TargetSummary>>({});

const dimensionLabels: Record<string, string> = {
  availability: '可用性',
  tamper: '篡改',
  blacklink: '暗链',
  sensitive_word: '敏感词',
  domain_hijack: 'DNS劫持',
  sensitive_file: '敏感文件',
};

function extractCircularDomainIp(): string {
  const d = formData.value;
  const raw = d['网站域名IP'] ?? d['域名IP'] ?? d['域名'] ?? d['IP'] ?? d['隐患URL'] ?? '';
  const s = String(raw).trim();
  if (!s) return '';
  try {
    const u = new URL(s.startsWith('http') ? s : `https://${s}`);
    return u.hostname;
  } catch {
    return s.split(/[/:]/)[0] || '';
  }
}

async function fetchMonitorForCircular() {
  const keyword = extractCircularDomainIp();
  if (!keyword) return;
  try {
    const [res, stats] = await Promise.all([
      getTargetList({ target_value: keyword, page: 1, page_size: 10 }),
      getTargetStats(),
    ]);
    monitorTargets.value = res?.data ?? [];
    monitorStatsMap.value = stats ?? {};
  } catch {
    monitorTargets.value = [];
  }
}

onMounted(() => {
  void ensureLoaded();
  fetchMonitorForCircular();
});
</script>

<template>
  <div class="circular-detail">
    <NCard size="small" class="circular-detail__hero">
      <template #header>
        <NSpace align="center" :size="12" wrap>
          <NButton text @click="emit('back')">← 返回</NButton>
          <span class="circular-detail__title">{{ detail.title }}</span>
          <NTag
            :type="(CircularStatusTypes[detail.status] || 'default') as any"
            size="small"
            :bordered="false"
          >
            {{ CircularStatusLabels[detail.status] ?? detail.status }}
          </NTag>
        </NSpace>
      </template>

      <NSteps :current="stepMap[detail.status] ?? 0" size="small" class="circular-detail__steps">
        <NStep title="录入" />
        <NStep title="核验" />
        <NStep title="派发" />
        <NStep title="处置" />
        <NStep title="审核" />
        <NStep title="归档" />
      </NSteps>

      <NDescriptions label-placement="left" bordered :column="2" size="small">
        <NDescriptionsItem label="通报编号">
          <span class="mono">{{ detail.code }}</span>
        </NDescriptionsItem>
        <NDescriptionsItem label="数据来源">
          {{ DataSourceLabels[detail.source] ?? detail.source }}
        </NDescriptionsItem>
        <NDescriptionsItem label="录入组织">
          {{ displayOrganize(detail.organize) }}
        </NDescriptionsItem>
        <NDescriptionsItem label="资产隶属单位">
          {{ assetUnitHint ? displayOrganize(assetUnitHint) : '-' }}
        </NDescriptionsItem>
        <NDescriptionsItem label="处置期限">
          {{ formatCircularTime(detail.processing_deadline) }}
        </NDescriptionsItem>
        <NDescriptionsItem label="创建时间">
          {{ formatCircularTime(detail.created_at) }}
        </NDescriptionsItem>
        <NDescriptionsItem label="更新时间">
          {{ formatCircularTime(detail.updated_at) }}
        </NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard v-if="summaryItems.length" title="关键信息" size="small" class="circular-detail__section">
      <NGrid :cols="2" :x-gap="16" :y-gap="12">
        <NGridItem v-for="item in summaryItems" :key="item.key">
          <div class="summary-item">
            <div class="summary-item__label">{{ item.key }}</div>
            <div class="summary-item__value">
              <NButton
                v-if="isCircularReportDownload(item.value)"
                text
                type="primary"
                size="small"
                @click="handleReportDownload(item.value, item.key)"
              >下载 {{ item.key }}</NButton>
              <template v-else>{{ item.value }}</template>
            </div>
          </div>
        </NGridItem>
      </NGrid>
    </NCard>

    <NCard
      v-if="template"
      :title="`表单内容 · ${template.name}`"
      size="small"
      class="circular-detail__section"
    >
      <DynamicFormRenderer
        :model-value="formData"
        layout="vertical"
        readonly
        :schema="template.schema || {}"
        :options="template.options || {}"
      />
    </NCard>

    <NCard
      v-if="monitorTargets.length"
      title="站点监测关联"
      size="small"
      class="circular-detail__section"
    >
      <div
        v-for="mt in monitorTargets"
        :key="mt.id"
        class="circular-monitor-row"
      >
        <NButton
          text
          type="info"
          size="small"
          @click="router.push({ name: 'MonitorTargetDetail', params: { id: mt.id } })"
        >
          {{ mt.name || mt.target_value }}
        </NButton>
        <NTag
          :type="mt.enabled ? 'success' : 'default'"
          size="small"
        >
          {{ mt.enabled ? '启用' : '停用' }}
        </NTag>
        <template v-if="monitorStatsMap[mt.id]">
          <NTooltip
            v-for="(dim, key) in monitorStatsMap[mt.id]?.dimensions"
            :key="key"
          >
            <template #trigger>
              <NTag
                :type="dim.last_has_issue ? 'error' : 'success'"
                size="small"
                round
              >
                {{ dimensionLabels[key as string] || key }}
                <template v-if="dim.issue_count > 0">
                  · {{ dim.issue_count }}
                </template>
              </NTag>
            </template>
            执行 {{ dim.total }} 次，问题 {{ dim.issue_count }} 次，待处理 {{ dim.pending }}
          </NTooltip>
          <span
            v-if="monitorStatsMap[mt.id]!.total_issues > 0"
            class="circular-monitor-summary"
          >
            共 {{ monitorStatsMap[mt.id]!.total_issues }} 个问题
            <template v-if="monitorStatsMap[mt.id]!.pending_count > 0">
              （{{ monitorStatsMap[mt.id]!.pending_count }} 待处理）
            </template>
          </span>
        </template>
      </div>
    </NCard>

    <NCard title="操作日志" size="small" class="circular-detail__section">
      <NTimeline v-if="oplogs.length">
        <NTimelineItem
          v-for="log in oplogs"
          :key="log.id"
          :title="OperationTypeLabels[log.operation_type] ?? log.operation_type"
          :time="formatCircularTime(log.created_at || log.operation_time)"
          :type="log.operation_result === '成功' ? 'success' : 'default'"
        >
          <div v-if="log.operator || log.operator_name" class="log-meta">
            操作人：{{ log.operator_name || log.operator }}
          </div>
          <div v-if="log.target_organize" class="log-meta">
            目标单位：{{ displayOrganize(log.target_organize) }}
          </div>
        </NTimelineItem>
      </NTimeline>
      <NEmpty v-else description="暂无操作记录" />
    </NCard>
  </div>
</template>

<style scoped>
.circular-detail {
  max-width: 1080px;
  margin: 0 auto;
}

.circular-detail__hero {
  margin-bottom: 16px;
}

.circular-detail__title {
  font-size: 16px;
  font-weight: 600;
}

.circular-detail__steps {
  margin-bottom: 20px;
}

.circular-detail__section {
  margin-bottom: 16px;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
}

.summary-item__label {
  display: block;
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 4px;
}

.summary-item__value {
  font-size: 14px;
  word-break: break-all;
}

.log-meta {
  display: block;
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-top: 4px;
}

.circular-monitor-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  padding: 6px 0;
}

.circular-monitor-row + .circular-monitor-row {
  border-top: 1px solid var(--n-border-color, #eee);
}

.circular-monitor-summary {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-left: 4px;
}
</style>
