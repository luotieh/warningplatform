<script lang="ts" setup>
import { computed, ref, watch } from 'vue';

import { NModal } from 'naive-ui';

import {
  deepflowGetEventDetail,
  deepflowExportEvidenceReport,
  deepflowRefreshEventReport,
} from '#/api/ly/deepflow';
import { message } from '#/adapter/naive';
import { useDeepflowStore } from '#/store';
import { mapSeverityToDisplay } from '#/utils/deepflow';
import { eventTimestampMs, formatTimestamp } from '#/utils/ly';
import deepflowSocket from '#/utils/deepflow-socket';

import ChatBox from './ChatBox.vue';

defineOptions({ name: 'LyReportModal' });

const props = withDefaults(
  defineProps<{
    context?: Record<string, any>;
    eventId?: string;
    visible?: boolean;
  }>(),
  { context: () => ({}), eventId: '', visible: false },
);

const emit = defineEmits<{
  (e: 'update:visible', value: boolean): void;
}>();

const show = computed({
  get: () => props.visible,
  set: (value: boolean) => emit('update:visible', value),
});

const deepflowStore = useDeepflowStore();
const detail = ref<Record<string, any>>({});
const downloading = ref(false);
const refreshing = ref(false);
const analysisVersion = ref(0);
const wsConnectionStatus = ref<'connected' | 'connecting' | 'disconnected'>(
  'disconnected',
);

const ctx = computed(() => props.context ?? {});

const severityText = computed(() => mapSeverityToDisplay(detail.value?.severity));
const activityContext = computed(() => {
  try { return JSON.parse(detail.value?.context || '{}'); } catch { return {}; }
});
const createdAtText = computed(() => formatTimestamp(activityContext.value.first_time || activityContext.value.occurrence_time || ctx.value.occurrence_time || detail.value?.created_at));
const lastActivity = computed(() => activityContext.value.last_time || activityContext.value.occurrence_time || detail.value?.last_seen_at || ctx.value.last_time);
const isConverged = computed(() => Boolean(detail.value?.aggregation_closed || detail.value?.archive_date || ctx.value.is_final) || Date.now() - eventTimestampMs(lastActivity.value) >= 30 * 60 * 1000);
const lifecycleText = computed(() => `${isConverged.value ? '收敛时间' : '最近活动'}：${formatTimestamp(lastActivity.value)}（北京时间）`);
const eventTitle = computed(() => {
  const type = String(
    ctx.value.event_type_name ||
      ctx.value.event_type ||
      detail.value?.event_type ||
      detail.value?.event_name ||
      '安全事件',
  );
  const source = String(ctx.value.threat_source || detail.value?.threat_source || '');
  if (source) return `发现与${source}的通讯行为 (${type})`;
  return detail.value?.event_name || type;
});
const eventSource = computed(() => {
  const raw = String(detail.value?.source || ctx.value.source || '').trim();
  if (!raw || /^flow\s*shadow$/i.test(raw)) return 'ta_node';
  return raw;
});
const eventLevelText = computed(() =>
  String(ctx.value.event_level || severityText.value || '-'),
);

const eventContext = computed(() => ({
  event_level: eventLevelText.value,
  event_type:
    ctx.value.event_type_name ||
    ctx.value.event_type ||
    detail.value?.event_name ||
    '安全事件',
  occurrence_time: createdAtText.value,
  rule_desc: ctx.value.rule_desc || detail.value?.message || '',
  threat_source: ctx.value.threat_source || detail.value?.threat_source || '',
  victim_target: ctx.value.victim_target || detail.value?.victim_target || '',
  // 命中频次/聚合信息：供研判分析参考（是否在某段时间内多次命中）
  hit_frequency: ctx.value.hit_frequency || '单次',
  hit_count: ctx.value.hit_count || 1,
  first_time: createdAtText.value,
  last_time: formatTimestamp(lastActivity.value),
  // 收敛状态：closed 表示已收敛、hit_count 为最终频次；active 表示可能继续
  aggregation_status: isConverged.value ? 'closed' : 'active',
  is_final: isConverged.value,
}));

function updateWSStatus(status: 'connected' | 'connecting' | 'disconnected') {
  wsConnectionStatus.value = status;
}

function syncSocketStatus() {
  if (deepflowSocket.status === 'connected' || deepflowSocket.connected) {
    updateWSStatus('connected');
  } else if (deepflowSocket.status === 'connecting') {
    updateWSStatus('connecting');
  } else {
    updateWSStatus('disconnected');
  }
}

function handleSocketConnected() {
  updateWSStatus('connected');
}
function handleSocketDisconnected() {
  updateWSStatus('disconnected');
}
function handleSocketError() {
  updateWSStatus('disconnected');
}

async function getDetails() {
  if (!props.eventId) {
    detail.value = {};
    return;
  }
  try {
    const eventId = props.eventId;
    const response = await deepflowGetEventDetail(eventId);
    if (eventId === props.eventId && props.visible) detail.value = response || {};
  } catch (error) {
    message.error(
      error instanceof Error ? error.message : '获取事件详情失败，请检查后端服务',
    );
  }
}

async function refreshReport() {
  if (refreshing.value || !props.eventId) return;
  refreshing.value = true;
  try {
    const res = await deepflowRefreshEventReport(props.eventId);
    analysisVersion.value = Number(res?.analysis_version || 0);
    message.success(
      res?.status === 'already_running'
        ? '该事件正在分析中，请稍后查看'
        : '分析刷新任务已提交，完成后自动更新',
    );
    await getDetails();
  } catch (error) {
    message.error(
      error instanceof Error ? error.message : '刷新分析失败，请稍后重试',
    );
  } finally {
    refreshing.value = false;
  }
}

function bindSocket() {
  deepflowSocket.on('connected', handleSocketConnected);
  deepflowSocket.on('disconnected', handleSocketDisconnected);
  deepflowSocket.on('error', handleSocketError);
  syncSocketStatus();
  deepflowSocket.connect();
  syncSocketStatus();
}

function unbindSocket() {
  deepflowSocket.off('connected', handleSocketConnected);
  deepflowSocket.off('disconnected', handleSocketDisconnected);
  deepflowSocket.off('error', handleSocketError);
}

function close() {
  show.value = false;
}

// Resolve the latest saved report on the server at download time.
async function downloadReport() {
  if (downloading.value || !props.eventId) return;
  downloading.value = true;
  const eventId = props.eventId;
  const title = eventTitle.value;
  try {
    const blob = await deepflowExportEvidenceReport(eventId);
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${title.replace(/[\n\r\t\\/:*?"<>|]/g, '_').slice(0, 80)}.docx`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    message.error(error instanceof Error ? error.message : '报告DOCX导出失败');
  } finally {
    downloading.value = false;
  }
}
watch(
  () => [props.visible, props.eventId] as const,
  async ([open, eventId]) => {
    detail.value = {};
    unbindSocket();
    if (!open) {
      return;
    }
    try {
      // Refresh the auxiliary DeepSOC session on every open. Tokens are held
      // in backend memory and may be invalid after a local service restart;
      // reusing a stale token from the event context causes a 401 report call.
      deepflowStore.clearUser();
      await deepflowStore.ensureToken();
    } catch (error) {
      console.error('[DeepFlow] 自动登录失败:', error);
    }
    if (!props.visible || eventId !== props.eventId) return;
    await getDetails();
    if (!props.visible || eventId !== props.eventId) return;
    if (props.visible && eventId === props.eventId) bindSocket();
  },
);
</script>

<template>
  <NModal
    v-model:show="show"
    :auto-focus="false"
    :mask-closable="true"
    transform-origin="center"
  >
    <div class="report-modal">
      <header class="report-header">
        <div class="report-title-wrap">
          <div class="report-title-text">
            <h2 class="report-title">{{ eventTitle }}</h2>
            <div class="report-sub">
              {{ eventSource }} · 严重程度 {{ eventLevelText }} ·
              发生：{{ createdAtText }}（北京时间） · {{ lifecycleText }}
            </div>
          </div>
        </div>
        <div class="report-header-right">
          <button
            class="report-icon-btn"
            type="button"
            :disabled="refreshing || !eventId"
            aria-label="手动刷新分析"
            title="手动刷新分析"
            @click="refreshReport"
          >
            <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
              <path
                d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
          </button>
          <button
            class="report-icon-btn"
            type="button"
            :disabled="downloading"
            aria-label="下载最新版报告 Word 文档"
            title="下载最新版报告 Word 文档"
            @click="downloadReport"
          >
            <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
              <path
                d="M12 3v11m0 0l-4-4m4 4l4-4M5 19h14"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
          </button>
          <button class="report-icon-btn" type="button" aria-label="关闭" @click="close">
            <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
              <path
                d="M6 6l12 12M18 6L6 18"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
              />
            </svg>
          </button>
        </div>
      </header>

      <div class="report-body">
        <div class="report-chat">
          <ChatBox
            v-if="eventId && deepflowStore.accessToken"
            :event-id="eventId"
            :event-context="eventContext"
          />
          <div v-else class="report-empty">正在加载对话…</div>
        </div>
      </div>
    </div>
  </NModal>
</template>

<style scoped>
.report-modal {
  display: flex;
  flex-direction: column;
  width: min(1320px, 96vw);
  height: min(960px, 94vh);
  overflow: hidden;
  background: hsl(var(--card));
  color: hsl(var(--foreground));
  border: 1px solid hsl(var(--border));
  border-radius: 14px;
  box-shadow: 0 24px 60px hsl(var(--foreground) / 18%);
}

.report-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 18px 18px 16px;
  border-bottom: 1px solid hsl(var(--border));
}

.report-title-wrap {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  min-width: 0;
}

.report-title-text {
  min-width: 0;
}

.report-title {
  margin: 0;
  font-size: 20px;
  font-weight: 700;
  line-height: 1.4;
  color: hsl(var(--card-foreground));
  word-break: break-word;
}

.report-sub {
  margin-top: 8px;
  overflow: hidden;
  font-size: 13px;
  color: hsl(var(--muted-foreground));
  text-overflow: ellipsis;
  white-space: nowrap;
}

.report-header-right {
  display: flex;
  flex: 0 0 auto;
  align-items: center;
  gap: 10px;
}

.report-icon-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  color: hsl(var(--muted-foreground));
  cursor: pointer;
  background: transparent;
  border: 0;
  border-radius: 8px;
  transition: background-color 0.15s, color 0.15s;
}
.report-icon-btn:hover:not(:disabled) {
  color: hsl(var(--foreground));
  background: hsl(var(--accent));
}
.report-icon-btn:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.report-body {
  flex: 1;
  min-height: 0;
  padding: 12px;
  background: hsl(var(--background));
}
.report-chat {
  width: 100%;
  max-width: 1100px;
  height: 100%;
  margin: 0 auto;
  overflow: hidden;
  border: 1px solid hsl(var(--border));
  border-radius: 12px;
}
.report-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  font-size: 14px;
  color: hsl(var(--muted-foreground));
}

@media (max-width: 768px) {
  .report-modal {
    width: 96vw;
    height: 90vh;
  }
  .report-title {
    white-space: normal;
  }
}
</style>
