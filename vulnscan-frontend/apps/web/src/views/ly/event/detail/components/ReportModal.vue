<script lang="ts" setup>
import { computed, ref, watch } from 'vue';

import { marked } from 'marked';
import { NModal } from 'naive-ui';

import {
  deepflowGetEventDetail,
  deepflowGetEventSummary,
  deepflowRefreshEventReport,
} from '#/api/ly/deepflow';
import { message } from '#/adapter/naive';
import { useDeepflowStore } from '#/store';
import { formatDeepflowDate, mapSeverityToDisplay } from '#/utils/deepflow';
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
const chatBoxRef = ref<{ getReportMarkdown: () => string } | null>(null);
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
    detail.value = (await deepflowGetEventDetail(props.eventId)) || {};
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

// 把 LLM 自动分析总结整理成 Markdown：只取最新一轮（后端按 id 升序返回，
// 最后一轮即最新报告），避免 Word 下载把历史所有轮次的报告都渲染进去。
function formatSummary(res: any): string {
  const list = Array.isArray(res)
    ? res
    : Array.isArray(res?.data)
      ? res.data
      : [];
  if (list.length > 0) {
    const latest = list[list.length - 1] as Record<string, any>;
    const title = `第 ${latest.round_id || 1} 轮分析`;
    const time = formatDeepflowDate(latest.updated_at || latest.created_at);
    return [
      `## ${title}`,
      time ? `*${time}*` : '',
      latest.event_summary || '暂无总结内容',
    ]
      .filter(Boolean)
      .join('\n\n');
  }
  if (typeof res === 'string') return res;
  if (res?.event_summary) return String(res.event_summary);
  if (res?.data?.event_summary) return String(res.data.event_summary);
  return '';
}

// 生成并下载 LLM 告警自动分析报告 Word 文档（.doc）
async function downloadReport() {
  if (downloading.value) return;
  downloading.value = true;
  try {
    // 1) LLM 自动分析总结（真正的“告警自动分析报告”）
    let summaryMd = '';
    if (props.eventId) {
      try {
        summaryMd = formatSummary(await deepflowGetEventSummary(props.eventId));
      } catch {
        summaryMd = '';
      }
    }
    // 2) 分析过程对话（多智能体研判）
    const chatMd = chatBoxRef.value?.getReportMarkdown?.() ?? '';

    const sections = [
      summaryMd ? `# 自动分析报告\n\n${summaryMd}` : '',
      chatMd ? `# 分析过程\n\n${chatMd}` : '',
    ].filter(Boolean);

    if (sections.length === 0) {
      message.warning('暂无可下载的报告内容');
      return;
    }

    const header = `# ${eventTitle.value}\n\n${eventSource.value} · 严重程度 ${eventLevelText.value} · ${createdAtText.value}\n`;
    const fullMd = [header, ...sections].join('\n\n---\n\n');

    const safeName = String(eventTitle.value || '安全事件报告')
      .replace(/[\n\r\t\\/:*?"<>|]/g, '_')
      .slice(0, 80);

    // Markdown -> HTML，再包成 Word 可识别的 HTML 文档（application/msword）。
    // 该方案无需额外依赖、可离线，Word / WPS 均可正常打开并保留排版。
    const bodyHtml = marked.parse(fullMd, { async: false }) as string;
    const docHtml =
      '<!DOCTYPE html>' +
      '<html xmlns:o="urn:schemas-microsoft-com:office:office" ' +
      'xmlns:w="urn:schemas-microsoft-com:office:word" ' +
      'xmlns="http://www.w3.org/TR/REC-html40">' +
      '<head><meta charset="utf-8">' +
      `<title>${safeName}</title>` +
      '<style>' +
      'body{font-family:"Microsoft YaHei","PingFang SC",-apple-system,sans-serif;font-size:14px;line-height:1.7;color:#1a1a1a;}' +
      'h1{font-size:22px;font-weight:700;margin:0 0 16px;}' +
      'h2{font-size:18px;font-weight:700;margin:20px 0 10px;}' +
      'h3{font-size:15px;font-weight:600;margin:16px 0 8px;}' +
      'p,li{margin:6px 0;}' +
      'hr{border:0;border-top:1px solid #d9d9d9;margin:18px 0;}' +
      'pre,code{background:#f5f5f5;font-family:Consolas,monospace;}' +
      'pre{padding:12px;}' +
      'table{border-collapse:collapse;width:100%;}' +
      'th,td{border:1px solid #d9d9d9;padding:6px 10px;}' +
      '</style></head>' +
      `<body>${bodyHtml}</body></html>`;

    // 前置 BOM，确保中文在 Word 中不乱码
    const blob = new Blob(['﻿', docHtml], { type: 'application/msword' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${safeName}.doc`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    console.error('[report] 生成 Word 文档失败', error);
    message.error('生成报告 Word 文档失败');
  } finally {
    downloading.value = false;
  }
}

watch(
  () => props.visible,
  async (open) => {
    if (!open) {
      unbindSocket();
      return;
    }
    const token = (props.context as Record<string, any>)?.deepsoc_token;
    try {
      if (token) deepflowStore.useToken(String(token));
      else await deepflowStore.ensureToken();
    } catch (error) {
      console.error('[DeepFlow] 自动登录失败:', error);
    }
    await getDetails();
    bindSocket();
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
            aria-label="下载报告 Word 文档"
            title="下载报告 Word 文档"
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
            v-if="eventId"
            ref="chatBoxRef"
            :event-id="eventId"
            :event-context="eventContext"
          />
          <div v-else class="report-empty">暂无报告内容</div>
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
