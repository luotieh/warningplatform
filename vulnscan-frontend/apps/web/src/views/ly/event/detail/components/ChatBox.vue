<script lang="ts" setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';

import { marked } from 'marked';
import { NAlert, NButton, NInput, NScrollbar, NSpin } from 'naive-ui';

import {
  deepflowAskAI,
  deepflowEstimateAI,
  deepflowGetChatRecords,
} from '#/api/ly/deepflow';
import { message } from '#/adapter/naive';
import { getMessageDisplay, normalizeDeepflowMessage } from '#/utils/deepflow';
import { formatTimestamp } from '#/utils/ly';
import deepflowSocket from '#/utils/deepflow-socket';
import { estimateWait, loadDurations, saveDuration, waitText } from './generation-wait';

interface ChatMessage extends Record<string, any> {
  created_at?: string;
  id?: number | string | null;
  message_content?: Record<string, any>;
  message_from?: string;
  message_id?: number | string | null;
  pending?: boolean;
  temp_id?: string | null;
}

const props = defineProps<{
  eventId: string;
  eventContext?: Record<string, any>;
}>();

const loading = ref(false);
const sendError = ref('');
const messageInput = ref('');
const messageRecord = ref<ChatMessage[]>([]);
const chatRef = ref<InstanceType<typeof NScrollbar> | null>(null);
const lastMessageDbId = ref(0);
const aiThinkingId = ref('');
const elapsedSeconds = ref(0);
const generationEstimate = ref(estimateWait([]));
const generationStatus = computed(() => waitText(elapsedSeconds.value, generationEstimate.value));
let waitTimer: ReturnType<typeof setInterval> | undefined;
let requestTimer: ReturnType<typeof setTimeout> | undefined;
let requestController: AbortController | undefined;
let requestGeneration = 0;

function stopWaiting() {
  if (waitTimer) clearInterval(waitTimer);
  if (requestTimer) clearTimeout(requestTimer);
  waitTimer = undefined;
  requestTimer = undefined;
}

function cancelPendingRequest() {
  requestGeneration++;
  requestController?.abort();
  requestController = undefined;
  stopWaiting();
  loading.value = false;
  elapsedSeconds.value = 0;
}

const displayMessages = computed(() =>
  messageRecord.value.map((item) => ({
    ...item,
    display: getMessageDisplay(item),
    isUser: isUserMessage(item),
  })),
);

const chatMessages = computed(() =>
  displayMessages.value
    // 过滤掉无实际内容的消息（如被剔除系统提示后的空消息），保持对话简洁
    .filter((item) => item.pending || String(item.display.ctx || '').trim() !== '')
    .map((item) => ({
      content: item.display.ctx || '',
      thinking: Boolean(item.pending && isAiResultMessage(item)),
      from: item.display.from,
      isUser: item.isUser,
      messageClass: getMessageClass(item),
      time: formatMessageTime(item.display.time),
    })),
);

// 供父组件（报告弹窗）导出 PDF：把当前对话拼成报告 Markdown
function getReportMarkdown() {
  return chatMessages.value
    .filter(
      (m) =>
        !String(m.messageClass || '').includes('thinking') &&
        String(m.content || '').trim() !== '',
    )
    .map((m) => {
      const head = m.time ? `**${m.from}** · ${m.time}` : `**${m.from}**`;
      return `${head}\n\n${m.content}`;
    })
    .join('\n\n---\n\n');
}

defineExpose({ getReportMarkdown });

function formatMessageTime(value?: string) {
  return value ? formatTimestamp(value) : '';
}


function isUserMessage(item: ChatMessage) {
  const from = String(item?.message_from || item?.from || '');
  const senderType = String(item?.sender_type || '').toLowerCase();
  const category = String(item?.message_category || '');

  if (category === 'engineer_chat') {
    return senderType !== 'ai';
  }

  return from === 'user' || from.includes('-');
}

async function scrollToBottom() {
  await nextTick();
  chatRef.value?.scrollTo({ top: Number.MAX_SAFE_INTEGER });
}

function getMessageKey(item: ChatMessage) {
  return String(
    item.temp_id ||
      item.message_id ||
      item.id ||
      `${item.message_from || 'msg'}-${item.created_at || ''}`,
  );
}

function getMessageText(item: ChatMessage) {
  const content = item?.message_content || {};
  return String(
    content?.text ||
      content?.content ||
      content?.response_text ||
      content?.data?.text ||
      content?.data?.response_text ||
      item?.message ||
      '',
  ).trim();
}

function isAiResultMessage(item: ChatMessage) {
  const from = String(item?.message_from || item?.from || '');
  const senderType = String(item?.sender_type || '').toLowerCase();

  return senderType === 'ai' || from === 'ai_assistant';
}

function getMessageClass(item: ChatMessage) {
  const from = String(item?.message_from || item?.from || '').toLowerCase();
  const senderType = String(item?.sender_type || '').toLowerCase();
  const category = String(item?.message_category || '');

  if (item?.pending && isAiResultMessage(item)) return 'message-thinking';
  if (category === 'engineer_chat' && senderType === 'ai') return 'message-ai-assistant';
  if (category === 'engineer_chat' && item.isUser) return 'message-engineer-question';
  if (from.includes('captain')) return 'message-captain';
  if (from.includes('manager')) return 'message-manager';
  if (from.includes('operator')) return 'message-operator';
  if (from.includes('executor')) return 'message-executor';
  if (from.includes('expert')) return 'message-expert';
  if (item.isUser) return 'message-user';
  return 'message-system';
}

function removeThinkingMessage(existed: Map<string, ChatMessage>) {
  if (!aiThinkingId.value) return;

  existed.delete(aiThinkingId.value);
  Array.from(existed.entries()).forEach(([key, item]) => {
    if (item?.temp_id === aiThinkingId.value || item?.message_id === aiThinkingId.value) {
      existed.delete(key);
    }
  });
  aiThinkingId.value = '';
}

function removeDuplicatedPendingUserMessage(existed: Map<string, ChatMessage>, message: ChatMessage) {
  if (!isUserMessage(message) || message.pending) return;

  const messageText = getMessageText(message);
  if (!messageText) return;

  Array.from(existed.entries()).forEach(([key, item]) => {
    if (!item?.pending || !isUserMessage(item)) return;
    if (getMessageText(item) === messageText) {
      existed.delete(key);
    }
  });
}

function upsertMessages(items: Record<string, any>[]) {
  const existed = new Map<string, ChatMessage>();
  messageRecord.value.forEach((item) => {
    existed.set(getMessageKey(item), item);
  });

  [...items]
    .sort((a, b) => Number(Boolean(a?.pending)) - Number(Boolean(b?.pending)))
    .forEach((item) => {
    const normalized = normalizeDeepflowMessage(item, props.eventId) as ChatMessage;
    if (isAiResultMessage(normalized) && !normalized.pending && !loading.value) removeThinkingMessage(existed);
    removeDuplicatedPendingUserMessage(existed, normalized);

    const key = getMessageKey(normalized);
    existed.set(key, normalized);
    const numericId = Number(normalized.id || normalized.message_id || 0);
    if (Number.isFinite(numericId)) {
      lastMessageDbId.value = Math.max(lastMessageDbId.value, numericId);
    }
  });

  messageRecord.value = Array.from(existed.values()).sort((a, b) => {
    // Server-persisted user timestamps can be later than the local placeholder.
    // Keep the in-flight AI indicator after the question it is answering.
    const aThinking = Boolean(a.pending && isAiResultMessage(a));
    const bThinking = Boolean(b.pending && isAiResultMessage(b));
    if (aThinking !== bThinking) return aThinking ? 1 : -1;
    const ta = new Date(a.created_at || 0).getTime();
    const tb = new Date(b.created_at || 0).getTime();
    return ta - tb;
  });
}

function addThinkingMessage() {
  if (aiThinkingId.value) return;
  aiThinkingId.value = `ai_thinking_${Date.now()}`;
  upsertMessages([
    {
      created_at: new Date().toISOString(),
      event_id: props.eventId,
      message_category: 'engineer_chat',
      message_content: { content: '请求已提交，等待模型返回。' },
      message_from: 'ai_assistant',
      message_id: aiThinkingId.value,
      pending: true,
      sender_type: 'ai',
      temp_id: aiThinkingId.value,
    },
  ]);
}

function removeTempMessage(tempId: string) {
  messageRecord.value = messageRecord.value.filter((item) => item.temp_id !== tempId);
}

function resetMessages() {
  messageRecord.value = [];
  lastMessageDbId.value = 0;
  aiThinkingId.value = '';
}

async function fetchMessages() {
  if (!props.eventId) return;
  const eventId = props.eventId;
  const generation = requestGeneration;
  try {
    const res = await deepflowGetChatRecords(eventId, {
      last_message_db_id: lastMessageDbId.value || 0,
    });
    if (props.eventId !== eventId || requestGeneration !== generation) return;
    const list = Array.isArray(res)
      ? res
      : res?.messages || res?.data?.messages || res?.data || [];
    if (Array.isArray(list) && list.length > 0) {
      upsertMessages(list);
      await scrollToBottom();
    }
  } catch {
    // 历史消息接口不可用时保留当前会话内容。
  }
}

async function sendAIMessage(text: string) {
  if (!text || loading.value || !props.eventId) return;

  sendError.value = '';
  loading.value = true;
  const generation = ++requestGeneration;
  const eventId = props.eventId;
  const startedAt = Date.now();
  elapsedSeconds.value = 0;
  generationEstimate.value = estimateWait([]);
  const controller = new AbortController();
  requestController = controller;
  waitTimer = setInterval(() => { elapsedSeconds.value = (Date.now() - startedAt) / 1000; }, 1000);
  // Preview failure must not prevent a real request. Its own short timeout
  // bounds the extra wait; the model request has the configured longer limit.
  let profile = '';
  const previewController = new AbortController();
  const abortPreview = () => previewController.abort();
  controller.signal.addEventListener('abort', abortPreview, { once: true });
  const previewTimer = setTimeout(() => previewController.abort(), 3000);
  const preview = deepflowEstimateAI({ event_id: eventId, message: text }, previewController.signal)
    .then((info) => {
      if (generation !== requestGeneration) return;
      profile = String(info.profile || '');
      generationEstimate.value = estimateWait(loadDurations(profile), Number(info.timeout_seconds));
    }).catch(() => {}).finally(() => { clearTimeout(previewTimer); controller.signal.removeEventListener('abort', abortPreview); });
  const tempId = `temp_${Date.now()}`;
  upsertMessages([
    {
      created_at: new Date().toISOString(),
      event_id: props.eventId,
      message_content: { text },
      message_from: 'user',
      message_id: tempId,
      message_type: 'user_message',
      pending: true,
      temp_id: tempId,
    },
  ]);
  messageInput.value = '';
  await scrollToBottom();
  addThinkingMessage();
  await scrollToBottom();

  try {
    await preview;
    if (generation !== requestGeneration) return;
    requestTimer = setTimeout(() => controller.abort(), (generationEstimate.value.timeout + 15) * 1000);
    const res = await deepflowAskAI({
      event_id: eventId,
      message: text,
    }, controller.signal);
    if (generation !== requestGeneration) return;
    if (res?.reply && String(res.reply).trim()) saveDuration(profile, (Date.now() - startedAt) / 1000);
    if (res?.user_message) {
      removeTempMessage(tempId);
      upsertMessages([res.user_message]);
    }
    if (res?.message) upsertMessages([res.message]);
    await fetchMessages();
  } catch (error) {
    if (generation !== requestGeneration) return;
    sendError.value = controller.signal.aborted ? '等待模型结果超时，请稍后检查报告或重试。' : error instanceof Error ? error.message : '发送消息失败';
    message.error('发送失败，请查看下方错误详情');
    messageRecord.value = messageRecord.value.filter((item) => item.temp_id !== aiThinkingId.value);
    aiThinkingId.value = '';
  } finally {
    if (generation === requestGeneration) {
      stopWaiting();
      requestController = undefined;
      messageRecord.value = messageRecord.value.filter((item) => item.temp_id !== aiThinkingId.value);
      aiThinkingId.value = '';
      loading.value = false;
    }
  }
}

async function sendMessage() {
  const text = messageInput.value.trim();
  if (!text || !props.eventId || loading.value) return;

  messageInput.value = '';
  await sendAIMessage(text);
}

function handleSocketConnected() {
  if (!props.eventId) return;
  deepflowSocket.join(props.eventId);
}

function handleNewMessage(data: any) {
  const messages = Array.isArray(data) ? data : [data];
  const currentEventId = String(props.eventId || '');
  const matched = messages.filter((item) => {
    if (!item) return false;
    const itemEventId = String(item.event_id || '');
    return !itemEventId || itemEventId === currentEventId;
  });

  if (matched.length === 0) return;
  upsertMessages(matched);
  scrollToBottom();
}

function renderMarkdown(text?: string) {
  if (!text) return '';
  try {
    return marked.parse(text, { async: false }) as string;
  } catch {
    return text;
  }
}

// —— 分析结果轮询兜底 ——
// 自动分析在后台异步执行；实时推送依赖 websocket（部署环境反代未放行升级时收不到）。
// 打开报告后若尚无分析产出，每 5 秒增量拉取一次，直到出现专家结论/失败提示或超时，
// 保证"打开报告只有创建事件"的窗口期内容能自动补上。
const ANALYSIS_POLL_INTERVAL_MS = 5000;
const ANALYSIS_POLL_MAX_MS = 10 * 60 * 1000;
let pollTimer: null | ReturnType<typeof setInterval> = null;
let pollStartedAt = 0;

function hasAnalysisOutcome(): boolean {
  return messageRecord.value.some((item) => {
    const from = String(item?.message_from || item?.from || '').toLowerCase();
    const type = String(item?.message_type || '').toLowerCase();
    return from.includes('expert') || type === 'event_summary' || type === 'llm_config_required';
  });
}

function stopAnalysisPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function startAnalysisPolling() {
  stopAnalysisPolling();
  if (!props.eventId || hasAnalysisOutcome()) return;
  pollStartedAt = Date.now();
  pollTimer = setInterval(async () => {
    if (!props.eventId || hasAnalysisOutcome() || Date.now() - pollStartedAt > ANALYSIS_POLL_MAX_MS) {
      stopAnalysisPolling();
      return;
    }
    await fetchMessages();
    if (hasAnalysisOutcome()) stopAnalysisPolling();
  }, ANALYSIS_POLL_INTERVAL_MS);
}

watch(
  () => props.eventId,
  async (value, oldValue) => {
    cancelPendingRequest();
    if (oldValue) deepflowSocket.leave(oldValue);
    sendError.value = '';
    resetMessages();
    stopAnalysisPolling();
    if (value) {
      deepflowSocket.join(value);
      await fetchMessages();
      startAnalysisPolling();
    }
  },
  { immediate: true },
);

onMounted(async () => {
  if (props.eventId) {
    deepflowSocket.join(props.eventId);
    await fetchMessages();
    startAnalysisPolling();
  }
  deepflowSocket.on('connected', handleSocketConnected);
  deepflowSocket.on('new_message', handleNewMessage);
  deepflowSocket.connect();
});

onUnmounted(() => {
  cancelPendingRequest();
  stopAnalysisPolling();
  if (props.eventId) deepflowSocket.leave(props.eventId);
  deepflowSocket.off('connected', handleSocketConnected);
  deepflowSocket.off('new_message', handleNewMessage);
});
</script>

<template>
  <div class="chat-shell">
    <div v-if="loading" class="generation-status" :class="{ 'generation-status-slow': generationStatus.slow }" role="status" aria-live="polite">
      <div class="generation-status-heading"><strong>AI助手</strong><span>{{ generationStatus.title }}</span></div>
      <div>{{ generationStatus.text }}</div>
    </div>
    <NScrollbar ref="chatRef" class="chat-body">
      <div v-if="chatMessages.length" class="messages">
        <div
          v-for="(item, index) in chatMessages"
          :key="`${item.from}-${item.time}-${index}`"
          :class="['message', item.messageClass]"
        >
          <div class="message-header">
            <span class="message-sender">{{ item.thinking ? `AI助手 · ${generationStatus.title}` : item.from }}</span>
            <span class="message-time">{{ item.time }}</span>
          </div>
          <div
            :class="[
              'message-content',
              item.messageClass === 'message-ai-assistant' ? 'ai-response markdown-content' : '',
              item.messageClass === 'message-engineer-question' ? 'engineer-question' : '',
            ]"
            v-html="renderMarkdown(item.thinking ? generationStatus.text : item.content || '暂无内容')"
          ></div>
        </div>
      </div>
      <div v-else class="empty-text">
        <div class="empty-title">暂无聊天记录</div>
        <div class="empty-subtitle">输入消息，与 DeepSOC 助手分析该安全事件</div>
      </div>
    </NScrollbar>
    <NAlert v-if="sendError" type="error" title="模型调用失败" class="mx-3 my-2 shrink-0" style="overflow-wrap: anywhere; max-height: 220px; overflow-y: auto">
      {{ sendError }}
    </NAlert>
    <div class="chat-input-container">
      <div class="chat-input-wrapper">
        <NInput
          v-model:value="messageInput"
          class="chat-input"
          type="textarea"
          placeholder="输入消息，与 AI 助手对话"
          :autosize="{ minRows: 1, maxRows: 4 }"
          @keydown.enter.exact.prevent="sendMessage"
        />
        <NSpin :show="loading" :size="20">
          <NButton
            class="send-button"
            type="primary"
            circle
            :disabled="loading || !messageInput.trim()"
            aria-label="发送"
            @click="sendMessage"
          >
            <template #icon>
              <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
                <path
                  d="M12 19V5M5 12l7-7 7 7"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2.2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
            </template>
          </NButton>
        </NSpin>
      </div>
      <div class="input-help-text">
        <span>消息会直接发送给 AI 助手，并结合当前事件上下文生成回复</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.chat-shell {
  /* 跟随 vben 主题 token，自动适配明暗 */
  --primary-color: hsl(var(--primary));
  --secondary-color: hsl(var(--success));
  --dark-bg: hsl(var(--card));
  --darker-bg: hsl(var(--background-deep));
  --light-text: hsl(var(--foreground));
  --accent-color: hsl(var(--destructive));
  --success-color: hsl(var(--success));
  --warning-color: hsl(var(--warning));
  --border-glow: 0 0 0 1px hsl(var(--border));
  --msg-surface: hsl(var(--accent));
  --msg-border: hsl(var(--border));
  --msg-muted: hsl(var(--muted-foreground));

  background: var(--dark-bg);
  color: var(--light-text);
  display: flex;
  flex: 1;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  overflow: hidden;
}

.chat-body {
  flex: 1;
  height: 0;
  min-height: 0;
  overflow: hidden;
  padding: 20px;
}

.generation-status {
  flex-shrink: 0;
  padding: 12px 20px;
  border-bottom: 1px solid hsl(var(--border));
  background: hsl(var(--primary) / 6%);
  color: hsl(var(--muted-foreground));
  font-size: 12px;
  line-height: 1.7;
}
.generation-status-heading { display: flex; align-items: center; gap: 10px; color: hsl(var(--foreground)); }
.generation-status-slow { background: hsl(var(--warning) / 10%); }

.messages {
  display: flex;
  flex-direction: column;
  gap: 6px;
  width: 100%;
  max-width: 1000px;
  margin: 0 auto;
  min-height: 100%;
}

/* ChatGPT 风格：消息无底色、无边框、无分隔线 */
.message {
  animation: fadeIn 0.25s ease-out;
  background: transparent;
  border: 0;
  border-radius: 0;
  box-shadow: none;
  margin-bottom: 2px;
  max-width: 100%;
  padding: 14px 2px;
  position: relative;
}

.message::before,
.message::after {
  display: none;
}

/* 用户消息：右侧浅灰圆角气泡 */
.message-user,
.message-engineer-question {
  align-self: flex-end;
  max-width: 78%;
  margin-left: auto;
  padding: 10px 16px;
  background: hsl(var(--accent));
  border-radius: 18px;
}

.message-thinking {
  animation: thinking-pulse 1.5s ease-in-out infinite;
}

.message-header {
  align-items: baseline;
  display: flex;
  gap: 8px;
  font-size: 12px;
  /* 时间统一紧跟在发送者名称之后 */
  justify-content: flex-start;
  margin-bottom: 6px;
}

/* 用户消息整体右对齐，发送者+时间同样成组，保持与系统消息一致的相对位置 */
.message-user .message-header,
.message-engineer-question .message-header {
  justify-content: flex-end;
}

.message-sender {
  color: hsl(var(--muted-foreground));
  font-weight: 600;
}

.message-time {
  color: var(--msg-muted);
  font-size: 11px;
}

.message-content {
  color: var(--light-text);
  line-height: 1.62;
  overflow-wrap: break-word;
}

/* ChatGPT 风格：用户/AI 内容均无额外底色与边框 */
.engineer-question {
  background: transparent;
  border: 0;
  padding: 0;
}

.ai-response.markdown-content {
  background: transparent;
  border: 0;
  padding: 0;
}

.message-content :deep(h1),
.message-content :deep(h2),
.message-content :deep(h3),
.message-content :deep(h4),
.message-content :deep(h5),
.message-content :deep(h6) {
  color: var(--light-text);
  font-weight: 700;
  line-height: 1.4;
  margin: 12px 0 8px;
}

.ai-response :deep(h1),
.ai-response :deep(h2),
.ai-response :deep(h3) {
  color: hsl(var(--foreground));
}

.message-content :deep(h1) {
  border-bottom: 1px solid hsl(var(--border));
  font-size: 18px;
  padding-bottom: 5px;
}

.message-content :deep(h2) {
  font-size: 16px;
}

.message-content :deep(h3),
.message-content :deep(h4),
.message-content :deep(h5),
.message-content :deep(h6) {
  font-size: 14px;
}

.message-content :deep(p) {
  margin: 7px 0;
}

.message-content :deep(p:first-child),
.message-content :deep(h1:first-child),
.message-content :deep(h2:first-child),
.message-content :deep(h3:first-child) {
  margin-top: 0;
}

.message-content :deep(p:last-child),
.message-content :deep(ul:last-child),
.message-content :deep(ol:last-child),
.message-content :deep(pre:last-child) {
  margin-bottom: 0;
}

.message-content :deep(ul),
.message-content :deep(ol) {
  margin: 8px 0;
  padding-left: 22px;
}

.message-content :deep(li) {
  margin: 5px 0;
}

.message-content :deep(code) {
  background-color: hsl(var(--muted));
  border-radius: 3px;
  color: hsl(var(--foreground));
  font-family: Consolas, Monaco, 'Courier New', monospace;
  font-size: 12px;
  padding: 2px 5px;
}

.message-content :deep(pre) {
  background-color: hsl(var(--muted));
  border-radius: 6px;
  margin: 10px 0;
  overflow-x: auto;
  padding: 12px;
  white-space: pre;
}

.message-content :deep(pre code) {
  background: transparent;
  color: inherit;
  padding: 0;
}

.message-content :deep(blockquote) {
  border-left: 3px solid rgba(102, 187, 106, 0.75);
  color: var(--msg-muted);
  margin: 10px 0;
  padding-left: 12px;
}

.message-content :deep(table) {
  border-collapse: collapse;
  margin: 10px 0;
  width: 100%;
}

.message-content :deep(th),
.message-content :deep(td) {
  border: 1px solid hsl(var(--border));
  padding: 8px;
  text-align: left;
}

.message-content :deep(th) {
  background-color: hsl(var(--muted));
}

/* ChatGPT 风格底部输入栏：居中圆角容器 */
.chat-input-container {
  background: transparent;
  border-top: 0;
  flex: 0 0 auto;
  padding: 10px 16px 16px;
  z-index: 2;
}

.chat-input-wrapper {
  align-items: flex-end;
  background: hsl(var(--card));
  border: 1px solid hsl(var(--border));
  border-radius: 26px;
  box-shadow: 0 2px 12px hsl(var(--foreground) / 6%);
  display: flex;
  gap: 8px;
  margin: 0 auto;
  max-width: 1000px;
  padding: 6px 6px 6px 10px;
}

.chat-input {
  flex: 1;
}

.chat-input :deep(.n-input) {
  /* 去掉 naive 输入框自带的内框线/聚焦描边，仅保留外层圆弧容器 */
  --n-border: none;
  --n-border-hover: none;
  --n-border-focus: none;
  --n-border-disabled: none;
  --n-box-shadow-focus: none;
  background-color: transparent;
}

.chat-input :deep(.n-input__border),
.chat-input :deep(.n-input__state-border) {
  display: none;
}

.chat-input :deep(.n-input .n-input-wrapper) {
  min-height: 40px;
  padding: 0 6px;
}

.chat-input :deep(.n-input__textarea-el) {
  color: hsl(var(--foreground));
  line-height: 1.5;
}

.chat-input :deep(.n-input__placeholder) {
  color: var(--msg-muted);
  opacity: 1;
}

.send-button {
  flex: 0 0 auto;
  width: 36px;
  min-width: 36px;
  height: 36px;
  padding: 0;
  border-radius: 50%;
  font-size: 18px;
  line-height: 1;
}

.input-help-text {
  color: var(--msg-muted);
  font-size: 12px;
  margin-top: 8px;
  text-align: center;
}

.input-help-text strong {
  color: var(--primary-color);
}

.empty-text {
  align-items: center;
  color: var(--msg-muted);
  display: flex;
  flex-direction: column;
  gap: 6px;
  justify-content: center;
  min-height: 100%;
  text-align: center;
}

.empty-title {
  color: var(--primary-color);
  font-size: 16px;
  font-weight: 700;
}

.empty-subtitle {
  font-size: 12px;
}

@keyframes thinking-pulse {
  0%,
  100% {
    opacity: 0.62;
  }
  50% {
    opacity: 1;
  }
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(8px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@media (max-width: 768px) {
  .chat-body {
    padding: 14px;
  }

  .message,
  .message-ai-assistant,
  .message-user,
  .message-engineer-question {
    max-width: 96%;
  }

  .chat-input-container {
    padding: 12px;
  }
}
</style>
