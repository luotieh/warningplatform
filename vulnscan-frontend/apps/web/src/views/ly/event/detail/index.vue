<script lang="ts" setup>
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import { NButton, NSpace } from "naive-ui";

import {
  deepflowGetEventDetail,
  deepflowGetEventStats,
  deepflowGetEventSummary,
  deepflowGetEvents,
} from "#/api/ly/deepflow";
import { message } from "#/adapter/naive";
import { useDeepflowStore } from "#/store";
import { formatDeepflowDate, mapSeverityToDisplay } from "#/utils/deepflow";
import deepflowSocket from "#/utils/deepflow-socket";

import ChatBox from "./components/ChatBox.vue";
import DetailsDialog from "./components/DetailsDialog.vue";
import ListDrawer from "./components/ListDrawer.vue";

defineOptions({ name: "LyEventDetail" });

const route = useRoute();
const router = useRouter();
const deepflowStore = useDeepflowStore();

const eventId = ref("");
const dialogVisible = ref(false);
const drawerVisible = ref(false);
const activeTab = ref<"context" | "original" | "summary">("original");
const wsConnectionStatus = ref<"connected" | "connecting" | "disconnected">(
  "disconnected",
);
const detail = ref<Record<string, any>>({});
const eventCount = ref({ action_count: 0, command_count: 0, task_count: 0 });
const dialogData = ref({ contentInfo: "", rawInfo: "", sumInfo: "" });
const tableData = ref<Record<string, any>[]>([]);

const tabs = [
  { id: "original", label: "原始信息" },
  { id: "context", label: "上下文信息" },
  { id: "summary", label: "事件总结" },
] as const;

const severityText = computed(() =>
  mapSeverityToDisplay(detail.value?.severity),
);
const createdAtText = computed(
  () =>
    formatDeepflowDate(detail.value?.created_at) ||
    String(route.query.occurrence_time || "-"),
);
const eventTitle = computed(() => {
  const type = String(
    route.query.event_type ||
      detail.value?.event_type ||
      detail.value?.event_name ||
      "安全事件",
  );
  const source = String(
    route.query.threat_source || detail.value?.threat_source || "",
  );
  if (source) return `发现与${source}的通讯行为 (${type})`;
  return detail.value?.event_name || type;
});
const eventSource = computed(() => {
  const raw = String(detail.value?.source || route.query.source || "").trim();
  if (!raw || /^flow\s*shadow$/i.test(raw)) return "ta_node";
  return raw;
});
const eventLevelText = computed(() =>
  String(route.query.event_level || severityText.value || "-"),
);
const currentRound = computed(() => Number(detail.value?.current_round || 1));
const wsStatusClass = computed(() => `is-${wsConnectionStatus.value}`);
const wsStatusText = computed(() => {
  if (wsConnectionStatus.value === "connected") return "已连接";
  if (wsConnectionStatus.value === "connecting") return "连接中";
  return "未连接";
});
const eventContext = computed(() => ({
  event_level: eventLevelText.value,
  event_type: route.query.event_type || detail.value?.event_name || "安全事件",
  occurrence_time: createdAtText.value,
  rule_desc: route.query.rule_desc || detail.value?.message || "",
  threat_source: route.query.threat_source || detail.value?.threat_source || "",
  victim_target: route.query.victim_target || detail.value?.victim_target || "",
}));

function formatSummaryData(res: any) {
  const list = Array.isArray(res)
    ? res
    : Array.isArray(res?.data)
      ? res.data
      : [];
  if (list.length > 0) {
    return list
      .map((item: Record<string, any>, index: number) => {
        const title = `第 ${item.round_id || index + 1} 轮总结`;
        const time = formatDeepflowDate(item.updated_at || item.created_at);
        return [
          `【${title}】`,
          time ? `时间：${time}` : "",
          item.event_summary || "暂无总结内容",
        ]
          .filter(Boolean)
          .join("\n");
      })
      .join("\n\n");
  }

  if (typeof res === "string") return res;
  if (res?.event_summary) return String(res.event_summary);
  if (res?.data?.event_summary) return String(res.data.event_summary);
  return "";
}

async function getDetails() {
  if (!eventId.value) return;
  try {
    const [detailRes, statsRes] = await Promise.all([
      deepflowGetEventDetail(eventId.value),
      deepflowGetEventStats(eventId.value),
    ]);
    detail.value = detailRes || {};
    eventCount.value = {
      action_count: Number(statsRes?.action_count || 0),
      command_count: Number(statsRes?.command_count || 0),
      task_count: Number(statsRes?.task_count || 0),
    };
  } catch (error) {
    message.error(error instanceof Error ? error.message : "获取事件详情失败，请检查后端服务");
    detail.value = {};
    eventCount.value = { action_count: 0, command_count: 0, task_count: 0 };
  }
}

async function getTable() {
  try {
    const res = await deepflowGetEvents();
    tableData.value = Array.isArray(res) ? res : [];
  } catch {
    tableData.value = [];
  }
}

async function loadSummary() {
  if (!eventId.value) return;
  let res: any = "";
  try {
    res = await deepflowGetEventSummary(eventId.value);
  } catch (error) {
    message.error(error instanceof Error ? error.message : "获取事件总结失败，请检查LLM配置和后端服务");
  }
  dialogData.value = {
    rawInfo: String(detail.value?.message || route.query.rule_desc || ""),
    contentInfo:
      String(detail.value?.context || "") ||
      `威胁来源：${String(route.query.threat_source || "-")}` +
        `\n受害目标：${String(route.query.victim_target || "-")}`,
    sumInfo: formatSummaryData(res),
  };
}

async function openDetailModal() {
  try {
    await loadSummary();
    dialogVisible.value = true;
  } catch (error) {
    message.error(error instanceof Error ? error.message : "获取事件总结失败");
  }
}

async function applyRouteState() {
  const nextEventId = String(
    route.query.deepsoc_event_id ||
      route.query.event_id ||
      route.query.id ||
      "",
  ).replace(/^#/, "");
  eventId.value = nextEventId;
  drawerVisible.value = !nextEventId;
  await getTable();
  if (nextEventId) {
    await getDetails();
  }
}

function updateWSStatus(status: "connected" | "connecting" | "disconnected") {
  wsConnectionStatus.value = status;
}

function syncSocketStatus() {
  if (deepflowSocket.status === "connected" || deepflowSocket.connected) {
    updateWSStatus("connected");
    return;
  }

  if (deepflowSocket.status === "connecting") {
    updateWSStatus("connecting");
    return;
  }

  updateWSStatus("disconnected");
}

function openDrawer() {
  drawerVisible.value = true;
}

function handleDrawerEventClick(event: Record<string, any>) {
  const next = String(event?.event_id || event?.id || "");
  if (!next) return;
  router.push({
    path: "/ly/event/detail",
    query: {
      ...route.query,
      deepsoc_event_id: next,
      event_id: next,
    },
  });
  drawerVisible.value = false;
}

onMounted(async () => {
  const queryToken = route.query.deepsoc_token;
  try {
    if (queryToken) deepflowStore.useToken(String(queryToken));
    else await deepflowStore.ensureToken();
  } catch (error) {
    console.error("[DeepFlow] 自动登录失败:", error);
  }

  await applyRouteState();
  deepflowSocket.on("connected", handleSocketConnected);
  deepflowSocket.on("disconnected", handleSocketDisconnected);
  deepflowSocket.on("error", handleSocketError);
  syncSocketStatus();
  deepflowSocket.connect();
  syncSocketStatus();
});

function handleSocketConnected() {
  updateWSStatus("connected");
}

function handleSocketDisconnected() {
  updateWSStatus("disconnected");
}

function handleSocketError() {
  updateWSStatus("disconnected");
}

onUnmounted(() => {
  deepflowSocket.off("connected", handleSocketConnected);
  deepflowSocket.off("disconnected", handleSocketDisconnected);
  deepflowSocket.off("error", handleSocketError);
});

watch(
  () => route.query,
  async () => {
    await applyRouteState();
  },
);
</script>

<template>
  <div class="ly-detail-page">
    <header class="detail-header">
      <h1>AI安全事件研判</h1>
      <NSpace align="center" :size="10">
        <span :class="['status-pill', 'connection-pill', wsStatusClass]">
          <span class="status-dot"></span>
          {{ wsStatusText }}
        </span>
        <span class="status-pill processing-pill">处理中</span>
        <NButton
          round
          size="small"
          type="primary"
          secondary
          @click="openDetailModal"
          >详情</NButton
        >
      </NSpace>
    </header>

    <div class="workbench">
      <aside class="summary-panel">
        <div class="ai-badge">AI</div>
        <h2>{{ eventTitle }}</h2>
        <p>{{ createdAtText }}</p>
        <div class="summary-fields">
          <div>ID：{{ eventId || "-" }}</div>
          <div>轮次：{{ currentRound }}</div>
          <div>来源：{{ eventSource }}</div>
          <div>严重程度：{{ eventLevelText }}</div>
          <div>创建时间：{{ createdAtText }}</div>
        </div>
        <NButton
          class="event-list-button"
          secondary
          type="primary"
          @click="openDrawer"
        >
          ☰ 事件列表
        </NButton>
      </aside>

      <main class="chat-panel">
        <div class="chat-box">
          <ChatBox :event-id="eventId" :event-context="eventContext" />
        </div>
      </main>

      <aside class="status-panel">
        <div class="status-title">
          <h2>事件状态</h2>
          <span
            :class="[
              'status-pill',
              'connection-pill',
              'status-pill-compact',
              wsStatusClass,
            ]"
          >
            <span class="status-dot"></span>
            {{ wsStatusText }}
          </span>
        </div>
        <div class="metric-list">
          <div class="metric-card metric-green">
            <span class="metric-icon">↺</span>
            <span>当前轮次</span>
            <strong>{{ currentRound }}</strong>
          </div>
          <div class="metric-card metric-orange">
            <span class="metric-icon">▣</span>
            <span>任务数</span>
            <strong>{{ eventCount.task_count }}</strong>
          </div>
          <div class="metric-card metric-pink">
            <span class="metric-icon">⌁</span>
            <span>动作数</span>
            <strong>{{ eventCount.action_count }}</strong>
          </div>
          <div class="metric-card metric-blue">
            <span class="metric-icon">◉</span>
            <span>指令数</span>
            <strong>{{ eventCount.command_count }}</strong>
          </div>
        </div>

        <div class="side-action">
          <span>自动分析</span>
          <strong>已开启</strong>
        </div>
        <button class="plain-action" type="button" @click="openDetailModal">
          <span>设置</span>
          <span>⚙</span>
        </button>
        <button
          class="plain-action"
          type="button"
          @click="router.push('/ly/event/list')"
        >
          <span>退出</span>
          <span>↩</span>
        </button>
      </aside>
    </div>

    <DetailsDialog
      v-model:visible="dialogVisible"
      title="事件详情"
      :show-footer="false"
    >
      <div class="dialog-content">
        <div class="tab-header">
          <div
            v-for="tab in tabs"
            :key="tab.id"
            :class="['tab-item', { active: activeTab === tab.id }]"
            @click="activeTab = tab.id"
          >
            {{ tab.label }}
          </div>
        </div>
        <div class="tab-panel">
          <pre v-if="activeTab === 'original'">{{
            dialogData.rawInfo || "暂无数据"
          }}</pre>
          <pre v-else-if="activeTab === 'context'">{{
            dialogData.contentInfo || "暂无数据"
          }}</pre>
          <pre v-else>{{ dialogData.sumInfo || "暂无数据" }}</pre>
        </div>
      </div>
    </DetailsDialog>

    <ListDrawer
      v-model:visible="drawerVisible"
      :table-data="tableData"
      title="事件列表"
      @event-click="handleDrawerEventClick"
    />
  </div>
</template>

<style scoped>
.ly-detail-page {
  --detail-accent: hsl(var(--primary));
  --detail-bg: hsl(var(--background-deep));
  --detail-border: hsl(var(--border));
  --detail-card: hsl(var(--card));
  --detail-card-soft: hsl(var(--accent));
  --detail-muted: hsl(var(--muted-foreground));
  --detail-panel: hsl(var(--background));
  --detail-text: hsl(var(--foreground));
  --detail-title: hsl(var(--card-foreground));

  box-sizing: border-box;
  background: var(--detail-bg);
  color: var(--detail-text);
  height: calc(100vh - var(--vben-header-height, 88px));
  min-height: 0;
  overflow: hidden;
  padding: 14px 16px;
}
.detail-header {
  align-items: center;
  display: flex;
  height: 34px;
  justify-content: space-between;
  padding: 0 8px;
}
.detail-header h1 {
  color: var(--detail-title);
  font-size: 18px;
  font-weight: 700;
  margin: 0;
}
.status-pill {
  align-items: center;
  border: 1px solid transparent;
  border-radius: 999px;
  display: inline-flex;
  font-size: 12px;
  font-weight: 600;
  gap: 6px;
  height: 24px;
  justify-content: center;
  line-height: 1;
  min-width: 66px;
  padding: 0 12px;
  white-space: nowrap;
}
.connection-pill.is-connected {
  background: hsl(var(--success) / 14%);
  border-color: hsl(var(--success) / 55%);
  color: hsl(var(--success));
}
.connection-pill.is-connecting {
  background: hsl(var(--warning) / 16%);
  border-color: hsl(var(--warning) / 58%);
  color: hsl(var(--warning));
}
.connection-pill.is-disconnected {
  background: hsl(var(--muted));
  border-color: hsl(var(--border));
  color: hsl(var(--muted-foreground));
}
.status-dot {
  background: currentColor;
  border-radius: 50%;
  flex: 0 0 8px;
  height: 8px;
  width: 8px;
}
.processing-pill {
  background: hsl(var(--warning) / 16%);
  border-color: hsl(var(--warning) / 58%);
  color: hsl(var(--warning));
}
.status-pill-compact {
  height: 22px;
  min-width: 70px;
  padding: 0 10px;
}
.workbench {
  background: var(--detail-panel);
  border: 1px solid var(--detail-border);
  border-radius: 12px;
  display: grid;
  grid-template-columns: 320px minmax(640px, 1fr) 300px;
  height: calc(100% - 42px);
  min-height: 0;
  overflow: hidden;
}
.summary-panel {
  background: var(--detail-card-soft);
  border-right: 1px solid var(--detail-border);
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  padding: 12px;
  position: relative;
}
.ai-badge {
  align-items: center;
  align-self: center;
  background: linear-gradient(
    135deg,
    hsl(var(--primary)),
    hsl(var(--primary) / 70%)
  );
  border-radius: 50%;
  color: hsl(var(--primary-foreground));
  display: flex;
  font-size: 14px;
  font-weight: 700;
  height: 36px;
  justify-content: center;
  margin-top: 10px;
  width: 36px;
}
.summary-panel h2 {
  color: var(--detail-title);
  font-size: 17px;
  line-height: 1.5;
  margin: 12px 0 10px;
  text-align: center;
}
.summary-panel p {
  color: var(--detail-muted);
  font-size: 12px;
  margin: 0 0 12px;
  text-align: center;
}
.summary-fields {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.summary-fields div {
  background: var(--detail-card);
  border: 1px solid var(--detail-border);
  border-radius: 6px;
  color: var(--detail-text);
  font-size: 13px;
  padding: 8px 10px;
  text-align: center;
}
.event-list-button {
  align-self: center;
  bottom: 140px;
  box-shadow: 0 10px 22px hsl(var(--primary) / 14%);
  min-width: 160px;
  position: absolute;
}
.chat-panel {
  background: var(--detail-panel);
  height: 100%;
  min-height: 0;
  min-width: 0;
  overflow: hidden;
  position: relative;
}
.chat-box {
  display: flex;
  height: 100%;
  min-height: 0;
  overflow: hidden;
}
.status-panel {
  background: var(--detail-card-soft);
  border-left: 1px solid var(--detail-border);
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 0;
  overflow: hidden;
  padding: 16px 12px;
}
.status-title {
  align-items: center;
  display: flex;
  justify-content: space-between;
}
.status-title h2 {
  color: var(--detail-title);
  font-size: 16px;
  margin: 0;
}
.metric-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 16px;
}
.metric-card {
  align-items: center;
  background: var(--detail-card);
  border-radius: 12px;
  color: var(--detail-text);
  display: grid;
  font-size: 14px;
  grid-template-columns: 44px 1fr auto;
  min-height: 64px;
  padding: 0 18px;
}
.metric-card strong {
  font-size: 18px;
}
.metric-icon {
  align-items: center;
  border-radius: 50%;
  color: hsl(var(--primary-foreground));
  display: flex;
  font-size: 14px;
  height: 22px;
  justify-content: center;
  width: 22px;
}
.metric-green .metric-icon {
  background: hsl(var(--success));
}
.metric-orange .metric-icon {
  background: hsl(var(--warning));
}
.metric-pink .metric-icon {
  background: hsl(var(--destructive));
}
.metric-blue .metric-icon {
  background: hsl(var(--primary));
}
.side-action,
.plain-action {
  align-items: center;
  background: var(--detail-card);
  border: 0;
  border-radius: 10px;
  color: var(--detail-text);
  display: flex;
  font-size: 14px;
  justify-content: space-between;
  min-height: 48px;
  padding: 0 16px;
  text-align: left;
  width: 100%;
}
.plain-action {
  cursor: pointer;
}
.dialog-content {
  min-height: 320px;
}
.tab-header {
  border-bottom: 1px solid hsl(var(--border));
  display: flex;
  gap: 12px;
  margin-bottom: 12px;
}
.tab-item {
  cursor: pointer;
  padding: 8px 4px;
}
.tab-item.active {
  border-bottom: 2px solid var(--n-color-primary);
  color: var(--n-color-primary);
}
.tab-panel pre {
  margin: 0;
  white-space: pre-wrap;
}

@media (max-width: 1280px) {
  .workbench {
    grid-template-columns: 280px minmax(520px, 1fr) 260px;
  }
}

@media (max-width: 980px) {
  .ly-detail-page {
    height: auto;
    min-height: 100vh;
    overflow: visible;
  }
  .workbench {
    grid-template-columns: 1fr;
    height: auto;
  }
  .summary-panel,
  .status-panel {
    min-height: 280px;
  }
  .event-list-button {
    bottom: 24px;
  }
  .chat-box {
    height: 640px;
  }
}
</style>
