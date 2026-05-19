<script lang="ts" setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';

import { Page } from '@vben/common-ui';
import { IconifyIcon } from '@vben/icons';

import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import 'dayjs/locale/zh-cn';
import {
  NAlert,
  NButton,
  NCard,
  NDescriptions,
  NDescriptionsItem,
  NDivider,
  NDrawer,
  NDrawerContent,
  NEmpty,
  NGi,
  NGrid,
  NInput,
  NModal,
  NPopconfirm,
  NProgress,
  NRadio,
  NRadioGroup,
  NSelect,
  NSpace,
  NSpin,
  NSwitch,
  NTabPane,
  NTabs,
  NTag,
  NTooltip,
  useMessage,
} from 'naive-ui';

dayjs.extend(relativeTime);
dayjs.locale('zh-cn');

import {
  getClusterConnectivityModes,
  getNodeKnowledgeManifest,
  getUnifiedNodes,
  issueScanNodeCredentials,
  type ConnectivityModeInfo,
  type DeploymentTopology,
  deleteScanNode,
  unregisterWorker,
  type NodeKnowledgeManifest,
  type NodeSummary,
  type UnifiedNode,
} from '#/api/cluster';

import { deleteMonitorAgent, shutdownAgent } from '#/api/sitemonitor';

defineOptions({ name: 'ClusterNodes' });

const message = useMessage();
const loading = ref(false);
const nodes = ref<UnifiedNode[]>([]);
const summary = ref<NodeSummary>({
  total_nodes: 0,
  online_nodes: 0,
  offline_nodes: 0,
  worker_count: 0,
  agent_count: 0,
  total_tasks: 0,
  total_capacity: 0,
});
const filterStatus = ref<string | null>(null);
const filterType = ref<string | null>(null);
const searchKeyword = ref('');
const autoRefresh = ref(true);
const lastRefreshedAt = ref<Date | null>(null);
const detailNode = ref<UnifiedNode | null>(null);
const showDetailDrawer = ref(false);
let refreshTimer: ReturnType<typeof setInterval> | null = null;

const apiBase = ((import.meta as any).env?.VITE_GLOB_API_URL as string) || '/api';

/** 签发凭据用：须为节点可访问的完整 API 根（Agent 不走 Vite 代理） */
function resolveEnrollMasterUrlDefault(): string {
  const trimmed = apiBase.replace(/\/$/, '');
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }
  return 'http://127.0.0.1:8090/api';
}

function isValidEnrollMasterUrl(url: string): boolean {
  const u = url.trim();
  return /^https?:\/\/\S+/i.test(u);
}

const nodeKnowledgeApiPrefix = `${apiBase.replace(/\/$/, '')}/node-api/knowledge`;

const kmLoading = ref(false);
const km = ref<NodeKnowledgeManifest | null>(null);

const showEnrollModal = ref(false);
const enrollJson = ref('');
const enrollMasterUrl = ref(resolveEnrollMasterUrlDefault());
const enrollTopology = ref<DeploymentTopology>('master_public_node_private');
const connectivityModes = ref<ConnectivityModeInfo[]>([]);
const enrollLabel = ref('');
const enrollSubmitting = ref(false);
/** 签发结果：none | encrypted（仅 envelope）| plaintext（明文凭据 JSON） */
const enrollResultMode = ref<'none' | 'encrypted' | 'plaintext' | 'error'>('none');
const enrollResultMain = ref('');
const enrollDecryptHint = ref('');

const enrollFileInputRef = ref<HTMLInputElement | null>(null);

const ENROLL_HISTORY_KEY = 'vulnscan_cluster_enroll_history_v1';
const ENROLL_HISTORY_MAX = 20;

interface EnrollHistoryItem {
  id: string;
  at: string;
  label: string;
  masterUrl: string;
  mode: 'encrypted' | 'plaintext' | 'error';
  /** 明文凭据签发时仅记录节点 UUID，不存 secret */
  nodeUuid?: string;
  /** 加密签发时保存完整 envelope，便于本机再次下载 */
  envelopeJson?: string;
  /** 异常时保存短片段 */
  detailSnippet?: string;
}

const clusterTab = ref<'nodes' | 'onboard'>('nodes');
const enrollHistory = ref<EnrollHistoryItem[]>([]);

const typeLabels: Record<string, string> = {
  local: '本地引擎',
  worker: 'Worker',
  agent: '监测节点',
  scan: '扫描节点',
};

const statusConfig: Record<string, { type: string; label: string }> = {
  online: { type: 'success', label: '在线' },
  offline: { type: 'default', label: '离线' },
  busy: { type: 'info', label: '繁忙' },
  drain: { type: 'warning', label: '排干' },
};

function fmtTime(raw?: string) {
  if (!raw) return '-';
  const d = dayjs(raw);
  return d.isValid() ? d.format('YYYY-MM-DD HH:mm:ss') : raw;
}

function fmtRelative(raw?: string) {
  if (!raw) return '-';
  const d = dayjs(raw);
  if (!d.isValid()) return raw;
  const diffSec = (Date.now() - d.valueOf()) / 1000;
  if (diffSec < 45) return '刚刚';
  return d.fromNow();
}

const lastRefreshText = computed(() => {
  if (!lastRefreshedAt.value) return '尚未刷新';
  return `更新于 ${fmtRelative(lastRefreshedAt.value.toISOString())}`;
});

const onlineRate = computed(() => {
  const total = summary.value.total_nodes || 0;
  if (!total) return 0;
  return Math.round((summary.value.online_nodes / total) * 100);
});

const typeBreakdownText = computed(() => {
  const parts: string[] = [];
  const local = nodes.value.filter((n) => n.type === 'local').length;
  const scan = nodes.value.filter((n) => n.type === 'scan' || n.type === 'worker').length;
  const agent = nodes.value.filter((n) => n.type === 'agent').length;
  if (local) parts.push(`本地 ${local}`);
  if (scan) parts.push(`扫描 ${scan}`);
  if (agent) parts.push(`监测 ${agent}`);
  return parts.join(' · ') || '暂无分类节点';
});

const totalQueuedTasks = computed(() =>
  nodes.value.reduce((sum, n) => sum + (n.queued_tasks ?? 0), 0),
);

const filteredNodes = computed(() => {
  let list = nodes.value;
  if (filterStatus.value) list = list.filter((n) => n.status === filterStatus.value);
  if (filterType.value) list = list.filter((n) => n.type === filterType.value);
  const kw = searchKeyword.value.trim().toLowerCase();
  if (kw) {
    list = list.filter((n) =>
      [n.name, n.hostname, n.ip, n.label, n.id, n.version]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(kw)),
    );
  }
  return list;
});

function openNodeDetail(row: UnifiedNode) {
  detailNode.value = row;
  showDetailDrawer.value = true;
}

function resetNodeFilters() {
  searchKeyword.value = '';
  filterStatus.value = null;
  filterType.value = null;
}

const statusFilterOptions = [
  { label: '在线', value: 'online' },
  { label: '繁忙', value: 'busy' },
  { label: '离线', value: 'offline' },
  { label: '排干', value: 'drain' },
];

const typeFilterOptions = [
  { label: '本地引擎', value: 'local' },
  { label: '扫描节点', value: 'scan' },
  { label: 'Worker', value: 'worker' },
  { label: '监测节点', value: 'agent' },
];

const onboardSteps = [
  {
    icon: 'lucide:key-round',
    title: '生成 enrollment',
    desc: '在待接入机器执行 agent enroll，得到 node-enrollment.json 与同目录私钥 node-enrollment.key',
    cmd: 'agent enroll -out node-enrollment.json',
  },
  {
    icon: 'lucide:badge-check',
    title: '主控签发凭据',
    desc: '将 enrollment JSON 上传到本页签发；推荐 RSA 加密包，响应中不含明文 secret',
    cmd: '',
  },
  {
    icon: 'lucide:rocket',
    title: '解密并启动',
    desc: '节点侧 decrypt-credentials 得到 node-agent.credentials.json，配置 credentials_file 后 agent run',
    cmd: 'agent decrypt-credentials -envelope credentials.enc.json -key node-enrollment.key -out node-agent.credentials.json',
  },
];

const statAccentMap: Record<string, string> = {
  default: 'blue',
  success: 'green',
  muted: 'slate',
  info: 'blue',
  warning: 'orange',
};

function nodeTypeColor(type: string) {
  if (type === 'local') return '#64748b';
  if (type === 'scan' || type === 'worker') return '#1890ff';
  return '#52c41a';
}

function resourceProgressStatus(pct: number): 'default' | 'error' | 'warning' {
  if (pct > 90) return 'error';
  if (pct > 70) return 'warning';
  return 'default';
}

function nodeDisplayTitle(row: UnifiedNode) {
  return row.label || row.name || row.hostname || row.ip || row.id;
}

function nodeDisplaySub(row: UnifiedNode) {
  return [row.ip, row.hostname].filter(Boolean).join(' · ') || row.id;
}

function enrollHistorySummary(row: EnrollHistoryItem) {
  if (row.mode === 'plaintext') return row.nodeUuid ? `节点 ${row.nodeUuid}` : row.label || '-';
  if (row.mode === 'encrypted') return row.label ? `加密 · ${row.label}` : 'RSA 加密 envelope';
  return row.detailSnippet || row.label || '-';
}

const kmMetricCards = computed(() => {
  if (!km.value) return [];
  return [
    { key: 'poc', label: 'PoC 游标', value: km.value.versions?.poc ?? 0, icon: 'lucide:shield' },
    {
      key: 'fingerprint',
      label: '指纹游标',
      value: km.value.versions?.fingerprint ?? 0,
      icon: 'lucide:fingerprint',
    },
    { key: 'rule', label: '规则游标', value: km.value.versions?.rule ?? 0, icon: 'lucide:book-open' },
    {
      key: 'time',
      label: '主控时间',
      value: km.value.server_time || '-',
      icon: 'lucide:clock',
      small: true,
    },
  ];
});

const statCards = computed(() => [
  {
    key: 'total',
    label: '节点总数',
    value: summary.value.total_nodes,
    sub: typeBreakdownText.value,
    icon: 'lucide:server',
    tone: 'default',
  },
  {
    key: 'online',
    label: '在线',
    value: summary.value.online_nodes,
    sub: `在线率 ${onlineRate.value}%`,
    icon: 'lucide:activity',
    tone: 'success',
  },
  {
    key: 'offline',
    label: '离线',
    value: summary.value.offline_nodes,
    sub: summary.value.offline_nodes ? '建议检查心跳' : '全部可达',
    icon: 'lucide:wifi-off',
    tone: 'muted',
  },
  {
    key: 'running',
    label: '执行中',
    value: summary.value.total_tasks,
    sub: `容量 ${summary.value.total_capacity || 0}`,
    icon: 'lucide:play-circle',
    tone: 'info',
  },
  {
    key: 'queue',
    label: '队列中',
    value: totalQueuedTasks.value,
    sub: totalQueuedTasks.value ? '存在排队任务' : '队列空闲',
    icon: 'lucide:list-ordered',
    tone: 'warning',
  },
  {
    key: 'capacity',
    label: '总容量',
    value: summary.value.total_capacity,
    sub: `扫描 ${summary.value.worker_count ?? 0} · 监测 ${summary.value.agent_count ?? 0}`,
    icon: 'lucide:gauge',
    tone: 'default',
  },
]);

async function fetchData() {
  loading.value = true;
  try {
    const result = await getUnifiedNodes() as any;
    nodes.value = result?.nodes ?? [];
    if (result?.summary) summary.value = result.summary;
    lastRefreshedAt.value = new Date();
  } finally {
    loading.value = false;
  }
}

function setupRefreshTimer() {
  if (refreshTimer) clearInterval(refreshTimer);
  if (!autoRefresh.value) return;
  refreshTimer = setInterval(fetchData, 10000);
}

function onAutoRefreshChange(enabled: boolean) {
  autoRefresh.value = enabled;
  setupRefreshTimer();
}

async function loadKnowledgeManifest() {
  kmLoading.value = true;
  try {
    km.value = await getNodeKnowledgeManifest();
  } catch {
    km.value = null;
  } finally {
    kmLoading.value = false;
  }
}

async function handleRefresh() {
  await Promise.all([fetchData(), loadKnowledgeManifest()]);
}

async function handleDeleteNode(node: UnifiedNode) {
  try {
    if (node.type === 'scan') {
      await deleteScanNode(node.id);
    } else if (node.type === 'worker') {
      await unregisterWorker(node.id);
    } else if (node.type === 'agent') {
      await deleteMonitorAgent(node.id);
    } else {
      return;
    }
    message.success('已删除');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}

async function handleShutdownAgent(id: string) {
  try {
    await shutdownAgent(id);
    message.success('已发送停止指令');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

function canDeleteNode(node: UnifiedNode) {
  return node.type !== 'local';
}

function canShutdownNode(node: UnifiedNode) {
  return node.type === 'agent' && (node.status === 'online' || node.status === 'busy');
}

const activeTopologyMode = computed(() =>
  connectivityModes.value.find((m) => m.id === enrollTopology.value),
);

async function loadConnectivityModes() {
  try {
    const data = await getClusterConnectivityModes();
    connectivityModes.value = data.modes ?? [];
    if (data.default_mode) {
      enrollTopology.value = data.default_mode;
    }
    onTopologyChange();
  } catch {
    connectivityModes.value = [];
  }
}

function onTopologyChange() {
  const mode = activeTopologyMode.value;
  if (mode?.suggested_master_url) {
    enrollMasterUrl.value = mode.suggested_master_url;
  }
}

function openEnrollModal() {
  enrollResultMode.value = 'none';
  enrollResultMain.value = '';
  enrollDecryptHint.value = '';
  void loadConnectivityModes();
  showEnrollModal.value = true;
}

function triggerEnrollmentFilePick() {
  enrollFileInputRef.value?.click();
}

function onEnrollmentFileSelected(ev: Event) {
  const input = ev.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    enrollJson.value = String(reader.result ?? '').trim();
    message.success(`已读入：${file.name}`);
  };
  reader.onerror = () => message.error('读取文件失败');
  reader.readAsText(file);
  input.value = '';
}

async function copyIssueResult() {
  const text = enrollResultMain.value.trim();
  if (!text) {
    message.warning('暂无可复制内容');
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    message.success('已复制到剪贴板');
  } catch {
    message.error('复制失败，请手动全选复制');
  }
}

function loadEnrollHistory() {
  try {
    const raw = localStorage.getItem(ENROLL_HISTORY_KEY);
    if (!raw) {
      enrollHistory.value = [];
      return;
    }
    const arr = JSON.parse(raw) as EnrollHistoryItem[];
    enrollHistory.value = Array.isArray(arr) ? arr : [];
  } catch {
    enrollHistory.value = [];
  }
}

function saveEnrollHistory() {
  try {
    localStorage.setItem(ENROLL_HISTORY_KEY, JSON.stringify(enrollHistory.value.slice(0, ENROLL_HISTORY_MAX)));
  } catch {
    message.warning('签发历史无法写入浏览器存储（可能已满或被禁用）');
  }
}

function pushEnrollHistory(item: Omit<EnrollHistoryItem, 'id'>) {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  enrollHistory.value = [{ ...item, id }, ...enrollHistory.value].slice(0, ENROLL_HISTORY_MAX);
  saveEnrollHistory();
}

function removeEnrollHistoryRow(id: string) {
  enrollHistory.value = enrollHistory.value.filter((x) => x.id !== id);
  saveEnrollHistory();
  message.success('已删除');
}

function clearEnrollHistory() {
  enrollHistory.value = [];
  saveEnrollHistory();
  message.success('已清空签发历史');
}

function downloadTextFile(filename: string, text: string) {
  const blob = new Blob([text], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadCurrentEnvelope() {
  const text = enrollResultMain.value.trim();
  if (!text) {
    message.warning('暂无可下载内容');
    return;
  }
  downloadTextFile(`scan-node-envelope-${Date.now()}.enc.json`, text);
  message.success('已开始下载');
}

function downloadEnvelopeHistory(row: EnrollHistoryItem) {
  if (!row.envelopeJson) return;
  downloadTextFile(`scan-node-envelope-${row.id}.enc.json`, row.envelopeJson);
  message.success('已开始下载');
}

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    message.success('已复制');
  } catch {
    message.error('复制失败');
  }
}

const enrollModeLabels: Record<EnrollHistoryItem['mode'], string> = {
  encrypted: '加密包',
  plaintext: '明文',
  error: '异常',
};

async function submitIssueScan() {
  enrollSubmitting.value = true;
  enrollResultMode.value = 'none';
  enrollResultMain.value = '';
  enrollDecryptHint.value = '';
  try {
    let enrollment: Record<string, unknown>;
    try {
      enrollment = JSON.parse(enrollJson.value || 'null') as Record<string, unknown>;
    } catch {
      message.error('enrollment JSON 格式错误');
      return;
    }
    if (!enrollment || typeof enrollment !== 'object') {
      message.error('请上传或粘贴 node-enrollment.json 全文');
      return;
    }
    const masterUrl = enrollMasterUrl.value.trim();
    if (masterUrl && !isValidEnrollMasterUrl(masterUrl)) {
      message.error(
        'master_url 须为完整地址（含 http:// 或 https://），例如 http://127.0.0.1:8090/api，不能仅为 /api',
      );
      return;
    }
    const data = await issueScanNodeCredentials({
      enrollment,
      master_url: enrollMasterUrl.value || undefined,
      label: enrollLabel.value || undefined,
      topology: enrollTopology.value,
    });
    if (data.encrypted && data.envelope) {
      enrollResultMode.value = 'encrypted';
      enrollResultMain.value = JSON.stringify(data.envelope, null, 2);
      enrollDecryptHint.value =
        '在节点上（与 enroll 生成的 .key 同机）将上方 JSON 保存为文件（如 credentials.enc.json），再执行：\n' +
        '  Linux/macOS: agent decrypt-credentials -envelope credentials.enc.json -key node-enrollment.key -out node-agent.credentials.json\n' +
        '  Windows:     agent.exe decrypt-credentials -envelope credentials.enc.json -key node-enrollment.key -out node-agent.credentials.json\n' +
        '然后设置环境变量 AGENT_CREDENTIALS_FILE 指向解密后的 node-agent.credentials.json，并直接运行 agent（无子命令）。';
      message.success('已签发加密包（响应中无明文 secret）');
      pushEnrollHistory({
        at: new Date().toISOString(),
        label: enrollLabel.value.trim() || '-',
        masterUrl: enrollMasterUrl.value.trim() || '-',
        mode: 'encrypted',
        envelopeJson: enrollResultMain.value,
      });
    } else if (data.credentials) {
      enrollResultMode.value = 'plaintext';
      enrollResultMain.value = JSON.stringify(data.credentials, null, 2);
      enrollDecryptHint.value =
        '当前 enrollment 未包含公钥（旧格式），主控返回明文凭据。请将上方 JSON 保存到节点并配置 AGENT_CREDENTIALS_FILE；生产环境请使用 agent enroll 重新生成含公钥的 enrollment。';
      message.success('已签发明文凭据（请妥善保管）');
      const nodeUuid = String(data.credentials.node_uuid ?? '').trim();
      pushEnrollHistory({
        at: new Date().toISOString(),
        label: enrollLabel.value.trim() || '-',
        masterUrl: enrollMasterUrl.value.trim() || '-',
        mode: 'plaintext',
        nodeUuid: nodeUuid || undefined,
      });
    } else {
      message.warning('响应格式异常');
      enrollResultMode.value = 'error';
      enrollResultMain.value = JSON.stringify(data, null, 2);
      enrollDecryptHint.value = '';
      pushEnrollHistory({
        at: new Date().toISOString(),
        label: enrollLabel.value.trim() || '-',
        masterUrl: enrollMasterUrl.value.trim() || '-',
        mode: 'error',
        detailSnippet: enrollResultMain.value.slice(0, 280),
      });
      return;
    }
    clusterTab.value = 'onboard';
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || String(e));
  } finally {
    enrollSubmitting.value = false;
  }
}

watch(clusterTab, (tab) => {
  if (tab === 'onboard' && !km.value && !kmLoading.value) {
    void loadKnowledgeManifest();
  }
});

onMounted(() => {
  loadEnrollHistory();
  void handleRefresh();
  setupRefreshTimer();
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
});
</script>

<template>
  <Page
    title="节点管理"
    description="统一查看本地引擎、扫描节点与监测节点的运行状态、资源占用与接入配置"
    content-class="nodes-page-content"
  >
    <NCard size="small" class="cluster-shell" :bordered="true">
      <NTabs v-model:value="clusterTab" type="line" animated class="cluster-tabs">
        <NTabPane name="nodes" tab="节点总览">
          <NGrid
            cols="2 s:3 m:6"
            :x-gap="12"
            :y-gap="12"
            responsive="screen"
            class="summary-grid"
          >
          <NGi v-for="card in statCards" :key="card.key">
            <div class="stat-card" :class="`stat-card--${statAccentMap[card.tone] || 'blue'}`">
              <div class="stat-card__icon">
                <IconifyIcon :icon="card.icon" class="text-2xl" />
              </div>
              <div class="stat-card__body">
                <div class="stat-card__value">{{ card.value }}</div>
                <div class="stat-card__label">{{ card.label }}</div>
                <div class="stat-card__sub">{{ card.sub }}</div>
              </div>
            </div>
          </NGi>
          </NGrid>

          <NDivider class="overview-divider" />

          <div class="overview-list-section">
            <div class="overview-list-header">
              <NSpace align="center" :size="8">
                <span class="overview-list-header__title">节点列表</span>
                <NTag size="small" :bordered="false" type="info">
                  {{ filteredNodes.length }} / {{ nodes.length }}
                </NTag>
              </NSpace>
              <NSpace :size="8" align="center" wrap class="overview-list-header__actions">
                <span class="refresh-meta__text">{{ lastRefreshText }}</span>
                <NSwitch :value="autoRefresh" size="small" @update:value="onAutoRefreshChange" />
                <span class="refresh-meta__label">自动刷新</span>
                <NButton size="small" :loading="loading" @click="handleRefresh">刷新</NButton>
                <NButton size="small" type="primary" @click="clusterTab = 'onboard'">接入节点</NButton>
              </NSpace>
            </div>
            <div class="filter-bar filter-bar--in-panel">
              <NInput
              v-model:value="searchKeyword"
              size="small"
              clearable
              placeholder="搜索名称 / IP / 主机名"
              class="filter-bar__search"
            >
              <template #prefix>
                <IconifyIcon icon="lucide:search" class="input-prefix-icon" />
              </template>
            </NInput>
            <NSelect
              v-model:value="filterType"
              size="small"
              clearable
              placeholder="节点类型"
              class="filter-bar__select"
              :options="typeFilterOptions"
            />
            <NSelect
              v-model:value="filterStatus"
              size="small"
              clearable
              placeholder="状态"
              class="filter-bar__select filter-bar__select--narrow"
              :options="statusFilterOptions"
            />
            <NButton size="small" quaternary @click="resetNodeFilters">重置筛选</NButton>
            </div>

            <NSpin :show="loading" class="node-grid-spin">
          <NGrid
            v-if="filteredNodes.length"
            cols="1 s:2 xl:3"
            :x-gap="16"
            :y-gap="16"
            responsive="screen"
            class="node-card-grid"
          >
            <NGi v-for="node in filteredNodes" :key="node.id">
              <NCard size="small" hoverable class="node-item-card">
                <div class="node-item-card__head">
                  <div class="node-item-card__title-row">
                    <span
                      class="node-item-card__type"
                      :style="{ '--node-type-color': nodeTypeColor(node.type) }"
                    >
                      {{ typeLabels[node.type] ?? node.type }}
                    </span>
                    <NTag
                      size="small"
                      round
                      :bordered="false"
                      :type="(statusConfig[node.status]?.type as any) || 'default'"
                    >
                      {{ statusConfig[node.status]?.label || node.status }}
                    </NTag>
                  </div>
                  <div class="node-item-card__name">{{ nodeDisplayTitle(node) }}</div>
                  <div class="node-item-card__sub">{{ nodeDisplaySub(node) }}</div>
                </div>
                <div class="node-item-card__metrics">
                  <div class="node-item-card__metric">
                    <span>CPU</span>
                    <NProgress
                      type="line"
                      :percentage="Math.round(node.cpu_usage)"
                      :height="6"
                      :show-indicator="false"
                      :status="resourceProgressStatus(node.cpu_usage)"
                    />
                    <span class="node-item-card__pct">{{ Math.round(node.cpu_usage) }}%</span>
                  </div>
                  <div class="node-item-card__metric">
                    <span>内存</span>
                    <NProgress
                      type="line"
                      :percentage="Math.round(node.mem_usage)"
                      :height="6"
                      :show-indicator="false"
                      :status="resourceProgressStatus(node.mem_usage)"
                    />
                    <span class="node-item-card__pct">{{ Math.round(node.mem_usage) }}%</span>
                  </div>
                </div>
                <div class="node-item-card__footer">
                  <div class="node-item-card__stats">
                    <span>负载 {{ node.active_tasks }}/{{ node.capacity || '-' }}</span>
                    <span>健康 {{ Math.round(node.health_score) }}%</span>
                    <NTooltip trigger="hover">
                      <template #trigger>
                        <span class="node-item-card__heartbeat">{{ fmtRelative(node.last_heartbeat) }}</span>
                      </template>
                      {{ fmtTime(node.last_heartbeat) }}
                    </NTooltip>
                  </div>
                  <NSpace :size="4">
                    <NButton size="tiny" tertiary type="primary" @click="openNodeDetail(node)">详情</NButton>
                    <NPopconfirm
                      v-if="canShutdownNode(node)"
                      @positive-click="handleShutdownAgent(node.id)"
                    >
                      <template #trigger>
                        <NButton size="tiny" tertiary>停止</NButton>
                      </template>
                      向在线监测节点发送停止指令？
                    </NPopconfirm>
                    <NPopconfirm
                      v-if="canDeleteNode(node)"
                      @positive-click="handleDeleteNode(node)"
                    >
                      <template #trigger>
                        <NButton size="tiny" tertiary type="error">删除</NButton>
                      </template>
                      确定从列表中删除该节点记录？删除后需重新签发凭据才能再次接入。
                    </NPopconfirm>
                  </NSpace>
                </div>
              </NCard>
            </NGi>
          </NGrid>
          <NCard v-else size="small" class="node-empty-card">
            <NEmpty description="暂无匹配的节点">
              <template #extra>
                <NSpace vertical :size="8" align="center">
                  <span class="node-empty__hint">
                    {{ nodes.length ? '请调整筛选条件' : '部署扫描节点后，将在此统一展示' }}
                  </span>
                  <NButton
                    v-if="!nodes.length"
                    type="primary"
                    size="small"
                    @click="clusterTab = 'onboard'"
                  >
                    去接入与签发
                  </NButton>
                  <NButton v-else size="small" @click="resetNodeFilters">清除筛选</NButton>
                </NSpace>
              </template>
            </NEmpty>
          </NCard>
            </NSpin>
          </div>
        </NTabPane>

        <NTabPane name="onboard" tab="接入与签发">
          <div class="onboard-stack">
        <NCard size="small" class="panel-card panel-card--flow panel-card--nested" title="扫描节点接入">
          <template #header-extra>
            <NSpace :size="8">
              <NButton type="primary" @click="openEnrollModal">签发凭据</NButton>
              <NButton quaternary @click="clusterTab = 'nodes'">查看节点</NButton>
            </NSpace>
          </template>
          <p class="panel-card__lead">
            同一 agent 完成 enroll → 主控签发 → decrypt-credentials → agent run；secret 仅在节点本地解密后出现。
          </p>
          <NGrid cols="1 m:3" :x-gap="12" :y-gap="12" responsive="screen">
            <NGi v-for="(step, idx) in onboardSteps" :key="idx">
              <div class="step-card">
                <div class="step-card__icon">
                  <IconifyIcon :icon="step.icon" />
                </div>
                <div class="step-card__index">步骤 {{ idx + 1 }}</div>
                <div class="step-card__title">{{ step.title }}</div>
                <p class="step-card__desc">{{ step.desc }}</p>
                <code v-if="step.cmd" class="step-card__cmd">{{ step.cmd }}</code>
              </div>
            </NGi>
          </NGrid>
        </NCard>

        <NGrid
          v-if="kmMetricCards.length"
          cols="2 s:4"
          :x-gap="12"
          :y-gap="12"
          responsive="screen"
          class="km-grid"
        >
          <NGi v-for="m in kmMetricCards" :key="m.key">
            <div class="metric-card">
              <div class="metric-card__icon">
                <IconifyIcon :icon="m.icon" />
              </div>
              <div class="metric-card__label">{{ m.label }}</div>
              <div class="metric-card__value" :class="{ 'metric-card__value--sm': m.small }">{{ m.value }}</div>
            </div>
          </NGi>
        </NGrid>
        <div v-else-if="!kmLoading" class="metric-card metric-card--empty km-grid">
          <NEmpty size="small" description="知识库版本未加载" />
          <NButton size="tiny" class="mt-2" @click="loadKnowledgeManifest">加载</NButton>
        </div>
        <div v-if="kmLoading" class="km-loading-hint">
          <NSpin size="small" /> 正在加载知识库版本…
        </div>

        <NCard v-if="enrollHistory.length > 0" size="small" class="panel-card panel-card--nested" title="本机签发历史">
          <template #header-extra>
            <NPopconfirm @positive-click="clearEnrollHistory">
              <template #trigger>
                <NButton size="tiny" quaternary>清空</NButton>
              </template>
              清空全部本地记录？
            </NPopconfirm>
          </template>
          <p class="panel-card__lead">
            保存在浏览器 localStorage，可重复下载 envelope；不保存明文凭据 secret。
          </p>
          <div class="history-card-list">
            <div v-for="row in enrollHistory" :key="row.id" class="history-item-card">
              <div class="history-item-card__main">
                <div class="history-item-card__top">
                  <NTag
                    size="small"
                    :bordered="false"
                    :type="row.mode === 'encrypted' ? 'info' : row.mode === 'plaintext' ? 'warning' : 'error'"
                  >
                    {{ enrollModeLabels[row.mode] }}
                  </NTag>
                  <span class="history-item-card__time">{{ fmtTime(row.at) }}</span>
                </div>
                <p class="history-item-card__sum">{{ enrollHistorySummary(row) }}</p>
                <p v-if="row.masterUrl" class="history-item-card__url">{{ row.masterUrl }}</p>
              </div>
              <NSpace :size="4" class="history-item-card__actions">
                <NButton
                  v-if="row.envelopeJson"
                  size="tiny"
                  tertiary
                  @click="downloadEnvelopeHistory(row)"
                >
                  下载
                </NButton>
                <NButton
                  v-if="row.nodeUuid"
                  size="tiny"
                  tertiary
                  @click="copyText(row.nodeUuid!)"
                >
                  复制 UUID
                </NButton>
                <NPopconfirm @positive-click="removeEnrollHistoryRow(row.id)">
                  <template #trigger>
                    <NButton size="tiny" tertiary type="error">删除</NButton>
                  </template>
                  删除此记录？
                </NPopconfirm>
              </NSpace>
            </div>
          </div>
        </NCard>
        <NCard v-else size="small" class="panel-card panel-card--nested panel-card--muted">
          <NEmpty description="暂无签发历史">
            <template #extra>
              <NButton type="primary" size="small" @click="openEnrollModal">立即签发</NButton>
            </template>
          </NEmpty>
        </NCard>

        <NCard size="small" class="panel-card panel-card--nested panel-card--muted" title="节点侧 API 与 Nuclei 回源">
          <p class="api-docs">
            请求 node-api 时携带 <code>X-Agent-Token</code>（节点 UUID）与
            <code>X-Agent-Secret</code>（若已配置）。
          </p>
          <pre class="api-docs__pre">{{ nodeKnowledgeApiPrefix }}/manifest
{{ nodeKnowledgeApiPrefix }}/sync/poc?since_version=0&limit=500
{{ nodeKnowledgeApiPrefix }}/sync/fingerprint?since_version=0&limit=500
{{ nodeKnowledgeApiPrefix }}/sync/rule?since_version=0&limit=500</pre>
          <p class="api-docs__note">
            可配置 <code>VULNSCAN_MASTER_API_BASE</code> 等环境变量实现 Nuclei 自动回源。
          </p>
        </NCard>
          </div>
        </NTabPane>
      </NTabs>
    </NCard>

    <NModal
      v-model:show="showEnrollModal"
      preset="card"
      title="签发扫描节点凭据"
      style="width: min(92vw, 800px)"
      :mask-closable="false"
    >
      <input
        ref="enrollFileInputRef"
        type="file"
        accept=".json,application/json"
        style="display: none"
        @change="onEnrollmentFileSelected"
      />
      <div class="enroll-modal-body">
        <div>
          <div class="enroll-field-label">
            <span>节点 enrollment（JSON）</span>
            <NSpace :size="8">
              <NButton size="tiny" tertiary @click="triggerEnrollmentFilePick">从本机选择文件</NButton>
            </NSpace>
          </div>
          <NInput
            v-model:value="enrollJson"
            type="textarea"
            placeholder="粘贴 node-enrollment.json 全文，或点击「从本机选择文件」"
            :autosize="{ minRows: 8, maxRows: 16 }"
          />
        </div>
        <div>
          <div class="enroll-field-label">部署拓扑与节点访问主控地址（须含 /api）</div>
          <NRadioGroup v-model:value="enrollTopology" style="margin-bottom: 12px" @update:value="onTopologyChange">
            <NSpace vertical :size="8">
              <NRadio
                v-for="mode in connectivityModes"
                :key="mode.id"
                :value="mode.id"
                :disabled="!mode.supported"
              >
                {{ mode.title }}
              </NRadio>
            </NSpace>
          </NRadioGroup>
          <NAlert
            v-if="activeTopologyMode"
            type="info"
            :bordered="false"
            style="margin-bottom: 12px"
            :title="activeTopologyMode.summary"
          >
            <div style="font-size: 12px; line-height: 1.6">
              <p><strong>节点侧：</strong>{{ activeTopologyMode.node_requirement }}</p>
              <p><strong>主控侧：</strong>{{ activeTopologyMode.master_requirement }}</p>
            </div>
          </NAlert>
          <NInput
            v-model:value="enrollMasterUrl"
            placeholder="本地开发：http://127.0.0.1:8090/api（须含协议与端口）"
          />
        </div>
        <div>
          <div class="enroll-field-label">节点显示名称（可选）</div>
          <NInput v-model:value="enrollLabel" placeholder="例如：华东扫描-01" />
        </div>
        <NSpace>
          <NButton type="primary" :loading="enrollSubmitting" @click="submitIssueScan">签发</NButton>
          <NButton quaternary @click="showEnrollModal = false">关闭</NButton>
        </NSpace>

        <template v-if="enrollResultMode !== 'none'">
          <NDivider style="margin: 4px 0" />
          <NAlert
            v-if="enrollResultMode === 'encrypted'"
            type="info"
            title="加密包（envelope）"
            style="margin-bottom: 10px"
          >
            请复制下方 JSON 到节点保存为文件，再使用与 enroll 时同名的 <code>.key</code> 私钥解密。主控浏览器与网络路径上不会出现明文 secret。
          </NAlert>
          <NAlert
            v-else-if="enrollResultMode === 'plaintext'"
            type="warning"
            title="明文凭据（兼容旧 enrollment）"
            style="margin-bottom: 10px"
          >
            当前 enrollment 未带公钥，主控只能返回明文。生产环境请使用最新 <code>agent enroll</code> 重新生成后再签发。
          </NAlert>
          <NAlert v-else type="error" title="非预期响应" style="margin-bottom: 10px">
            未识别到 credentials 或 envelope 字段，以下为原始 JSON 便于排查。
          </NAlert>
          <div class="enroll-field-label">
            <span>{{
              enrollResultMode === 'encrypted'
                ? 'envelope JSON（可复制保存）'
                : enrollResultMode === 'error'
                  ? '原始响应 JSON'
                  : '凭据 JSON（可复制保存）'
            }}</span>
            <NSpace :size="8">
              <NButton size="tiny" tertiary @click="copyIssueResult">复制全文</NButton>
              <NButton
                v-if="enrollResultMode === 'encrypted'"
                size="tiny"
                type="primary"
                ghost
                @click="downloadCurrentEnvelope"
              >
                下载 .enc.json
              </NButton>
            </NSpace>
          </div>
          <NInput :value="enrollResultMain" type="textarea" readonly :autosize="{ minRows: 6, maxRows: 14 }" />
          <div v-if="enrollDecryptHint" class="enroll-hint">{{ enrollDecryptHint }}</div>
        </template>
      </div>
    </NModal>

    <NDrawer v-model:show="showDetailDrawer" :width="480" placement="right">
      <NDrawerContent
        v-if="detailNode"
        :title="detailNode.label || detailNode.name || detailNode.hostname || '节点详情'"
        closable
      >
        <NDescriptions label-placement="left" :column="1" bordered size="small">
          <NDescriptionsItem label="类型">
            {{ typeLabels[detailNode.type] || detailNode.type }}
          </NDescriptionsItem>
          <NDescriptionsItem label="状态">
            <NTag
              size="small"
              :type="(statusConfig[detailNode.status]?.type as any) || 'default'"
              :bordered="false"
            >
              {{ statusConfig[detailNode.status]?.label || detailNode.status }}
            </NTag>
          </NDescriptionsItem>
          <NDescriptionsItem label="节点 ID">
            <span class="mono-text">{{ detailNode.id }}</span>
          </NDescriptionsItem>
          <NDescriptionsItem label="IP">{{ detailNode.ip || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="主机名">{{ detailNode.hostname || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="版本">{{ detailNode.version || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="健康度">{{ Math.round(detailNode.health_score) }}%</NDescriptionsItem>
          <NDescriptionsItem label="CPU / 内存">
            {{ Math.round(detailNode.cpu_usage) }}% / {{ Math.round(detailNode.mem_usage) }}%
          </NDescriptionsItem>
          <NDescriptionsItem label="负载">
            {{ detailNode.active_tasks }} / {{ detailNode.capacity || '-' }}
            <template v-if="(detailNode.queued_tasks ?? 0) > 0">
              （队列 {{ detailNode.queued_tasks }}）
            </template>
          </NDescriptionsItem>
          <NDescriptionsItem label="最近心跳">
            {{ fmtTime(detailNode.last_heartbeat) }}
            <span class="text-muted">（{{ fmtRelative(detailNode.last_heartbeat) }}）</span>
          </NDescriptionsItem>
          <NDescriptionsItem v-if="detailNode.registered_at" label="注册时间">
            {{ fmtTime(detailNode.registered_at) }}
          </NDescriptionsItem>
        </NDescriptions>
      </NDrawerContent>
    </NDrawer>
  </Page>
</template>

<style scoped>

/* 统计卡片 */
.stat-card {
  display: flex;
  align-items: center;
  padding: 18px 20px;
  border-radius: 12px;
  background: linear-gradient(135deg, #fff 0%, #f8fafc 100%);
  border: 1px solid var(--n-border-color);
  border-left-width: 4px;
  height: 100%;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgb(0 0 0 / 8%);
}

.stat-card--blue { border-left-color: #3b82f6; }
.stat-card--blue .stat-card__icon { color: #3b82f6; }
.stat-card--green { border-left-color: #22c55e; }
.stat-card--green .stat-card__icon { color: #22c55e; }
.stat-card--orange { border-left-color: #f59e0b; }
.stat-card--orange .stat-card__icon { color: #f59e0b; }
.stat-card--slate { border-left-color: #94a3b8; }
.stat-card--slate .stat-card__icon { color: #94a3b8; }

.stat-card__icon {
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  opacity: 0.85;
}

.stat-card__body {
  flex: 1;
  min-width: 0;
  padding-left: 14px;
}

.stat-card__value {
  font-size: 26px;
  font-weight: 700;
  line-height: 1.2;
}

.stat-card__label {
  font-size: 13px;
  font-weight: 500;
  margin-top: 2px;
}

.stat-card__sub {
  font-size: 11px;
  color: var(--n-text-color-3);
  margin-top: 4px;
  line-height: 1.4;
}

/* 与 Page 标题区 px-6 对齐；覆盖默认 p-4 */
:global(.nodes-page-content) {
  padding: 12px 24px 24px !important;
}

.cluster-tabs :deep(.n-tabs-nav) {
  padding-left: 0;
  margin-left: 0;
}

.cluster-tabs :deep(.n-tabs-pane-wrapper) {
  padding: 0;
}

.cluster-shell {
  width: 100%;
}

.cluster-shell :deep(.n-card__content) {
  padding-top: 8px;
}

.cluster-shell .cluster-tabs :deep(.n-tabs-nav) {
  margin-bottom: 4px;
}

.cluster-shell .summary-grid {
  margin-bottom: 0;
}

.panel-card--nested {
  margin-bottom: 0;
}

.onboard-stack {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.overview-divider {
  margin: 16px 0;
}

.overview-list-section {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.overview-list-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}

.overview-list-header__title {
  font-size: 14px;
  font-weight: 600;
}

.filter-bar--in-panel {
  margin-bottom: 0;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--n-border-color);
}

/* 节点卡片 */
.node-grid-spin {
  display: block;
  margin-top: 12px;
}

.node-item-card {
  height: 100%;
}

.node-item-card :deep(.n-card__content) {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.node-item-card__title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 6px;
}

.node-item-card__type {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  background: color-mix(in srgb, var(--node-type-color) 12%, transparent);
  color: var(--node-type-color);
}

.node-item-card__name {
  font-size: 15px;
  font-weight: 600;
  line-height: 1.35;
  word-break: break-word;
  color: var(--n-text-color);
}

.node-item-card__sub {
  margin-top: 4px;
  font-size: 12px;
  color: var(--n-text-color-3);
}

.node-item-card__metrics {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.node-item-card__metric {
  display: grid;
  grid-template-columns: 32px 1fr 36px;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--n-text-color-3);
}

.node-item-card__pct {
  text-align: right;
  font-variant-numeric: tabular-nums;
}

.node-item-card__footer {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-top: 10px;
  border-top: 1px dashed var(--n-border-color);
}

.node-item-card__stats {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 12px;
  font-size: 12px;
  color: var(--n-text-color-2);
}

.node-item-card__heartbeat {
  color: var(--n-text-color-3);
  cursor: default;
}

.node-empty-card {
  margin-top: 16px;
}

/* 接入页 */
.panel-card {
  margin-bottom: 16px;
}

.panel-card--muted {
  background: var(--n-color-modal);
}

.panel-card__lead {
  margin: 0 0 14px;
  font-size: 13px;
  line-height: 1.6;
  color: var(--n-text-color-2);
}

.step-card {
  height: 100%;
  padding: 16px;
  border-radius: 10px;
  border: 1px solid var(--n-border-color);
  background: var(--card-color, var(--n-color-embedded, #fff));
}

.step-card__icon {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  color: var(--n-primary-color);
  background: rgb(24 144 255 / 10%);
  margin-bottom: 10px;
}

.step-card__index {
  font-size: 11px;
  font-weight: 600;
  color: var(--n-primary-color);
  margin-bottom: 4px;
}

.step-card__title {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 6px;
}

.step-card__desc {
  margin: 0 0 8px;
  font-size: 12px;
  line-height: 1.55;
  color: var(--n-text-color-2);
}

.step-card__cmd {
  display: block;
  padding: 8px;
  border-radius: 6px;
  font-size: 11px;
  line-height: 1.45;
  word-break: break-all;
  background: var(--n-code-color, #f6f8fa);
  user-select: all;
}

.metric-card {
  padding: 14px 16px;
  border-radius: 10px;
  border: 1px solid var(--n-border-color);
  background: var(--card-color, var(--n-color-embedded, #fff));
  height: 100%;
}

.metric-card__icon {
  font-size: 18px;
  color: var(--n-primary-color);
  margin-bottom: 8px;
}

.metric-card__label {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 4px;
}

.metric-card__value {
  font-size: 22px;
  font-weight: 700;
  line-height: 1.2;
}

.metric-card__value--sm {
  font-size: 12px;
  font-weight: 500;
  word-break: break-all;
}

.metric-card--empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100px;
}

.km-grid {
  margin-bottom: 8px;
}

.km-loading-hint {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 16px;
}

.history-card-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.history-item-card {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 14px;
  border-radius: 10px;
  border: 1px solid var(--n-border-color);
  background: var(--n-color-modal);
}

.history-item-card__top {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.history-item-card__time {
  font-size: 12px;
  color: var(--n-text-color-3);
}

.history-item-card__sum {
  margin: 8px 0 0;
  font-size: 13px;
  font-weight: 500;
}

.history-item-card__url {
  margin: 4px 0 0;
  font-size: 11px;
  color: var(--n-text-color-3);
  word-break: break-all;
}

.history-item-card__actions {
  flex-shrink: 0;
}

.api-docs {
  margin: 0 0 10px;
  font-size: 13px;
  line-height: 1.6;
}

.api-docs__pre {
  margin: 0 0 10px;
  padding: 12px;
  border-radius: 8px;
  background: var(--n-code-color, #f6f8fa);
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  word-break: break-all;
}

.api-docs__note {
  margin: 0;
  font-size: 12px;
  color: var(--n-text-color-3);
}

.api-docs code {
  padding: 0 4px;
  border-radius: 4px;
  background: var(--n-action-color);
  font-size: 12px;
}

.cluster-tabs {
  width: 100%;
}

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--n-border-color);
}

.filter-bar__search {
  width: min(100%, 240px);
  flex: 1 1 200px;
}

.filter-bar__select {
  width: 130px;
}

.filter-bar__select--narrow {
  width: 110px;
}

.node-empty__hint {
  font-size: 12px;
  color: var(--n-text-color-3);
}

.input-prefix-icon {
  font-size: 14px;
  color: var(--n-text-color-3);
}

.refresh-meta__text,
.refresh-meta__label {
  font-size: 12px;
  color: var(--n-text-color-3);
}

.mono-text {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  word-break: break-all;
}

.text-muted {
  color: var(--n-text-color-3);
  font-size: 12px;
}

.enroll-modal-body {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.enroll-field-label {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 6px;
  font-weight: 500;
  font-size: 13px;
}

.enroll-hint {
  margin-top: 10px;
  padding: 10px 12px;
  border-radius: 8px;
  background: var(--n-color-target, #f7f7f8);
  border: 1px solid var(--n-border-color);
  font-family: ui-monospace, monospace;
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  word-break: break-word;
}

.nodes-page {
  width: 100%;
}

.node-list-card__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  width: 100%;
}

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--n-border-color);
}

.filter-bar__search {
  width: min(100%, 240px);
  flex: 1 1 200px;
}

.filter-bar__select {
  width: 130px;
}

.filter-bar__select--narrow {
  width: 110px;
}

.onboard-grid {
  margin-bottom: 16px;
}

.onboard-card {
  height: 100%;
}

.onboard-alert {
  margin-bottom: 14px;
}

.onboard-steps {
  display: flex;
  flex-direction: column;
  gap: 14px;
  margin-bottom: 16px;
}

.onboard-step {
  display: flex;
  gap: 12px;
  align-items: flex-start;
}

.onboard-step__index {
  flex-shrink: 0;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  font-weight: 600;
  background: rgb(24 144 255 / 12%);
  color: #1890ff;
}

.onboard-step__title {
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 4px;
}

.onboard-step__desc {
  margin: 0 0 6px;
  font-size: 13px;
  line-height: 1.55;
  color: var(--n-text-color-2);
}

.onboard-step__cmd {
  display: block;
  padding: 8px 10px;
  border-radius: 6px;
  background: var(--n-code-color, #f6f8fa);
  font-size: 12px;
  line-height: 1.5;
  word-break: break-all;
  user-select: all;
}

.onboard-actions {
  margin-top: 4px;
}

.km-metric {
  padding: 10px 12px;
  border-radius: 8px;
  border: 1px solid var(--n-border-color);
}

.km-metric__label {
  display: block;
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 4px;
}

.km-metric__value {
  font-size: 20px;
  font-weight: 700;
}

.km-metric__value--sm {
  font-size: 12px;
  font-weight: 500;
  word-break: break-all;
}

.onboard-history-card,
.onboard-history-empty {
  margin-bottom: 16px;
}

.api-docs {
  font-size: 13px;
  line-height: 1.6;
  color: var(--n-text-color-2);
}

.api-docs__pre {
  margin: 10px 0;
  padding: 12px;
  border-radius: 8px;
  background: var(--n-code-color, #f6f8fa);
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  word-break: break-all;
}

.api-docs__note {
  margin: 0;
  font-size: 12px;
  color: var(--n-text-color-3);
}

.api-docs code {
  padding: 0 4px;
  border-radius: 4px;
  background: var(--n-action-color);
  font-size: 12px;
}
.cluster-tabs {
  margin-bottom: 4px;
}

.onboard-stack {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.summary-grid {
  margin-bottom: 16px;
}

.stat-card {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 14px 16px;
  border-radius: 10px;
  border: 1px solid var(--n-border-color);
  background: linear-gradient(135deg, var(--card-color, #fff) 0%, var(--n-color-embedded, #f8fafc) 100%);
  height: 100%;
  transition: box-shadow 0.2s ease, border-color 0.2s ease;
}

.stat-card:hover {
  box-shadow: 0 4px 14px rgb(0 0 0 / 6%);
}

.stat-card--blue {
  border-left: 4px solid #3b82f6;
}

.stat-card--blue .stat-card__icon {
  color: #3b82f6;
}

.stat-card--green {
  border-left: 4px solid #22c55e;
}

.stat-card--green .stat-card__icon {
  color: #22c55e;
}

.stat-card--orange {
  border-left: 4px solid #f59e0b;
}

.stat-card--orange .stat-card__icon {
  color: #f59e0b;
}

.stat-card--slate {
  border-left: 4px solid #94a3b8;
}

.stat-card--slate .stat-card__icon {
  color: #94a3b8;
}

.stat-card__icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: 8px;
  font-size: 18px;
  flex-shrink: 0;
  background: var(--n-action-color);
  color: var(--n-text-color-2);
}

.stat-card--success .stat-card__icon {
  background: rgb(82 196 26 / 12%);
  color: #52c41a;
}

.stat-card--success .stat-card__value {
  color: #52c41a;
}

.stat-card--warning .stat-card__icon {
  background: rgb(237 137 54 / 12%);
  color: #ed8936;
}

.stat-card--warning .stat-card__value {
  color: #ed8936;
}

.stat-card--info .stat-card__icon {
  background: rgb(24 144 255 / 12%);
  color: #1890ff;
}

.stat-card--info .stat-card__value {
  color: #1890ff;
}

.stat-card--muted .stat-card__value {
  color: var(--n-text-color-3);
}

.stat-card__value {
  font-size: 24px;
  font-weight: 700;
  line-height: 1.2;
}

.stat-card__label {
  font-size: 13px;
  font-weight: 500;
  margin-top: 2px;
}

.stat-card__sub {
  font-size: 11px;
  color: var(--n-text-color-3);
  margin-top: 4px;
  line-height: 1.4;
}

.node-list-card__title {
  font-weight: 600;
}

.node-toolbar {
  max-width: 100%;
}

.refresh-meta__text {
  font-size: 12px;
  color: var(--n-text-color-3);
  white-space: nowrap;
}

.refresh-meta__label {
  font-size: 12px;
  color: var(--n-text-color-3);
}

.input-prefix-icon {
  font-size: 14px;
  color: var(--n-text-color-3);
}

.node-empty {
  padding: 32px 0;
}

.node-empty__hint {
  font-size: 12px;
  color: var(--n-text-color-3);
}

.node-cell__head {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.node-cell__type {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  white-space: nowrap;
  background: color-mix(in srgb, var(--node-type-color) 12%, transparent);
  color: var(--node-type-color);
}

.node-cell__name {
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.node-cell__sub {
  display: block;
  margin-top: 4px;
  font-size: 11px;
  color: var(--n-text-color-3);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.resource-bars {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.resource-bars__row {
  display: flex;
  align-items: center;
  gap: 6px;
}

.resource-bars__label {
  width: 28px;
  font-size: 11px;
  color: var(--n-text-color-3);
  flex-shrink: 0;
}

.resource-bars__pct {
  width: 32px;
  font-size: 11px;
  text-align: right;
  color: var(--n-text-color-2);
  flex-shrink: 0;
}

.load-cell__main {
  font-size: 13px;
  font-weight: 600;
}

.load-cell__sub {
  display: block;
  margin-top: 2px;
  font-size: 11px;
  color: var(--n-text-color-3);
}

.health-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.health-cell__meta {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}

.health-cell__time {
  font-size: 11px;
  color: var(--n-text-color-3);
  cursor: default;
}

.mono-text {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  word-break: break-all;
}

.text-muted {
  color: var(--n-text-color-3);
  font-size: 12px;
}

.enroll-modal-body {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.enroll-field-label {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 6px;
  font-weight: 500;
  font-size: 13px;
  color: var(--n-text-color);
}

.enroll-hint {
  margin-top: 10px;
  padding: 10px 12px;
  border-radius: 8px;
  background: var(--n-color-target, #f7f7f8);
  border: 1px solid var(--n-border-color, #e8e8e8);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  word-break: break-word;
  color: #555;
}
</style>
