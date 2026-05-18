<script lang="ts" setup>
import { h, onMounted, onUnmounted, ref, computed } from 'vue';

import {
  NAlert,
  NButton,
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NDivider,
  NEmpty,
  NInput,
  NModal,
  NPopconfirm,
  NProgress,
  NSelect,
  NSpace,
  NSpin,
  NTabPane,
  NTabs,
  NTag,
  useMessage,
} from 'naive-ui';

import {
  getNodeKnowledgeManifest,
  getUnifiedNodes,
  issueScanNodeCredentials,
  unregisterWorker,
  type NodeKnowledgeManifest,
  type NodeSummary,
  type UnifiedNode,
} from '#/api/cluster';

import { shutdownAgent } from '#/api/sitemonitor';

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
let refreshTimer: ReturnType<typeof setInterval> | null = null;

const apiBase = ((import.meta as any).env?.VITE_GLOB_API_URL as string) || '/api';
const nodeKnowledgeApiPrefix = `${apiBase.replace(/\/$/, '')}/node-api/knowledge`;

const kmLoading = ref(false);
const km = ref<NodeKnowledgeManifest | null>(null);

const showEnrollModal = ref(false);
const enrollJson = ref('');
const enrollMasterUrl = ref(`${apiBase.replace(/\/$/, '')}`);
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
  worker: '扫描节点',
  agent: '监测节点',
};

const statusConfig: Record<string, { type: string; label: string }> = {
  online: { type: 'success', label: '在线' },
  offline: { type: 'default', label: '离线' },
  busy: { type: 'info', label: '繁忙' },
  drain: { type: 'warning', label: '排干' },
};

function fmtTime(raw?: string) {
  if (!raw) return '-';
  const d = new Date(raw);
  if (isNaN(d.getTime())) return raw;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const totalQueuedTasks = computed(() =>
  nodes.value.reduce((sum, n) => sum + (n.queued_tasks ?? 0), 0),
);

const filteredNodes = computed(() => {
  let list = nodes.value;
  if (filterStatus.value) list = list.filter((n) => n.status === filterStatus.value);
  return list;
});

const columns = [
  {
    title: '节点',
    key: 'name',
    minWidth: 160,
    render: (row: UnifiedNode) => {
      const color = row.type === 'local' ? '#722ed1' : row.type === 'worker' ? '#1890ff' : '#52c41a';
      return h('div', { style: 'display:flex;align-items:center;gap:8px' }, [
        h('span', {
          style: `padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;background:${color}12;color:${color};white-space:nowrap`,
        }, typeLabels[row.type] ?? row.type),
        h('span', { style: 'font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap' },
          row.name || row.hostname || row.ip || '-'),
      ]);
    },
  },
  {
    title: '状态',
    key: 'status',
    width: 80,
    render: (row: UnifiedNode) => {
      const cfg = statusConfig[row.status] ?? { type: 'default', label: row.status };
      return h(NTag, { type: cfg.type as any, size: 'small' }, () => cfg.label);
    },
  },
  {
    title: 'CPU',
    key: 'cpu_usage',
    width: 120,
    render: (row: UnifiedNode) =>
      h(NProgress, {
        type: 'line',
        percentage: Math.round(row.cpu_usage),
        height: 16,
        indicatorPlacement: 'inside',
        status: row.cpu_usage > 90 ? 'error' : row.cpu_usage > 70 ? 'warning' : 'success',
      }),
  },
  {
    title: '内存',
    key: 'mem_usage',
    width: 120,
    render: (row: UnifiedNode) =>
      h(NProgress, {
        type: 'line',
        percentage: Math.round(row.mem_usage),
        height: 16,
        indicatorPlacement: 'inside',
        status: row.mem_usage > 90 ? 'error' : row.mem_usage > 70 ? 'warning' : 'success',
      }),
  },
  {
    title: '执行中 / 容量',
    key: 'active_tasks',
    width: 110,
    align: 'center' as const,
    render: (row: UnifiedNode) =>
      h('span', { style: 'font-size:13px;font-weight:500' }, `${row.active_tasks} / ${row.capacity || '-'}`),
  },
  {
    title: '队列',
    key: 'queued_tasks',
    width: 70,
    align: 'center' as const,
    render: (row: UnifiedNode) => {
      const q = row.queued_tasks ?? 0;
      if (q === 0) return h('span', { style: 'color:#999' }, '0');
      return h(NTag, { type: 'warning', size: 'small', round: true }, () => q);
    },
  },
  {
    title: '健康度',
    key: 'health_score',
    width: 80,
    align: 'center' as const,
    render: (row: UnifiedNode) => {
      const score = Math.round(row.health_score);
      const type = score >= 80 ? 'success' : score >= 50 ? 'warning' : 'error';
      return h(NTag, { type: type as any, size: 'small', round: true }, () => `${score}%`);
    },
  },
  {
    title: '心跳',
    key: 'last_heartbeat',
    width: 160,
    render: (row: UnifiedNode) =>
      h('span', { style: 'font-size:12px;color:#666' }, fmtTime(row.last_heartbeat)),
  },
  {
    title: '操作',
    key: 'actions',
    width: 80,
    fixed: 'right' as const,
    render: (row: UnifiedNode) => {
      if (row.type === 'local') {
        return h('span', { style: 'font-size:12px;color:#999' }, '内置');
      }
      if (row.type === 'worker') {
        return h(NPopconfirm, { onPositiveClick: () => handleRemoveWorker(row.id) }, {
          trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '注销'),
          default: () => '确定注销此节点？',
        });
      }
      return h(NPopconfirm, { onPositiveClick: () => handleShutdownAgent(row.id) }, {
        trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '停止'),
        default: () => '确定停止此节点？',
      });
    },
  },
];

async function fetchData() {
  loading.value = true;
  try {
    const result = await getUnifiedNodes() as any;
    nodes.value = result?.nodes ?? [];
    if (result?.summary) summary.value = result.summary;
  } finally {
    loading.value = false;
  }
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

async function handleRemoveWorker(id: string) {
  try {
    await unregisterWorker(id);
    message.success('已注销');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

async function handleShutdownAgent(id: string) {
  try {
    await shutdownAgent(id);
    message.success('已停止');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

function openEnrollModal() {
  enrollResultMode.value = 'none';
  enrollResultMain.value = '';
  enrollDecryptHint.value = '';
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

const historyColumns = [
  {
    title: '时间',
    key: 'at',
    width: 168,
    render: (row: EnrollHistoryItem) =>
      h('span', { style: 'font-size:12px;color:#666' }, fmtTime(row.at)),
  },
  {
    title: '类型',
    key: 'mode',
    width: 88,
    render: (row: EnrollHistoryItem) => {
      const t = row.mode === 'encrypted' ? 'info' : row.mode === 'plaintext' ? 'warning' : 'error';
      return h(NTag, { type: t as any, size: 'small' }, () => enrollModeLabels[row.mode]);
    },
  },
  {
    title: '说明',
    key: 'sum',
    ellipsis: { tooltip: true } as const,
    render: (row: EnrollHistoryItem) => {
      if (row.mode === 'plaintext') return row.nodeUuid ? `节点 ${row.nodeUuid}` : row.label || '-';
      if (row.mode === 'encrypted') return row.label ? `加密 · ${row.label}` : 'RSA 加密 envelope';
      return row.detailSnippet || row.label || '-';
    },
  },
  {
    title: 'master_url',
    key: 'masterUrl',
    width: 200,
    ellipsis: { tooltip: true } as const,
    render: (row: EnrollHistoryItem) => h('span', { style: 'font-size:12px' }, row.masterUrl || '-'),
  },
  {
    title: '操作',
    key: 'actions',
    width: 168,
    render: (row: EnrollHistoryItem) =>
      h(NSpace, { size: 4 }, {
        default: () => {
          const btns: ReturnType<typeof h>[] = [];
          if (row.envelopeJson) {
            btns.push(
              h(NButton, { size: 'tiny', tertiary: true, onClick: () => downloadEnvelopeHistory(row) }, () => '下载'),
            );
          }
          if (row.nodeUuid) {
            btns.push(
              h(NButton, { size: 'tiny', tertiary: true, onClick: () => copyText(row.nodeUuid!) }, () => '复制UUID'),
            );
          }
          btns.push(
            h(
              NPopconfirm,
              { onPositiveClick: () => removeEnrollHistoryRow(row.id) },
              {
                default: () => '删除此记录？',
                trigger: () => h(NButton, { size: 'tiny', tertiary: true, type: 'error' }, () => '删除'),
              },
            ),
          );
          return btns;
        },
      }),
  },
];

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
    const data = await issueScanNodeCredentials({
      enrollment,
      master_url: enrollMasterUrl.value || undefined,
      label: enrollLabel.value || undefined,
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

onMounted(() => {
  loadEnrollHistory();
  void handleRefresh();
  void loadKnowledgeManifest();
  refreshTimer = setInterval(fetchData, 10000);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
});
</script>

<template>
  <div class="nodes-page">
    <NTabs v-model:value="clusterTab" type="line" animated class="cluster-tabs">
      <NTabPane name="nodes" tab="节点总览">
        <div class="summary-grid">
          <div class="summary-card">
            <div class="summary-value">{{ summary.total_nodes }}</div>
            <div class="summary-label">节点总数</div>
          </div>
          <div class="summary-card">
            <div class="summary-value" style="color: #52c41a">{{ summary.online_nodes }}</div>
            <div class="summary-label">在线</div>
          </div>
          <div class="summary-card">
            <div class="summary-value" style="color: #999">{{ summary.offline_nodes }}</div>
            <div class="summary-label">离线</div>
          </div>
          <div class="summary-card">
            <div class="summary-value" style="color: #1890ff">{{ summary.total_tasks }}</div>
            <div class="summary-label">执行中</div>
          </div>
          <div class="summary-card">
            <div class="summary-value" style="color: #ed8936">{{ totalQueuedTasks }}</div>
            <div class="summary-label">队列中</div>
          </div>
          <div class="summary-card">
            <div class="summary-value">{{ summary.total_capacity }}</div>
            <div class="summary-label">总容量</div>
          </div>
        </div>

        <NCard size="small">
          <template #header>
            <span style="font-weight: 600">节点列表</span>
          </template>
          <template #header-extra>
            <NSpace :size="8">
              <NSelect
                v-model:value="filterStatus"
                size="small"
                clearable
                placeholder="状态筛选"
                style="width: 120px"
                :options="[{ label: '在线', value: 'online' }, { label: '繁忙', value: 'busy' }, { label: '离线', value: 'offline' }]"
              />
              <NButton size="small" @click="handleRefresh">刷新</NButton>
            </NSpace>
          </template>
          <NDataTable
            v-if="filteredNodes.length > 0 || loading"
            :columns="columns"
            :data="filteredNodes"
            :loading="loading"
            :bordered="false"
            size="small"
            striped
            :scroll-x="900"
          />
          <NEmpty v-else description="暂无节点" style="padding: 32px 0">
            <template #extra>
              <span style="font-size: 12px; color: #999"> 部署远程节点后，将在此统一展示 </span>
            </template>
          </NEmpty>
        </NCard>
      </NTabPane>

      <NTabPane name="onboard" tab="接入与签发">
        <div class="onboard-stack">
          <NCard size="small" title="扫描节点首次接入（推荐）">
            <NAlert type="success" style="margin-bottom: 12px" title="当前推荐流程">
              节点侧只需<strong>同一个 agent 二进制</strong>：先 <code>enroll</code> 生成申请与私钥，将 <strong>仅 JSON</strong> 交给主控签发；主控返回<strong>加密包</strong>后，在节点再 <code>decrypt-credentials</code> 得到明文凭据并启动代理。
            </NAlert>
            <div style="font-size: 13px; line-height: 1.7; color: #555">
              <ol style="padding-left: 18px; margin: 0">
                <li>
                  在待接入机器上使用<strong>与运行时代理相同的二进制</strong>生成
                  <code>node-enrollment.json</code> 及同目录下的私钥
                  <code>node-enrollment.key</code>（仅 JSON 需交给主控）：<br />
                  <code style="user-select: all">agent enroll -out node-enrollment.json</code>
                  （Linux/macOS；Windows 使用 <code>agent.exe enroll -out node-enrollment.json</code>）
                </li>
                <li>
                  将 <strong>仅 JSON 文件</strong>带到主控签发；主控返回<strong>加密包</strong>（无明文 secret 传输）。在节点用私钥解密为明文凭据后再启动代理。
                </li>
                <li>
                  解密示例：<br />
                  <code style="user-select: all">agent decrypt-credentials -envelope credentials.enc.json -key node-enrollment.key -out node-agent.credentials.json</code>
                </li>
                <li>
                  设置环境变量 <code>AGENT_CREDENTIALS_FILE</code> 指向明文凭据文件后，直接运行
                  <code>agent</code>（无子命令）即可连主控。
                </li>
              </ol>
            </div>
            <NSpace style="margin-top: 12px">
              <NButton size="small" type="primary" @click="openEnrollModal">签发扫描节点凭据</NButton>
            </NSpace>
          </NCard>

          <NCard v-if="enrollHistory.length > 0" size="small" title="本机签发历史">
            <template #header-extra>
              <NPopconfirm @positive-click="clearEnrollHistory">
                <template #trigger>
                  <NButton size="tiny" quaternary>清空</NButton>
                </template>
                清空全部本地记录？（不影响已创建节点）
              </NPopconfirm>
            </template>
            <NAlert type="info" style="margin-bottom: 10px" :bordered="false">
              保存在本浏览器（localStorage），可再次下载加密 envelope；<strong>不保存</strong>明文凭据中的 secret。
            </NAlert>
            <NDataTable
              :columns="historyColumns"
              :data="enrollHistory"
              :row-key="(row: EnrollHistoryItem) => row.id"
              size="small"
              :bordered="false"
            />
          </NCard>
          <NAlert v-else type="info" title="暂无签发历史" style="margin-bottom: 0">
            签发成功后会在此列出；加密签发的 envelope 可在此重复下载到本机。
          </NAlert>

          <NCard size="small">
            <template #header>
              <span style="font-weight: 600">扫描节点知识库同步（主控权威版本）</span>
            </template>
            <template #header-extra>
              <NButton size="tiny" quaternary :loading="kmLoading" @click="loadKnowledgeManifest">刷新版本</NButton>
            </template>
            <NSpin :show="kmLoading && !km">
              <NDescriptions v-if="km" label-placement="left" :column="1" bordered size="small">
                <NDescriptionsItem label="PoC 游标 (poc)">{{ km.versions?.poc ?? 0 }}</NDescriptionsItem>
                <NDescriptionsItem label="指纹游标 (fingerprint)">{{ km.versions?.fingerprint ?? 0 }}</NDescriptionsItem>
                <NDescriptionsItem label="扫描规则游标 (rule)">{{ km.versions?.rule ?? 0 }}</NDescriptionsItem>
                <NDescriptionsItem label="主控时间">{{ km.server_time || '-' }}</NDescriptionsItem>
              </NDescriptions>
              <NEmpty v-else description="暂无数据或无权访问" style="padding: 12px 0" />
            </NSpin>
            <NAlert type="info" style="margin-top: 12px" title="节点侧拉取说明">
              <div style="font-size: 13px; line-height: 1.6">
                扫描代理调用 node-api 时使用请求头
                <code style="padding: 0 4px">X-Agent-Token: &lt;节点 UUID&gt;</code>（或 Query
                <code style="padding: 0 4px">token</code>）。若主控已为该节点下发密钥（库内
                <code>agent_secret_hash</code>），必须同时携带
                <code style="padding: 0 4px">X-Agent-Secret: &lt;明文密钥&gt;</code>（或 Query
                <code style="padding: 0 4px">agent_secret</code>）。在全局 API 前缀下请求：
                <div style="margin-top: 8px; font-family: ui-monospace, monospace; word-break: break-all">
                  GET {{ nodeKnowledgeApiPrefix }}/manifest<br />
                  GET {{ nodeKnowledgeApiPrefix }}/sync/poc?since_version=0&amp;limit=500<br />
                  GET {{ nodeKnowledgeApiPrefix }}/sync/fingerprint?since_version=0&amp;limit=500<br />
                  GET {{ nodeKnowledgeApiPrefix }}/sync/rule?since_version=0&amp;limit=500
                </div>
                响应 JSON 与联邦增量结构一致（items / latest_version / has_more / server_time）；节点将数据写入本地库后即可用现有 Nuclei 物化流程扫描。
                <div style="margin-top: 10px">
                  <strong>Nuclei 自动回源：</strong>本地库无可用 PoC 时，引擎可用环境变量
                  <code>VULNSCAN_MASTER_API_BASE</code>（如 <code>https://主控/api</code>）、
                  <code>VULNSCAN_NODE_AGENT_TOKEN</code>（节点 UUID）及（若主控已配置节点密钥）
                  <code>VULNSCAN_NODE_AGENT_SECRET</code> 请求
                  <code>/node-api/knowledge/sync/poc</code> 写入本地后再加载；仍无则跳过。任务参数可覆盖
                  <code>poc_master_api_base</code>、<code>node_agent_token</code>、<code>node_agent_secret</code>；<code>poc_master_pull_disable: true</code> 关闭。
                </div>
              </div>
            </NAlert>
          </NCard>
        </div>
      </NTabPane>
    </NTabs>

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
          <div class="enroll-field-label">节点访问主控的 API 根地址（须含 /api）</div>
          <NInput v-model:value="enrollMasterUrl" placeholder="例如：https://主控域名/api" />
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
  </div>
</template>

<style scoped>
.cluster-tabs {
  margin-bottom: 4px;
}

.onboard-stack {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 12px;
  margin-bottom: 16px;
}

.summary-card {
  background: var(--card-color, #fff);
  border-radius: 10px;
  padding: 16px;
  text-align: center;
  border: 1px solid var(--border-color, #eee);
}

.summary-value {
  font-size: 28px;
  font-weight: 700;
  line-height: 1.2;
}

.summary-label {
  font-size: 12px;
  color: #999;
  margin-top: 4px;
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
