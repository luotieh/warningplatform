<script lang="ts" setup>
import { h, onMounted, onUnmounted, ref, computed } from 'vue';

import {
  NButton,
  NCard,
  NDataTable,
  NPopconfirm,
  NTag,
  NProgress,
  NEmpty,
  NSpace,
  NSelect,
  useMessage,
} from 'naive-ui';

import {
  getUnifiedNodes,
  getClusterStats,
  unregisterWorker,
  type UnifiedNode,
  type NodeSummary,
} from '#/api/cluster';

import { shutdownAgent } from '#/api/monitor';

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
const schedulerStats = ref({
  active_runners: 0,
  max_parallel: 0,
  memory_queue_len: 0,
  running_tasks: 0,
  queued_tasks: 0,
  completed_today: 0,
});
const filterType = ref<string | null>(null);
const filterStatus = ref<string | null>(null);
let refreshTimer: ReturnType<typeof setInterval> | null = null;

const typeLabels: Record<string, string> = {
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

const filteredNodes = computed(() => {
  let list = nodes.value;
  if (filterType.value) list = list.filter((n) => n.type === filterType.value);
  if (filterStatus.value) list = list.filter((n) => n.status === filterStatus.value);
  return list;
});

const columns = [
  {
    title: '类型',
    key: 'type',
    width: 90,
    render: (row: UnifiedNode) => {
      const color = row.type === 'worker' ? '#1890ff' : '#52c41a';
      return h('span', {
        style: `padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; background: ${color}15; color: ${color}`,
      }, typeLabels[row.type] ?? row.type);
    },
  },
  {
    title: '名称',
    key: 'name',
    minWidth: 120,
    ellipsis: { tooltip: true },
    render: (row: UnifiedNode) =>
      h('span', { style: 'font-weight: 500' }, row.name || row.hostname || row.ip || '-'),
  },
  { title: 'IP', key: 'ip', width: 130, ellipsis: { tooltip: true } },
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
    width: 100,
    render: (row: UnifiedNode) =>
      h(NProgress, {
        type: 'line',
        percentage: Math.round(row.cpu_usage),
        height: 14,
        indicatorPlacement: 'inside',
        status: row.cpu_usage > 90 ? 'error' : row.cpu_usage > 70 ? 'warning' : 'success',
      }),
  },
  {
    title: '内存',
    key: 'mem_usage',
    width: 100,
    render: (row: UnifiedNode) =>
      h(NProgress, {
        type: 'line',
        percentage: Math.round(row.mem_usage),
        height: 14,
        indicatorPlacement: 'inside',
        status: row.mem_usage > 90 ? 'error' : row.mem_usage > 70 ? 'warning' : 'success',
      }),
  },
  {
    title: '任务',
    key: 'active_tasks',
    width: 80,
    align: 'center' as const,
    render: (row: UnifiedNode) =>
      h('span', { style: 'font-size: 12px' }, `${row.active_tasks}/${row.capacity || '-'}`),
  },
  {
    title: '健康分',
    key: 'health_score',
    width: 80,
    render: (row: UnifiedNode) => {
      const score = Math.round(row.health_score);
      const color = score >= 80 ? 'success' : score >= 50 ? 'warning' : 'error';
      return h(NTag, { type: color as any, size: 'small', round: true }, () => score);
    },
  },
  {
    title: '区域',
    key: 'region',
    width: 80,
    render: (row: UnifiedNode) => row.region || '-',
  },
  { title: '版本', key: 'version', width: 80, ellipsis: { tooltip: true } },
  {
    title: '最近心跳',
    key: 'last_heartbeat',
    width: 170,
    render: (row: UnifiedNode) =>
      h('span', { style: 'font-size: 12px; color: #666;' }, fmtTime(row.last_heartbeat)),
  },
  {
    title: '操作',
    key: 'actions',
    width: 80,
    render: (row: UnifiedNode) => {
      if (row.type === 'worker') {
        return h(NPopconfirm, { onPositiveClick: () => handleRemoveWorker(row.id) }, {
          trigger: () => h(NButton, { size: 'small', text: true, type: 'error' }, () => '注销'),
          default: () => '确定注销此扫描节点？',
        });
      }
      return h(NPopconfirm, { onPositiveClick: () => handleShutdownAgent(row.id) }, {
        trigger: () => h(NButton, { size: 'small', text: true, type: 'error' }, () => '停止'),
        default: () => '确定停止此监测节点？',
      });
    },
  },
];

async function fetchData() {
  loading.value = true;
  try {
    const [nodesRes, statsRes] = await Promise.allSettled([getUnifiedNodes(), getClusterStats()]);
    if (nodesRes.status === 'fulfilled') {
      const result = nodesRes.value as any;
      nodes.value = result?.nodes ?? [];
      if (result?.summary) summary.value = result.summary;
    }
    if (statsRes.status === 'fulfilled') {
      const s = statsRes.value as any;
      schedulerStats.value = {
        active_runners: s?.active_runners ?? 0,
        max_parallel: s?.max_parallel ?? 0,
        memory_queue_len: s?.memory_queue_len ?? 0,
        running_tasks: s?.running_tasks ?? 0,
        queued_tasks: s?.queued_tasks ?? 0,
        completed_today: s?.completed_today ?? 0,
      };
    }
  } finally {
    loading.value = false;
  }
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

onMounted(() => {
  fetchData();
  refreshTimer = setInterval(fetchData, 10000);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
});
</script>

<template>
  <div style="padding: 16px">
    <!-- Summary Cards -->
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
        <div class="summary-value" style="color: #1890ff">{{ summary.worker_count }}</div>
        <div class="summary-label">扫描节点</div>
      </div>
      <div class="summary-card">
        <div class="summary-value" style="color: #52c41a">{{ summary.agent_count }}</div>
        <div class="summary-label">监测节点</div>
      </div>
      <div class="summary-card">
        <div class="summary-value" style="color: #ed8936">{{ summary.total_tasks }}</div>
        <div class="summary-label">活跃任务</div>
      </div>
    </div>

    <!-- Local Engine -->
    <NCard size="small" style="margin-bottom: 16px">
      <template #header>
        <NSpace align="center" :size="8">
          <span style="font-weight: 600">本地执行引擎</span>
          <NTag :type="schedulerStats.active_runners > 0 ? 'success' : 'info'" size="small" round>
            {{ schedulerStats.active_runners > 0 ? '运行中' : '就绪' }}
          </NTag>
        </NSpace>
      </template>
      <div class="engine-stats">
        <div class="engine-stat">
          <div class="engine-stat-value" style="color: var(--primary-color)">{{ schedulerStats.active_runners }}</div>
          <div class="engine-stat-label">正在执行</div>
        </div>
        <div class="engine-stat">
          <div class="engine-stat-value" style="color: #ed8936">{{ schedulerStats.memory_queue_len }}</div>
          <div class="engine-stat-label">内存队列</div>
        </div>
        <div class="engine-stat">
          <div class="engine-stat-value" style="color: #48bb78">{{ schedulerStats.completed_today }}</div>
          <div class="engine-stat-label">今日完成</div>
        </div>
        <div class="engine-stat">
          <div class="engine-stat-value">{{ schedulerStats.max_parallel }}</div>
          <div class="engine-stat-label">最大并行</div>
        </div>
      </div>
    </NCard>

    <!-- Node Table -->
    <NCard size="small">
      <template #header>
        <span style="font-weight: 600">节点列表</span>
      </template>
      <template #header-extra>
        <NSpace :size="8">
          <NSelect
            v-model:value="filterType"
            size="small"
            clearable
            placeholder="类型"
            style="width: 120px"
            :options="[{ label: '扫描节点', value: 'worker' }, { label: '监测节点', value: 'agent' }]"
          />
          <NSelect
            v-model:value="filterStatus"
            size="small"
            clearable
            placeholder="状态"
            style="width: 100px"
            :options="[{ label: '在线', value: 'online' }, { label: '离线', value: 'offline' }, { label: '排干', value: 'drain' }]"
          />
          <NButton size="small" @click="fetchData">刷新</NButton>
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
      />
      <NEmpty v-else description="暂无节点" style="padding: 32px 0">
        <template #extra>
          <span style="font-size: 12px; color: #999">
            部署扫描节点或监测节点后，将在此统一展示
          </span>
        </template>
      </NEmpty>
    </NCard>
  </div>
</template>

<style scoped>
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

.engine-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
}

.engine-stat {
  text-align: center;
}

.engine-stat-value {
  font-size: 24px;
  font-weight: 600;
}

.engine-stat-label {
  font-size: 12px;
  color: #999;
  margin-top: 2px;
}
</style>
