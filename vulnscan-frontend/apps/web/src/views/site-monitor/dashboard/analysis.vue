<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import type {
  DashboardStats,
  MonitorAgent,
  MonitorExecution,
} from '#/api/monitor';

import { computed, h, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';
import { IconifyIcon } from '@vben/icons';

import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NDataTable,
  NGi,
  NGrid,
  NSelect,
  NSpace,
  NSwitch,
  NTag,
} from 'naive-ui';

import {
  getAgentList,
  getDashboardStats,
  getExecutionList,
  getTaskExecutionStats,
} from '#/api/monitor';
import { useAutoRefresh } from '#/composables/useAutoRefresh';

defineOptions({ name: 'MonitorDashboard' });

const router = useRouter();
const loading = ref(false);

const stats = reactive({
  enabledTasks: 0,
  issueExecutions: 0,
  onlineAgents: 0,
  totalAgents: 0,
  totalExecutions: 0,
  totalTasks: 0,
});

const recentExecutions = ref<MonitorExecution[]>([]);
const safeRecentExecutions = computed(() =>
  Array.isArray(recentExecutions.value) ? recentExecutions.value : [],
);
const agentList = ref<MonitorAgent[]>([]);
const safeAgentList = computed(() =>
  Array.isArray(agentList.value) ? agentList.value : [],
);
const taskStatsMap = ref<
  Record<string, Record<string, { total: number; issue_count: number }>>
>({});

// ── 维度元信息 ──
const dimensions = [
  { key: 'availability', label: '可用性', icon: 'ri:pulse-line', color: '#409eff' },
  { key: 'tamper', label: '篡改监测', icon: 'ri:shield-flash-line', color: '#f56c6c' },
  { key: 'blacklink', label: '暗链监测', icon: 'ri:bug-line', color: '#e6a23c' },
  { key: 'sensitive_word', label: '敏感词', icon: 'ri:file-text-line', color: '#a855f7' },
  { key: 'sensitive_file', label: '敏感文件', icon: 'ri:folder-shield-2-line', color: '#14b8a6' },
  { key: 'domain_hijack', label: '域名劫持', icon: 'ri:global-line', color: '#10b981' },
];

const dimMap: Record<string, string> = Object.fromEntries(
  dimensions.map((v) => [v.key, v.label]),
);

const statusLabel = (v: string) =>
  ({
    failed: '失败',
    pending: '等待中',
    running: '运行中',
    success: '成功',
  })[v] ?? v;

const statusColor = (v: string) => {
  if (v === 'success') return '#67c23a';
  if (v === 'failed') return '#f56c6c';
  if (v === 'running') return '#e6a23c';
  return '#909399';
};

const agentStatusLabel = (v: string) =>
  v === 'online' ? '在线' : v === 'offline' ? '离线' : v || '未知';

const agentStatusColor = (v: string) => {
  if (v === 'online') return '#67c23a';
  if (v === 'offline') return '#f56c6c';
  return '#909399';
};

const fmtTime = (v: string) =>
  v ? dayjs(v).format('YYYY-MM-DD HH:mm:ss') : '-';

const fmtPercent = (v: number | undefined) =>
  v == null ? '-' : `${v.toFixed(1)}%`;

const dimensionCards = computed(() =>
  dimensions.map((d) => {
    let total = 0;
    let issueCount = 0;
    for (const item of Object.values(taskStatsMap.value || {})) {
      const stat = item?.[d.key];
      if (!stat) continue;
      total += Number(stat.total || 0);
      issueCount += Number(stat.issue_count || 0);
    }
    return { ...d, issueCount, total };
  }),
);

const lastRefreshAt = ref<null | string>(null);

async function fetchAll() {
  loading.value = true;
  try {
    const [statsRes, execRes, agentRes, taskStatsRes] = await Promise.all([
      getDashboardStats(),
      getExecutionList({ size: 20 }),
      getAgentList(),
      getTaskExecutionStats(),
    ]);
    const overview = ((statsRes as any)?.data ?? statsRes ?? {}) as DashboardStats;
    stats.totalTasks = overview.total_tasks || 0;
    stats.enabledTasks = overview.enabled_tasks || 0;
    stats.totalExecutions = overview.total_executions || 0;
    stats.issueExecutions = overview.issue_executions || 0;
    stats.onlineAgents = overview.online_agents || 0;
    stats.totalAgents = overview.total_agents || 0;
    recentExecutions.value = execRes.data || [];
    agentList.value = Array.isArray(agentRes) ? agentRes : ((agentRes as any)?.data || []);
    taskStatsMap.value = (taskStatsRes as any)?.data ?? taskStatsRes ?? {};
    lastRefreshAt.value = dayjs().format('HH:mm:ss');
  } finally {
    loading.value = false;
  }
}

const refreshIntervalOptions = [
  { label: '10 秒', value: 10_000 },
  { label: '30 秒', value: 30_000 },
  { label: '1 分钟', value: 60_000 },
  { label: '5 分钟', value: 300_000 },
];

// 使用 useAutoRefresh 替代裸 setInterval：
// - 页面不可见时自动暂停（节省资源）
// - 单次接口慢时不会叠加并发
// - 支持运行时调整间隔与开关
const { enabled: autoRefreshEnabled, interval: autoRefreshInterval } =
  useAutoRefresh({
    task: fetchAll,
    interval: 30_000,
    immediate: true,
    runOnMount: true,
  });

const goExecDetail = (row: MonitorExecution) =>
  router.push(`/monitor/tasks/executions/detail/${row.id}`);
const goTasks = () => router.push('/monitor/tasks');
const goAgents = () => router.push('/monitor/agents');
const goExecutions = () => router.push('/monitor/tasks/executions');

const agentColumns: DataTableColumns<MonitorAgent> = [
  { key: 'uuid', title: 'UUID', minWidth: 220, ellipsis: { tooltip: true } },
  { key: 'version', title: '版本', width: 90, align: 'center' },
  {
    key: 'status',
    title: '状态',
    width: 80,
    align: 'center',
    render: (row) =>
      h(
        'span',
        { style: { color: agentStatusColor(row.status), fontWeight: 500 } },
        agentStatusLabel(row.status),
      ),
  },
  {
    key: 'tasks',
    title: '任务',
    width: 150,
    align: 'center',
    render: (row) =>
      h('span', null, [
        `${row.running_tasks ?? 0}/${row.max_concurrent ?? 0}`,
        h(
          'span',
          { style: { color: '#909399', marginLeft: '4px' } },
          `(${row.queued_tasks ?? 0}/${row.max_queue ?? 0})`,
        ),
      ]),
  },
  {
    key: 'cpu',
    title: 'CPU',
    width: 90,
    align: 'center',
    render: (row) => fmtPercent(row.cpu_usage),
  },
  {
    key: 'memory',
    title: '内存',
    width: 90,
    align: 'center',
    render: (row) => fmtPercent(row.memory_usage),
  },
  {
    key: 'updated_at',
    title: '最后心跳',
    width: 170,
    align: 'center',
    render: (row) => fmtTime(row.updated_at),
  },
];

const executionColumns: DataTableColumns<MonitorExecution> = [
  { key: 'id', title: '执行ID', width: 180, ellipsis: { tooltip: true } },
  { key: 'url', title: 'URL', minWidth: 220, ellipsis: { tooltip: true } },
  {
    key: 'dimension',
    title: '维度',
    width: 110,
    align: 'center',
    render: (row) => dimMap[row.dimension] || row.dimension || '-',
  },
  {
    key: 'status',
    title: '状态',
    width: 90,
    align: 'center',
    render: (row) =>
      h(
        'span',
        { style: { color: statusColor(row.status), fontWeight: 500 } },
        statusLabel(row.status),
      ),
  },
  {
    key: 'has_issue',
    title: '安全问题',
    width: 100,
    align: 'center',
    render: (row) =>
      h(
        'span',
        {
          style: {
            color: row.has_issue ? '#f56c6c' : '#67c23a',
            fontWeight: 500,
          },
        },
        row.has_issue ? '发现' : '无',
      ),
  },
  {
    key: 'created_at',
    title: '创建时间',
    width: 170,
    align: 'center',
    render: (row) => fmtTime(row.created_at),
  },
  {
    key: 'op',
    title: '操作',
    width: 90,
    align: 'center',
    fixed: 'right',
    render: (row) =>
      h(
        NButton,
        {
          text: true,
          type: 'primary',
          size: 'small',
          onClick: () => goExecDetail(row),
        },
        { default: () => '详情' },
      ),
  },
];

</script>

<template>
  <Page title="数据分析" description="网站监测全局总览、Agent 状态、最近执行记录">
    <template #extra>
      <NSpace :size="12" align="center">
        <NTag v-if="lastRefreshAt" type="default" size="small" round>
          上次刷新：{{ lastRefreshAt }}
        </NTag>
        <span class="text-muted-foreground text-xs">自动刷新</span>
        <NSwitch v-model:value="autoRefreshEnabled" size="small" />
        <NSelect
          v-model:value="autoRefreshInterval"
          :options="refreshIntervalOptions"
          :disabled="!autoRefreshEnabled"
          size="small"
          style="width: 100px"
        />
        <NButton
          size="small"
          type="primary"
          :loading="loading"
          @click="fetchAll"
        >
          立即刷新
        </NButton>
      </NSpace>
    </template>
    <!-- 顶部 4 张统计卡 -->
    <NGrid cols="2 m:4" :x-gap="16" :y-gap="16" responsive="screen">
      <NGi>
        <NCard hoverable class="cursor-pointer" @click="goTasks">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-muted-foreground mb-1 text-sm">监测任务</div>
              <div class="text-2xl font-bold">{{ stats.totalTasks }}</div>
              <div class="text-muted-foreground mt-1 text-xs">
                已启用 {{ stats.enabledTasks }}
              </div>
            </div>
            <div class="text-blue-400 opacity-60">
              <IconifyIcon icon="ri:task-line" class="text-4xl" />
            </div>
          </div>
        </NCard>
      </NGi>
      <NGi>
        <NCard hoverable class="cursor-pointer" @click="goExecutions">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-muted-foreground mb-1 text-sm">执行记录</div>
              <div class="text-2xl font-bold">{{ stats.totalExecutions }}</div>
              <div
                class="mt-1 text-xs"
                :class="
                  stats.issueExecutions > 0
                    ? 'text-red-500'
                    : 'text-muted-foreground'
                "
              >
                发现问题 {{ stats.issueExecutions }}
              </div>
            </div>
            <div class="text-orange-400 opacity-60">
              <IconifyIcon icon="ri:file-chart-line" class="text-4xl" />
            </div>
          </div>
        </NCard>
      </NGi>
      <NGi>
        <NCard hoverable class="cursor-pointer" @click="goAgents">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-muted-foreground mb-1 text-sm">Agent 节点</div>
              <div class="text-2xl font-bold">{{ stats.totalAgents }}</div>
              <div
                class="mt-1 text-xs"
                :class="
                  stats.onlineAgents > 0
                    ? 'text-green-500'
                    : 'text-muted-foreground'
                "
              >
                在线 {{ stats.onlineAgents }}
              </div>
            </div>
            <div class="text-green-400 opacity-60">
              <IconifyIcon icon="ri:robot-line" class="text-4xl" />
            </div>
          </div>
        </NCard>
      </NGi>
      <NGi>
        <NCard hoverable>
          <div class="flex items-center justify-between">
            <div>
              <div class="text-muted-foreground mb-1 text-sm">监测维度</div>
              <div class="text-2xl font-bold">6</div>
              <div class="text-muted-foreground mt-1 text-xs">
                可用性/篡改/暗链/敏感词/敏感文件/域名劫持
              </div>
            </div>
            <div class="text-purple-400 opacity-60">
              <IconifyIcon icon="ri:shield-check-line" class="text-4xl" />
            </div>
          </div>
        </NCard>
      </NGi>
    </NGrid>

    <!-- 6 个维度统计 -->
    <NGrid
      cols="2 s:3 m:6"
      :x-gap="12"
      :y-gap="12"
      responsive="screen"
      class="mt-4"
    >
      <NGi v-for="item in dimensionCards" :key="item.key">
        <NCard hoverable>
          <div class="mb-3 flex items-center justify-between">
            <div class="font-bold">{{ item.label }}</div>
            <div class="opacity-70" :style="{ color: item.color }">
              <IconifyIcon :icon="item.icon" class="text-2xl" />
            </div>
          </div>
          <div class="flex items-end justify-between">
            <div>
              <div class="text-muted-foreground mb-1 text-xs">监测总次数</div>
              <div class="text-xl font-bold">{{ item.total }}</div>
            </div>
            <div class="text-right">
              <div class="text-muted-foreground mb-1 text-xs">发现问题</div>
              <div
                class="text-xl font-bold"
                :style="{ color: item.issueCount > 0 ? '#f56c6c' : '#909399' }"
              >
                {{ item.issueCount }}
              </div>
            </div>
          </div>
        </NCard>
      </NGi>
    </NGrid>

    <!-- Agent 状态概览 -->
    <NCard class="mt-4" title="Agent 状态概览">
      <template #header-extra>
        <NSpace>
          <NButton text type="primary" @click="fetchAll">刷新</NButton>
          <NButton text type="primary" @click="goAgents">查看全部</NButton>
        </NSpace>
      </template>
      <NDataTable
        :columns="agentColumns"
        :data="safeAgentList"
        :loading="loading"
        :max-height="260"
        :row-key="(r: MonitorAgent) => r.uuid"
        size="small"
      />
    </NCard>

    <!-- 最近执行记录 -->
    <NCard class="mt-4" title="最近执行记录">
      <template #header-extra>
        <NSpace>
          <NButton text type="primary" @click="fetchAll">刷新</NButton>
          <NButton text type="primary" @click="goExecutions">查看全部</NButton>
        </NSpace>
      </template>
      <NDataTable
        :columns="executionColumns"
        :data="safeRecentExecutions"
        :loading="loading"
        :max-height="420"
        :row-key="(r: MonitorExecution) => r.id"
        size="small"
      />
    </NCard>
  </Page>
</template>
