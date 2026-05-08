<script lang="ts" setup>
import { h, onMounted, onUnmounted, ref } from 'vue';

import {
  NCard,
  NDataTable,
  NEmpty,
  NGrid,
  NGridItem,
  NProgress,
  NStatistic,
  NTag,
  NSpin,
  NButton,
  NDescriptions,
  NDescriptionsItem,
} from 'naive-ui';

import { getSubMasterList, getFederationStats, type SubMaster, type FederationStats } from '#/api/federation';

defineOptions({ name: 'FederationManage' });

const loading = ref(true);
const subMasters = ref<SubMaster[]>([]);
const stats = ref<FederationStats>({ total_sub_masters: 0, online_sub_masters: 0, current_versions: {} });
let refreshTimer: ReturnType<typeof setInterval> | null = null;

const statusColors: Record<string, string> = {
  online: 'success',
  offline: 'default',
  degraded: 'warning',
  maintenance: 'info',
};

const statusLabels: Record<string, string> = {
  online: '在线',
  offline: '离线',
  degraded: '降级',
  maintenance: '维护中',
};

function fmtTime(raw?: string) {
  if (!raw) return '-';
  const d = new Date(raw);
  if (isNaN(d.getTime())) return raw;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const columns = [
  { title: '编码', key: 'sub_master_code', width: 160, ellipsis: { tooltip: true } },
  { title: '主机名', key: 'hostname', minWidth: 120, ellipsis: { tooltip: true } },
  { title: 'IP', key: 'ip_address', width: 130 },
  { title: '版本', key: 'version', width: 80 },
  {
    title: '状态',
    key: 'status',
    width: 80,
    render: (row: SubMaster) =>
      h(NTag, { type: (statusColors[row.status] || 'default') as any, size: 'small' }, () => statusLabels[row.status] || row.status),
  },
  {
    title: 'CPU',
    key: 'cpu_percent',
    width: 100,
    render: (row: SubMaster) =>
      h(NProgress, {
        type: 'line', percentage: Math.round(row.cpu_percent), height: 14,
        indicatorPlacement: 'inside',
        status: row.cpu_percent > 90 ? 'error' : row.cpu_percent > 70 ? 'warning' : 'success',
      }),
  },
  {
    title: '内存',
    key: 'mem_percent',
    width: 100,
    render: (row: SubMaster) =>
      h(NProgress, {
        type: 'line', percentage: Math.round(row.mem_percent), height: 14,
        indicatorPlacement: 'inside',
        status: row.mem_percent > 90 ? 'error' : row.mem_percent > 70 ? 'warning' : 'success',
      }),
  },
  { title: 'Worker', key: 'worker_count', width: 70, align: 'center' as const },
  { title: '任务数', key: 'active_tasks', width: 70, align: 'center' as const },
  { title: '今日扫描', key: 'scans_today', width: 80, align: 'center' as const },
  {
    title: 'PoC版本',
    key: 'poc_version',
    width: 90,
    render: (row: SubMaster) => {
      const latest = stats.value.current_versions?.poc ?? 0;
      const behind = latest > 0 && latest > row.poc_version;
      return h(NTag, { type: behind ? 'warning' : 'success', size: 'small' }, () => `${row.poc_version}${behind ? ` / ${latest}` : ''}`);
    },
  },
  {
    title: '最近心跳',
    key: 'last_heartbeat_at',
    width: 170,
    render: (row: SubMaster) => h('span', { style: 'font-size: 12px; color: #666;' }, fmtTime(row.last_heartbeat_at)),
  },
];

async function fetchData() {
  try {
    const [subs, fedStats] = await Promise.allSettled([getSubMasterList(), getFederationStats()]);
    if (subs.status === 'fulfilled') {
      subMasters.value = subs.value.items || [];
    }
    if (fedStats.status === 'fulfilled') {
      stats.value = fedStats.value as any;
    }
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  fetchData();
  refreshTimer = setInterval(fetchData, 15000);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
});
</script>

<template>
  <div style="padding: 16px">
    <NSpin :show="loading">
      <NGrid :cols="3" :x-gap="16" :y-gap="16" style="margin-bottom: 16px">
        <NGridItem>
          <NCard size="small"><NStatistic label="分主控总数" :value="stats.total_sub_masters" /></NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small"><NStatistic label="在线分主控" :value="stats.online_sub_masters" /></NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small">
            <NDescriptions label-placement="left" :column="1" size="small">
              <NDescriptionsItem label="PoC 版本">
                {{ stats.current_versions?.poc ?? 0 }}
              </NDescriptionsItem>
              <NDescriptionsItem label="指纹版本">
                {{ stats.current_versions?.fingerprint ?? 0 }}
              </NDescriptionsItem>
              <NDescriptionsItem label="规则版本">
                {{ stats.current_versions?.rule ?? 0 }}
              </NDescriptionsItem>
            </NDescriptions>
          </NCard>
        </NGridItem>
      </NGrid>

      <NCard size="small">
        <template #header>
          <span style="font-weight: 600">分主控列表</span>
        </template>
        <template #header-extra>
          <NButton size="small" @click="fetchData">刷新</NButton>
        </template>
        <NDataTable
          v-if="subMasters.length > 0 || loading"
          :columns="columns"
          :data="subMasters"
          :bordered="false"
          size="small"
          striped
        />
        <NEmpty v-else description="暂无分主控节点" style="padding: 32px 0">
          <template #extra>
            <span style="font-size: 12px; color: #999">
              配置联邦模式并注册分主控后，将在此展示
            </span>
          </template>
        </NEmpty>
      </NCard>
    </NSpin>
  </div>
</template>
