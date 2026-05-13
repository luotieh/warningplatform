<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import type { MonitorAgent } from '#/api/sitemonitor';

import { computed, h, onMounted, onUnmounted, ref } from 'vue';

import { Page } from '@vben/common-ui';
import { IconifyIcon } from '@vben/icons';

import dayjs from 'dayjs';
import { NButton, NCard, NDataTable, NSpace, NTag } from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  getAgentList,
  shutdownAgent,
  syncAgentRules,
} from '#/api/sitemonitor';

defineOptions({ name: 'MonitorAgents' });
const loading = ref(false);
const dataList = ref<MonitorAgent[]>([]);
const safeDataList = computed(() =>
  Array.isArray(dataList.value) ? dataList.value : [],
);

async function fetchData() {
  loading.value = true;
  try {
    const res = await getAgentList();
    dataList.value = Array.isArray(res) ? res : (res as any)?.data || [];
  } finally {
    loading.value = false;
  }
}

const statusType = (status: string): 'default' | 'error' | 'success' => {
  if (status === 'online') return 'success';
  if (status === 'offline') return 'error';
  return 'default';
};

const statusLabel = (status: string) => {
  if (status === 'online') return '在线';
  if (status === 'offline') return '离线';
  return '未知';
};

const fmtPercent = (v: number | undefined) =>
  v == null ? '-' : `${v.toFixed(1)}%`;

const fmtTime = (t: string) =>
  t ? dayjs(t).format('YYYY-MM-DD HH:mm:ss') : '-';

function handleSyncRules(row: MonitorAgent) {
  dialog.info({
    title: '同步规则',
    content: `确认向 Agent [${row.uuid.slice(0, 8)}...] 下发全量规则同步指令？`,
    positiveText: '确认',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const res: any = await syncAgentRules(row.uuid);
        if (res?.ok) {
          message.success(
            `规则同步成功，已加载 ${res.rules_loaded ?? 0} 个模块`,
          );
        } else {
          message.warning(res?.error || '同步失败');
        }
      } catch (e: any) {
        message.error(e?.message || '同步规则失败');
      }
    },
  });
}

function handleShutdown(row: MonitorAgent) {
  dialog.warning({
    title: '下线 Agent',
    content: `确认下线 Agent [${row.uuid.slice(0, 8)}...]？\n如有任务运行中，Agent 将拒绝下线。`,
    positiveText: '确认下线',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const res: any = await shutdownAgent(row.uuid);
        if (res?.ok) {
          message.success('Agent 正在关闭');
          setTimeout(fetchData, 2000);
        } else {
          message.warning(res?.error || '下线失败');
        }
      } catch (e: any) {
        message.error(e?.message || '下线指令失败');
      }
    },
  });
}

const columns: DataTableColumns<MonitorAgent> = [
  { key: 'uuid', title: 'UUID', minWidth: 180, ellipsis: { tooltip: true } },
  { key: 'version', title: '版本', width: 80 },
  {
    key: 'status',
    title: '状态',
    width: 80,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        { type: statusType(row.status), size: 'small', bordered: false },
        { default: () => statusLabel(row.status) },
      ),
  },
  {
    key: 'ip_address',
    title: 'IP',
    width: 140,
    ellipsis: { tooltip: true },
  },
  {
    key: 'mac_address',
    title: 'MAC',
    width: 150,
    ellipsis: { tooltip: true },
  },
  {
    key: 'tasks',
    title: '任务',
    width: 180,
    align: 'center',
    render: (row) =>
      h('span', null, [
        h('span', { style: { fontWeight: 'bold' } }, `${row.running_tasks}`),
        ` 运行 / `,
        h('span', null, `${row.queued_tasks}`),
        ` 排队`,
        h(
          'span',
          { style: { color: '#67c23a', marginLeft: '6px' } },
          `(已完成 ${row.tasks_completed ?? 0})`,
        ),
      ]),
  },
  {
    key: 'cpu_usage',
    title: 'CPU',
    width: 80,
    align: 'center',
    render: (row) => fmtPercent(row.cpu_usage),
  },
  {
    key: 'memory_usage',
    title: '内存',
    width: 80,
    align: 'center',
    render: (row) => fmtPercent(row.memory_usage),
  },
  {
    key: 'updated_at',
    title: '最后心跳',
    width: 170,
    align: 'center',
    render: (row) => fmtTime(row.last_heartbeat || row.updated_at),
  },
  {
    key: 'op',
    title: '操作',
    width: 180,
    fixed: 'right',
    align: 'center',
    render: (row) =>
      h(NSpace, { size: 'small' }, () => [
        h(
          NButton,
          {
            text: true,
            type: 'primary',
            size: 'small',
            disabled: row.status !== 'online',
            onClick: () => handleSyncRules(row),
          },
          { default: () => '同步规则' },
        ),
        h(
          NButton,
          {
            text: true,
            type: 'error',
            size: 'small',
            disabled: row.status !== 'online',
            onClick: () => handleShutdown(row),
          },
          { default: () => '下线' },
        ),
      ]),
  },
];

let timer: null | ReturnType<typeof setInterval> = null;
onMounted(() => {
  fetchData();
  timer = setInterval(fetchData, 10_000);
});
onUnmounted(() => {
  if (timer) clearInterval(timer);
});
</script>

<template>
  <Page title="Agent 管理" description="Agent 节点状态、规则同步、远程关停">
    <NCard>
      <template #header-extra>
        <NButton type="primary" size="small" @click="fetchData">
          <template #icon>
            <IconifyIcon icon="ri:refresh-line" />
          </template>
          刷新
        </NButton>
      </template>
      <NDataTable
        :columns="columns"
        :data="safeDataList"
        :loading="loading"
        :row-key="(r: MonitorAgent) => r.uuid"
        size="small"
        striped
      />
    </NCard>
  </Page>
</template>
