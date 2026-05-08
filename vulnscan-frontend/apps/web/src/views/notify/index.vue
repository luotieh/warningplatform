<script lang="ts" setup>
import { h, onMounted, ref } from 'vue';
import {
  NButton, NCard, NDataTable, NEmpty, NSelect, NSpace, NStatistic,
  NTag, useMessage,
} from 'naive-ui';
import type { Notification } from '#/api/notify';
import { getNotifications, getUnreadCount, markAllRead, markRead } from '#/api/notify';
import { useRouter } from 'vue-router';

defineOptions({ name: 'NotifyIndex' });

const message = useMessage();
const router = useRouter();
const loading = ref(false);
const notifications = ref<Notification[]>([]);
const unreadCount = ref(0);
const total = ref(0);
const readFilter = ref<string | null>(null);

const typeOptions = [
  { label: '全部', value: '' },
  { label: '任务完成', value: 'task_complete' },
  { label: '任务失败', value: 'task_failed' },
  { label: '严重漏洞', value: 'vuln_critical' },
  { label: '高危漏洞', value: 'vuln_high' },
];
const typeFilter = ref('');

const columns = [
  {
    title: '状态', key: 'read', width: 60, align: 'center' as const,
    render: (row: Notification) => row.read
      ? h('span', { style: 'color:#ccc;font-size:10px' }, '●')
      : h('span', { style: 'color:#2080f0;font-size:10px' }, '●'),
  },
  {
    title: '级别', key: 'severity', width: 70,
    render: (row: Notification) => {
      const typeMap: Record<string, any> = { critical: 'error', error: 'error', high: 'warning', info: 'info' };
      return h(NTag, { size: 'small', type: typeMap[row.severity] ?? 'default' }, () => row.severity);
    },
  },
  { title: '标题', key: 'title', minWidth: 200, ellipsis: { tooltip: true } },
  { title: '内容', key: 'content', ellipsis: { tooltip: true } },
  { title: '时间', key: 'created_at', width: 170 },
  {
    title: '操作', key: 'actions', width: 140,
    render: (row: Notification) => h(NSpace, { size: 4 }, () => [
      !row.read ? h(NButton, { size: 'tiny', onClick: () => onMarkRead(row) }, () => '已读') : null,
      row.link ? h(NButton, { size: 'tiny', type: 'info', onClick: () => router.push(row.link) }, () => '查看') : null,
    ]),
  },
];

async function fetchList() {
  loading.value = true;
  try {
    const params: any = {};
    if (readFilter.value) params.read = readFilter.value;
    if (typeFilter.value) params.type = typeFilter.value;
    const res: any = await getNotifications(params);
    const body = res?.data ?? res;
    notifications.value = body?.data ?? [];
    total.value = body?.total ?? notifications.value.length;
  } catch { message.error('获取通知失败'); }
  finally { loading.value = false; }
}

async function fetchUnread() {
  try {
    const res: any = await getUnreadCount();
    const body = res?.data ?? res;
    unreadCount.value = body?.count ?? 0;
  } catch {}
}

async function onMarkRead(item: Notification) {
  try {
    await markRead(item.id);
    item.read = true;
    unreadCount.value = Math.max(0, unreadCount.value - 1);
  } catch {}
}

async function onMarkAllRead() {
  try {
    await markAllRead();
    notifications.value.forEach(n => { n.read = true; });
    unreadCount.value = 0;
    message.success('已全部标记为已读');
  } catch { message.error('操作失败'); }
}

onMounted(() => { fetchList(); fetchUnread(); });
</script>

<template>
  <div style="padding: 16px">
    <NCard title="通知中心" size="small">
      <template #header-extra>
        <NSpace align="center">
          <NStatistic label="未读" :value="unreadCount" style="display:inline-flex;gap:4px" />
          <NButton size="small" type="warning" :disabled="unreadCount === 0" @click="onMarkAllRead">全部已读</NButton>
        </NSpace>
      </template>

      <NSpace style="margin-bottom:12px">
        <NSelect v-model:value="readFilter" :options="[{ label: '全部', value: '' }, { label: '未读', value: 'false' }]" style="width:100px" size="small" @update:value="fetchList" />
        <NSelect v-model:value="typeFilter" :options="typeOptions" style="width:140px" size="small" clearable placeholder="类型筛选" @update:value="fetchList" />
      </NSpace>

      <NEmpty v-if="notifications.length === 0 && !loading" description="暂无通知" />
      <NDataTable v-else :columns="columns" :data="notifications" :loading="loading" :bordered="false" size="small" striped />
    </NCard>
  </div>
</template>
