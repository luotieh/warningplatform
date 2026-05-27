<script lang="ts" setup>
import { computed, h, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import {
  NButton,
  NDataTable,
  NEmpty,
  NSelect,
  NSpace,
  NTag,
  useMessage,
} from 'naive-ui';

import type { Notification } from '#/api/notify';
import {
  getNotifications,
  getUnreadCount,
  markAllRead,
  markRead,
} from '#/api/notify';
import { BasePageContainer } from '#/components/page';

defineOptions({ name: 'NotifyIndex' });

const message = useMessage();
const router = useRouter();
const loading = ref(false);
const notifications = ref<Notification[]>([]);
const unreadCount = ref(0);
const total = ref(0);
const readFilter = ref<string | null>(null);
const typeFilter = ref('');

const readOptions = [
  { label: '全部', value: '' },
  { label: '未读', value: 'false' },
  { label: '已读', value: 'true' },
];

const typeOptions = [
  { label: '全部类型', value: '' },
  { label: '任务完成', value: 'task_complete' },
  { label: '任务失败', value: 'task_failed' },
  { label: '严重漏洞', value: 'vuln_critical' },
  { label: '高危漏洞', value: 'vuln_high' },
];

const severityMap: Record<string, { type: 'default' | 'error' | 'info' | 'success' | 'warning'; label: string }> = {
  critical: { type: 'error', label: '严重' },
  error: { type: 'error', label: '错误' },
  high: { type: 'warning', label: '高' },
  medium: { type: 'warning', label: '中' },
  info: { type: 'info', label: '信息' },
  low: { type: 'default', label: '低' },
};

const columns = [
  {
    title: '',
    key: 'read',
    width: 36,
    align: 'center' as const,
    render: (row: Notification) =>
      h('span', {
        class: row.read ? 'dot dot-read' : 'dot dot-unread',
      }),
  },
  {
    title: '级别',
    key: 'severity',
    width: 80,
    render: (row: Notification) => {
      const info = severityMap[row.severity] ?? { type: 'default' as const, label: row.severity };
      return h(NTag, { size: 'small', type: info.type, bordered: false }, () => info.label);
    },
  },
  {
    title: '标题',
    key: 'title',
    minWidth: 200,
    ellipsis: { tooltip: true },
    render: (row: Notification) =>
      h(
        'span',
        { class: row.read ? '' : 'text-bold' },
        row.title,
      ),
  },
  {
    title: '内容',
    key: 'content',
    ellipsis: { tooltip: true },
  },
  {
    title: '时间',
    key: 'created_at',
    width: 170,
    render: (row: Notification) =>
      h('span', { class: 'text-muted' }, formatTime(row.created_at)),
  },
  {
    title: '操作',
    key: 'actions',
    width: 130,
    render: (row: Notification) =>
      h(NSpace, { size: 6 }, () => [
        !row.read
          ? h(
              NButton,
              {
                size: 'tiny',
                quaternary: true,
                type: 'primary',
                onClick: () => onMarkRead(row),
              },
              () => '标记已读',
            )
          : null,
        row.link
          ? h(
              NButton,
              {
                size: 'tiny',
                quaternary: true,
                type: 'info',
                onClick: () => router.push(row.link),
              },
              () => '查看',
            )
          : null,
      ]),
  },
];

const subtitle = computed(() => {
  const parts: string[] = [];
  if (unreadCount.value > 0) {
    parts.push(`${unreadCount.value} 条未读`);
  }
  if (total.value > 0) {
    parts.push(`共 ${total.value} 条`);
  }
  return parts.length > 0 ? parts.join('，') : '暂无新通知';
});

function formatTime(raw?: string) {
  if (!raw) return '';
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return raw;
  const diff = Date.now() - d.getTime();
  if (diff < 60_000) return '刚刚';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

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
  } catch {
    message.error('获取通知失败');
  } finally {
    loading.value = false;
  }
}

async function fetchUnread() {
  try {
    const res: any = await getUnreadCount();
    const body = res?.data ?? res;
    unreadCount.value = body?.count ?? 0;
  } catch {
    /* ignore */
  }
}

async function onMarkRead(item: Notification) {
  try {
    await markRead(item.id);
    item.read = true;
    unreadCount.value = Math.max(0, unreadCount.value - 1);
  } catch {
    /* ignore */
  }
}

async function onMarkAllRead() {
  try {
    await markAllRead();
    notifications.value.forEach((n) => {
      n.read = true;
    });
    unreadCount.value = 0;
    message.success('已全部标记为已读');
  } catch {
    message.error('操作失败');
  }
}

onMounted(() => {
  fetchList();
  fetchUnread();
});
</script>

<template>
  <BasePageContainer
    title="通知中心"
    :subtitle="subtitle"
  >
    <template #actions>
      <NButton
        size="small"
        type="primary"
        :disabled="unreadCount === 0"
        @click="onMarkAllRead"
      >
        全部已读
      </NButton>
    </template>

    <div class="notify-toolbar">
      <NSpace size="small">
        <NSelect
          v-model:value="readFilter"
          :options="readOptions"
          style="width: 100px"
          size="small"
          @update:value="fetchList"
        />
        <NSelect
          v-model:value="typeFilter"
          :options="typeOptions"
          style="width: 140px"
          size="small"
          clearable
          placeholder="类型筛选"
          @update:value="fetchList"
        />
      </NSpace>
    </div>

    <NEmpty
      v-if="notifications.length === 0 && !loading"
      description="暂无通知"
      class="notify-empty"
    />
    <NDataTable
      v-else
      :columns="columns"
      :data="notifications"
      :loading="loading"
      :bordered="false"
      size="small"
      :row-class-name="(row: Notification) => row.read ? 'notify-row-read' : ''"
    />
  </BasePageContainer>
</template>

<style scoped>
.notify-toolbar {
  margin-bottom: 14px;
}

.notify-empty {
  padding: 60px 0;
}

.dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 999px;
}

.dot-unread {
  background: hsl(var(--primary));
  box-shadow: 0 0 0 3px hsl(var(--primary) / 0.12);
}

.dot-read {
  background: hsl(var(--muted-foreground) / 0.2);
}

.text-bold {
  font-weight: 600;
}

.text-muted {
  font-size: 12px;
  color: hsl(var(--muted-foreground));
}

:deep(.notify-row-read td) {
  opacity: 0.6;
}
</style>
