<script lang="ts" setup>
import { onMounted, ref } from 'vue';

import {
  NAlert,
  NButton,
  NEmpty,
  NList,
  NListItem,
  NPopconfirm,
  NSpin,
  NTag,
  NThing,
} from 'naive-ui';

import {
  type ProfileApi,
  listSessions,
  logoutAllSessions,
} from '#/api/core/profile';
import { message } from '#/adapter/naive';
import { useAuthStore } from '#/store';

const authStore = useAuthStore();

const loading = ref(false);
const submitting = ref(false);
const sessions = ref<ProfileApi.SessionItem[]>([]);

function formatTime(ts?: number) {
  if (!ts) return '-';
  const ms = ts < 1e12 ? ts * 1000 : ts;
  return new Date(ms).toLocaleString();
}

async function load() {
  loading.value = true;
  try {
    sessions.value = (await listSessions()) ?? [];
  } catch {
    sessions.value = [];
  } finally {
    loading.value = false;
  }
}

async function handleLogoutAll() {
  submitting.value = true;
  try {
    await logoutAllSessions();
    message.success('所有会话已注销，需重新登录');
    setTimeout(() => {
      authStore.logout();
    }, 800);
  } catch (error: any) {
    message.error(error?.message || '操作失败');
  } finally {
    submitting.value = false;
  }
}

onMounted(load);
</script>

<template>
  <NSpin :show="loading">
    <NAlert type="info" class="mb-4" :show-icon="true">
      <div class="flex items-center justify-between gap-2">
        <span>
          展示当前账号所有有效的登录会话。如有可疑设备，建议立即注销全部会话并修改密码。
        </span>
        <NPopconfirm @positive-click="handleLogoutAll">
          <template #trigger>
            <NButton size="small" type="warning" :loading="submitting">
              注销全部会话
            </NButton>
          </template>
          确定要注销所有会话？您本次登录也将失效，需要重新登录。
        </NPopconfirm>
      </div>
    </NAlert>

    <div class="mb-3 flex items-center justify-between">
      <div class="text-base font-medium">
        活跃会话 ({{ sessions.length }})
      </div>
      <NButton size="small" @click="load">刷新</NButton>
    </div>

    <NList v-if="sessions.length > 0" bordered hoverable>
      <NListItem v-for="s in sessions" :key="s.session_id">
        <NThing :title="`会话 ${s.session_id.slice(0, 12)}…`">
          <template #header-extra>
            <NTag size="small" type="success">活跃</NTag>
          </template>
          <div class="text-muted-foreground text-xs">
            <div>登录时间：{{ formatTime(s.issued_at) }}</div>
            <div>最近活跃：{{ formatTime(s.last_active_at) }}</div>
            <div>过期时间：{{ formatTime(s.expires_at) }}</div>
            <div v-if="s.client_ip">IP：{{ s.client_ip }}</div>
            <div v-if="s.user_agent" class="truncate">
              UA：{{ s.user_agent }}
            </div>
          </div>
        </NThing>
      </NListItem>
    </NList>
    <NEmpty v-else description="暂无活跃会话" />
  </NSpin>
</template>
