<script setup lang="ts">
import { ref } from 'vue';
import {
  NCard,
  NButton,
  NAlert,
  NResult,
  NDescriptions,
  NDescriptionsItem,
  NSpace,
  NTag,
  useMessage,
} from 'naive-ui';

import { syncFrontendRoutes } from '#/api/authorize/menu';
import { collectRouteManifest } from '#/composables/use-route-sync';

const message = useMessage();
const syncing = ref(false);
const synced = ref(false);
const syncResult = ref<{
  created: number;
  updated: number;
  unchanged: number;
} | null>(null);
const manifest = collectRouteManifest();

const menuCount = manifest.length;
const buttonCount = manifest.reduce((sum, m) => {
  const countBtns = (items: typeof manifest): number =>
    items.reduce((s, i) => {
      const isBtnSelf = i.menu_type === 4 ? 1 : 0;
      const childBtns = i.children ? countBtns(i.children) : 0;
      return s + isBtnSelf + childBtns;
    }, 0);
  return sum + (m.children ? countBtns(m.children) : 0);
}, 0);

async function handleSync() {
  syncing.value = true;
  try {
    const result = await syncFrontendRoutes(manifest);
    syncResult.value = result;
    synced.value = true;
    message.success('菜单同步成功！请在 IAM 后台为角色分配菜单权限');
  } catch (e: any) {
    message.error(`同步失败: ${e?.message || '未知错误'}`);
  } finally {
    syncing.value = false;
  }
}
</script>

<template>
  <div style="max-width: 720px; margin: 40px auto; padding: 0 16px">
    <NCard title="系统初始化" size="large">
      <template #header-extra>
        <NTag type="warning" size="small">仅管理员可见</NTag>
      </template>

      <NAlert type="info" title="菜单权限同步" style="margin-bottom: 24px">
        将当前系统的前端菜单和按钮权限同步到 IAM 统一权限管理平台。
        同步后，管理员可在 IAM 后台的「角色管理 → 菜单权限」中控制各角色可见的菜单和按钮。
      </NAlert>

      <NDescriptions label-placement="left" bordered :column="1">
        <NDescriptionsItem label="菜单模块数">
          {{ menuCount }} 个
        </NDescriptionsItem>
        <NDescriptionsItem label="按钮权限数">
          {{ buttonCount }} 个
        </NDescriptionsItem>
      </NDescriptions>

      <NSpace vertical style="margin-top: 24px">
        <NButton
          type="primary"
          size="large"
          block
          :loading="syncing"
          @click="handleSync"
        >
          {{ syncing ? '同步中...' : '同步菜单到 IAM' }}
        </NButton>

        <NResult
          v-if="synced && syncResult"
          status="success"
          title="同步完成"
          :description="`新增 ${syncResult.created} 项，更新 ${syncResult.updated} 项，未变 ${syncResult.unchanged} 项`"
          style="margin-top: 16px"
        />
      </NSpace>
    </NCard>
  </div>
</template>
