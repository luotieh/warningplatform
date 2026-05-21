<script setup lang="ts">
import { computed, ref } from 'vue';
import {
  NCard,
  NButton,
  NAlert,
  NResult,
  NDescriptions,
  NDescriptionsItem,
  NSpace,
  NTag,
  NDataTable,
  useMessage,
} from 'naive-ui';

import { syncFrontendRoutes } from '#/api/authorize/menu';
import {
  auditRouteManifest,
  collectRouteManifest,
} from '#/composables/use-route-sync';
import { usePerm } from '#/composables/usePerm';
import { shouldUseLocalFullMenus } from '#/permissions/admin-role';
import { isBackendAccessMode } from '#/permissions/access-mode';
import { useAccessStore, useUserStore } from '@vben/stores';

const message = useMessage();
const userStore = useUserStore();
const accessStore = useAccessStore();
const { can, isSuper } = usePerm();
const syncing = ref(false);

/** 能打开本页或持有同步权限码即可操作（避免 IAM 未分配按钮码时按钮被 v-perm 移除） */
const canSyncMenu = computed(
  () =>
    isSuper.value ||
    shouldUseLocalFullMenus(
      userStore.userRoles,
      [...(accessStore.accessCodes || [])],
      userStore.userInfo,
    ) ||
    can('system:init:sync-menu'),
);
const synced = ref(false);
const syncResult = ref<{
  created: number;
  updated: number;
  unchanged: number;
} | null>(null);
const manifest = collectRouteManifest();
const auditRows = auditRouteManifest();

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

const missingPermPages = computed(() =>
  auditRows.filter((r) => r.missingPerms),
);

const auditColumns = [
  { title: '菜单路径', key: 'path', width: 220 },
  { title: '标题', key: 'title', width: 140 },
  { title: '路由名', key: 'name', width: 160 },
  {
    title: '按钮声明',
    key: 'buttonCount',
    width: 100,
    render: (row: (typeof auditRows)[0]) =>
      row.missingPerms
        ? '未配置'
        : `${row.buttonCount} 个`,
  },
];

async function handleSync() {
  syncing.value = true;
  try {
    const result = await syncFrontendRoutes(manifest);
    syncResult.value = result;
    synced.value = true;
    message.success('菜单同步成功！请在 IAM 后台为角色分配菜单与按钮权限');
  } catch (e: any) {
    const msg =
      e?.response?.data?.msg ??
      e?.response?.data?.message ??
      e?.message ??
      '未知错误';
    message.error(`同步失败: ${msg}`);
  } finally {
    syncing.value = false;
  }
}
</script>

<template>
  <div style="max-width: 960px; margin: 40px auto; padding: 0 16px">
    <NCard title="系统初始化" size="large">
      <template #header-extra>
        <NSpace>
          <NTag :type="isBackendAccessMode() ? 'success' : 'warning'" size="small">
            {{ isBackendAccessMode() ? '后端菜单模式' : '前端路由模式' }}
          </NTag>
          <NTag type="warning" size="small">仅管理员可见</NTag>
        </NSpace>
      </template>

      <NAlert type="info" title="生产环境菜单权限" style="margin-bottom: 16px">
        当前系统使用 <strong>后端菜单模式</strong>：侧栏与页面路由以 IAM
        <code>/me/menus</code> 返回为准；按钮以路由 <code>meta.perms</code> 同步到 IAM 后的权限码为准。
        若仍能看到全部菜单，请检查：① 是否在本页完成「同步菜单到 IAM」；② IAM 是否为该角色只分配了部分菜单；
        ③ 开发环境勿开启 <code>VITE_ALLOW_ACCESS_FALLBACK=true</code>（会回退为前端全量路由）。
        部署后请为各角色勾选菜单与按钮，用户需<strong>重新登录</strong>生效。
      </NAlert>

      <NDescriptions label-placement="left" bordered :column="2">
        <NDescriptionsItem label="待同步菜单模块">
          {{ menuCount }} 个
        </NDescriptionsItem>
        <NDescriptionsItem label="待同步按钮权限">
          {{ buttonCount }} 个
        </NDescriptionsItem>
        <NDescriptionsItem label="未声明按钮的菜单页">
          <NTag :type="missingPermPages.length ? 'warning' : 'success'" size="small">
            {{ missingPermPages.length }} 个
          </NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="访问模式">
          backend（IAM）
        </NDescriptionsItem>
      </NDescriptions>

      <NAlert
        v-if="missingPermPages.length"
        type="warning"
        title="部分菜单页未配置 meta.perms"
        style="margin-top: 16px"
      >
        下列页面同步到 IAM 后只有菜单、没有可分配的按钮权限；若页面上有操作按钮，请在对应路由模块补充
        <code>meta.perms</code> 后重新同步。
      </NAlert>

      <NDataTable
        v-if="missingPermPages.length"
        style="margin-top: 12px"
        size="small"
        :columns="auditColumns"
        :data="missingPermPages"
        :max-height="280"
      />

      <NSpace vertical style="margin-top: 24px">
        <NButton
          v-if="canSyncMenu"
          type="primary"
          size="large"
          block
          :loading="syncing"
          @click="handleSync"
        >
          {{ syncing ? '同步中...' : '同步菜单到 IAM' }}
        </NButton>
        <NAlert
          v-else
          type="warning"
          style="margin-top: 8px"
          title="无同步权限"
        >
          当前账号缺少权限码 <code>system:init:sync-menu</code>。请使用管理员账号登录，或在 IAM
          为角色分配「系统初始化 → 同步菜单到 IAM」按钮后重新登录。
        </NAlert>

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
