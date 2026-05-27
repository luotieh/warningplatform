import type {
  ComponentRecordType,
  GenerateMenuAndRoutesOptions,
} from '@vben/types';

import { generateAccessible } from '@vben/access';
import { useAccessStore, useUserStore } from '@vben/stores';

import { message } from '#/adapter/naive';
import { getAllMenusApi } from '#/api';
import { syncFrontendRoutes } from '#/api/authorize/menu';
import { countVisibleMenuRoutes } from '#/api/core/menu';
import { collectRouteManifest } from '#/composables/use-route-sync';
import { BasicLayout, IFrameView } from '#/layouts';
import { $t } from '#/locales';
import { allowFrontendAccessFallback } from '#/permissions/access-check';
import { isBackendAccessMode } from '#/permissions/access-mode';
import { shouldUseLocalFullMenus } from '#/permissions/admin-role';

const forbiddenComponent = () => import('#/views/_core/fallback/forbidden.vue');

/** 变更菜单结构时需 bump，以触发重新同步 */
const SYNC_DONE_KEY = 'vulnscan_menu_synced_v3';

const EMPTY_MENU_HINT =
  '后端未返回可用菜单。请联系管理员在「系统初始化」同步菜单到 IAM 并分配角色权限。';

const MENU_API_FAIL_HINT =
  '无法从 IAM 加载菜单（/iam/menus）。请确认已登录且后端 IAM 代理正常。';

function loadFrontendRoutes(options: GenerateMenuAndRoutesOptions) {
  const pageMap: ComponentRecordType = import.meta.glob('../views/**/*.vue');
  const layoutMap: ComponentRecordType = {
    BasicLayout,
    IFrameView,
  };
  return generateAccessible('frontend', {
    ...options,
    forbiddenComponent,
    layoutMap,
    pageMap,
  });
}

function resolveMenuContext(options: GenerateMenuAndRoutesOptions) {
  const userStore = useUserStore();
  const accessStore = useAccessStore();
  const roles = options.roles ?? userStore.userRoles ?? [];
  const accessCodes = accessStore.accessCodes;
  const userInfo = userStore.userInfo;
  const useLocalMenus = shouldUseLocalFullMenus(roles, accessCodes, userInfo);
  return { roles, accessCodes, userInfo, useLocalMenus };
}

async function generateAccess(options: GenerateMenuAndRoutesOptions) {
  const pageMap: ComponentRecordType = import.meta.glob('../views/**/*.vue');
  const layoutMap: ComponentRecordType = {
    BasicLayout,
    IFrameView,
  };

  const { roles, useLocalMenus } = resolveMenuContext(options);

  if (!isBackendAccessMode()) {
    return loadFrontendRoutes(options);
  }

  // 管理员 / 特权账号：始终用本地路由，保证侧栏不为空（按钮仍走 IAM accessCodes）
  if (useLocalMenus) {
    return loadFrontendRoutes(options);
  }

  message.loading(`${$t('common.loadingMenu')}...`, { duration: 1.5 });

  try {
    let menus = await getAllMenusApi();
    let hasMenuRoutes = menus?.length > 0 && countVisibleMenuRoutes(menus) > 0;

    const manifest = collectRouteManifest();
    const manifestHash =
      String(manifest.length) +
      ':' +
      manifest
        .map((m) => m.name)
        .sort()
        .join(',');
    const lastSyncHash = sessionStorage.getItem(SYNC_DONE_KEY);
    const needsSync = manifestHash !== lastSyncHash && manifest.length > 0;

    if (needsSync) {
      try {
        await syncFrontendRoutes(manifest);
        sessionStorage.setItem(SYNC_DONE_KEY, manifestHash);
        if (!hasMenuRoutes) {
          message.success('菜单初始化完成，正在加载...');
        }
        const retryMenus = await getAllMenusApi();
        if (retryMenus?.length > 0 && countVisibleMenuRoutes(retryMenus) > 0) {
          menus = retryMenus;
          hasMenuRoutes = true;
        }
      } catch (e) {
        console.warn('[Menu Auto-Sync] failed:', e);
      }
    }

    if (!hasMenuRoutes) {
      if (allowFrontendAccessFallback() || !import.meta.env.PROD) {
        message.warning(
          `${EMPTY_MENU_HINT} 开发环境已临时加载本地全量菜单。`,
          { duration: 8 },
        );
        return loadFrontendRoutes(options);
      }

      message.error(EMPTY_MENU_HINT, { duration: 10 });
      return generateAccessible('backend', {
        ...options,
        fetchMenuListAsync: async () => [],
        forbiddenComponent,
        layoutMap,
        pageMap,
      });
    }

    return generateAccessible('backend', {
      ...options,
      fetchMenuListAsync: async () => menus,
      forbiddenComponent,
      layoutMap,
      pageMap,
    });
  } catch (e) {
    message.error(MENU_API_FAIL_HINT, { duration: 8 });

    if (allowFrontendAccessFallback() || !import.meta.env.PROD) {
      return loadFrontendRoutes(options);
    }

    throw e instanceof Error ? e : new Error(MENU_API_FAIL_HINT);
  }
}

/** 侧栏为空时对特权用户强制重建本地菜单 */
export async function ensureAccessMenusForPrivileged(
  options: GenerateMenuAndRoutesOptions,
) {
  const accessStore = useAccessStore();
  if ((accessStore.accessMenus?.length ?? 0) > 0) {
    return null;
  }
  const { useLocalMenus } = resolveMenuContext(options);
  if (!useLocalMenus) return null;
  return loadFrontendRoutes(options);
}

export { generateAccess };
