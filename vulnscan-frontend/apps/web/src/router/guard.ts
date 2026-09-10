import type { Router } from 'vue-router';

import { LOGIN_PATH } from '@vben/constants';
import { preferences } from '@vben/preferences';
import { useAccessStore, useUserStore } from '@vben/stores';
import { startProgress, stopProgress } from '@vben/utils';

import { accessRoutes, coreRouteNames } from '#/router/routes';
import { useAuthStore } from '#/store';
import { isSSOMode, redirectToSSO } from '#/utils/sso';

import { ensureAccessMenusForPrivileged, generateAccess } from './access';

function setupCommonGuard(router: Router) {
  const loadedPaths = new Set<string>();

  router.beforeEach((to) => {
    to.meta.loaded = loadedPaths.has(to.path);
    if (!to.meta.loaded && preferences.transition.progress) {
      startProgress();
    }
    return true;
  });

  router.afterEach((to) => {
    loadedPaths.add(to.path);
    if (preferences.transition.progress) {
      stopProgress();
    }
  });
}

function redirectToLogin(toFullPath: string) {
  if (isSSOMode()) {
    redirectToSSO(toFullPath);
    return false;
  }

  return {
    path: LOGIN_PATH,
    query:
      toFullPath === preferences.app.defaultHomePath
        ? {}
        : { redirect: encodeURIComponent(toFullPath) },
    replace: true,
  };
}

function setupAccessGuard(router: Router) {
  router.beforeEach(async (to, from) => {
    const accessStore = useAccessStore();
    const userStore = useUserStore();
    const authStore = useAuthStore();

    const skipAuth = import.meta.env.VITE_SKIP_AUTH === 'true';

    // 开发模式（VITE_SKIP_AUTH=true）强制使用本地模拟态：即使浏览器残留了旧的
    // IAM token/用户信息也一律覆盖，避免残留态触发 /iam/profile 401 → 登录页 ↔ 首页
    // 无限重定向（认证跳转循环）。
    if (skipAuth) {
      accessStore.setAccessToken('dev-mock-token');
      userStore.setUserInfo({
        realName: '开发者',
        roles: ['super'],
        userId: 'dev-user',
        username: 'dev',
      } as any);
      accessStore.setAccessCodes(['*:*']);
    }

    if (coreRouteNames.includes(to.name as string)) {
      // 仅当本次会话已通过服务端校验（isAccessChecked）才把登录页弹回首页：
      // 只凭 localStorage 里存在令牌就弹回，遇到过期令牌会与“接口 401 → 跳登录”
      // 互相弹跳，形成无限刷新循环。
      if (
        to.path === LOGIN_PATH &&
        accessStore.accessToken &&
        accessStore.isAccessChecked
      ) {
        return decodeURIComponent(
          (to.query?.redirect as string) ||
            userStore.userInfo?.homePath ||
            preferences.app.defaultHomePath,
        );
      }
      return true;
    }

    if (!accessStore.accessToken) {
      if (to.meta.ignoreAccess) {
        return true;
      }
      if (to.fullPath !== LOGIN_PATH) {
        return redirectToLogin(to.fullPath);
      }
      return to;
    }

    // 仅判断 isAccessChecked，勿因 accessMenus 为空反复重置（否则会无限请求 /me/menus）
    if (accessStore.isAccessChecked) {
      return true;
    }

    try {
      let userInfo;
      if (skipAuth) {
        userInfo = userStore.userInfo || {
          realName: '开发者',
          roles: ['super'],
          userId: 'dev-user',
          username: 'dev',
        };
        userStore.setUserInfo(userInfo as any);
      } else {
        userInfo = userStore.userInfo || (await authStore.fetchUserInfo());
      }
      const userRoles = (userInfo as any).roles ?? [];

      const accessOptions = {
        roles: userRoles,
        router,
        routes: accessRoutes,
      };

      let { accessibleMenus, accessibleRoutes } =
        await generateAccess(accessOptions);

      if ((accessibleMenus?.length ?? 0) === 0) {
        const fallback = await ensureAccessMenusForPrivileged(accessOptions);
        if (fallback) {
          accessibleMenus = fallback.accessibleMenus;
          accessibleRoutes = fallback.accessibleRoutes;
        }
      }

      accessStore.setAccessMenus(accessibleMenus);
      accessStore.setAccessRoutes(accessibleRoutes);
      accessStore.setIsAccessChecked(true);

      const homePath = '/workbench/overview';
      const redirectPath = (from.query.redirect ??
        (to.path === homePath || to.path === '/' || to.path === '/workbench' || to.path === '/dashboard' || to.path === '/dashboard/overview'
          ? (userInfo as any).homePath || homePath
          : to.fullPath)) as string;
      const resolved = decodeURIComponent(String(redirectPath));

      return {
        ...router.resolve(resolved),
        replace: true,
      };
    } catch {
      accessStore.setAccessToken(null);
      if (skipAuth) return true;
      return redirectToLogin(to.fullPath);
    }
  });
}

function createRouterGuard(router: Router) {
  setupCommonGuard(router);
  setupAccessGuard(router);
}

export { createRouterGuard };
