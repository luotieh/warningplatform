import { useRoute } from 'vue-router';

import { createPermResolver } from '#/permissions/route-perm';

/** 去掉动态段，使详情页复用列表页权限命名空间 */
export function normalizePermRoutePath(path: string): string {
  return path
    .replace(/\/:[^/]+/g, '')
    .replace(/\/+/g, '/')
    .replace(/\/$/, '') || '/';
}

/**
 * 基于当前路由（或指定路径）生成权限码，如 perm('create') => 'scan:task:create'
 */
export function useRoutePerm(fallbackPath?: string) {
  const route = useRoute();
  const base = fallbackPath || normalizePermRoutePath(route.path);
  const perm = createPermResolver(base);
  return { perm, namespacePath: base };
}
