import { useAccessStore, useUserStore } from '@vben/stores';

import { isStrictButtonPerm } from '#/permissions/access-mode';
import { isAdminRole } from '#/permissions/admin-role';

/** IAM 下发的通配权限（仅此后端显式授予时视为超级权限） */
export function hasIamWildcard(codes: Set<string>): boolean {
  return codes.has('*:*');
}

/**
 * 是否对按钮/操作放行（后端模式下仅认 IAM 权限码，不认本地 admin 角色名）
 */
export function canAccessCodes(
  required: string[],
  options?: { requireAll?: boolean },
): boolean {
  if (!required.length) return true;

  const accessStore = useAccessStore();
  const codes = new Set(accessStore.accessCodes || []);

  if (hasIamWildcard(codes)) return true;

  const userStore = useUserStore();
  if (isAdminRole(userStore.userRoles as string[] | undefined)) return true;

  const hit = (c: string) => {
    if (codes.has(c)) return true;
    const parts = c.split(':');
    const ns = parts.length >= 2 ? parts.slice(0, 2).join(':') : c;
    let nsConfigured = false;
    for (const cc of codes) {
      if (cc === ns || cc.startsWith(`${ns}:`)) {
        nsConfigured = true;
        break;
      }
    }
    return !nsConfigured;
  };
  return options?.requireAll
    ? required.every(hit)
    : required.some(hit);
}

/** 开发环境是否允许 IAM 菜单失败时回退为前端全量路由 */
export function allowFrontendAccessFallback(): boolean {
  return import.meta.env.VITE_ALLOW_ACCESS_FALLBACK === 'true';
}
