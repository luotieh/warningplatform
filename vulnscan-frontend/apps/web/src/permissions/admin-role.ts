import type { UserInfo } from '@vben/types';

import { hasIamWildcard } from '#/permissions/access-check';

/** 识别管理员/特权账号（用于菜单兜底，便于进入系统初始化） */
const ADMIN_ROLE_KEYS = new Set([
  'super',
  'admin',
  'administrator',
  'superadmin',
  '管理员',
  '超级管理员',
  '系统管理员',
]);

export function isAdminRole(roles: string[] | undefined): boolean {
  if (!roles?.length) return false;
  return roles.some((role) => {
    const raw = String(role).trim();
    if (!raw) return false;
    const lower = raw.toLowerCase();
    if (ADMIN_ROLE_KEYS.has(raw) || ADMIN_ROLE_KEYS.has(lower)) return true;
    if (lower.includes('admin')) return true;
    if (raw.includes('管理员')) return true;
    return false;
  });
}

function nameLooksLikeAdmin(userInfo?: UserInfo | null): boolean {
  if (!userInfo) return false;
  const text = [userInfo.realName, userInfo.username, userInfo.desc]
    .filter(Boolean)
    .join(' ');
  return text.includes('管理员');
}

/**
 * 是否始终使用本地全量路由作为侧栏菜单（不依赖 IAM /me/menus 树）
 * 管理员 / 通配权限 / 显示名为管理员 均适用
 */
export function shouldUseLocalFullMenus(
  roles?: string[],
  accessCodes?: string[] | null,
  userInfo?: UserInfo | null,
): boolean {
  if (hasIamWildcard(new Set(accessCodes || []))) return true;
  if (isAdminRole(roles)) return true;
  if (nameLooksLikeAdmin(userInfo)) return true;
  return false;
}
