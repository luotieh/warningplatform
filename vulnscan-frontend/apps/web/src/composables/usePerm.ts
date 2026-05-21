/**
 * 权限工具
 * - usePerm()：在 setup 中判断用户是否拥有某些权限码
 * - v-perm 指令：用法见 directives/perm.ts
 *
 * 权限码来源：accessStore.accessCodes（由 getAccessCodesApi 从 IAM /me/menus 收集）
 *
 * 后端模式（accessMode=backend）：
 *   - 仅 *:* 通配放行；不再因本地 admin 角色名或未配置 namespace 而默认放行
 *   - 未声明 v-perm / can() 的按钮仍会显示（需在页面补充权限绑定）
 */
import { computed } from 'vue';

import { useAccessStore } from '@vben/stores';

import { canAccessCodes, hasIamWildcard } from '#/permissions/access-check';
import { isStrictButtonPerm } from '#/permissions/access-mode';

export type PermInput = string | string[];

function toArray(input: PermInput): string[] {
  return Array.isArray(input) ? input : [input];
}

function getNamespace(code: string): string {
  const parts = code.split(':');
  if (parts.length < 2) return code;
  return parts.slice(0, 2).join(':');
}

export function usePerm() {
  const accessStore = useAccessStore();

  const codes = computed(() => new Set(accessStore.accessCodes || []));

  const isSuper = computed(() => hasIamWildcard(codes.value));

  function namespaceRegistered(ns: string): boolean {
    for (const c of codes.value) {
      if (c === ns || c.startsWith(`${ns}:`)) return true;
    }
    return false;
  }

  function checkOne(code: string): boolean {
    if (codes.value.has(code)) return true;
    if (isStrictButtonPerm()) return false;
    const ns = getNamespace(code);
    if (!namespaceRegistered(ns)) return true;
    return false;
  }

  function canAny(input: PermInput): boolean {
    const list = toArray(input).filter(Boolean);
    if (list.length === 0) return true;
    if (isStrictButtonPerm()) {
      return canAccessCodes(list, { requireAll: false });
    }
    if (isSuper.value) return true;
    return list.some((c) => checkOne(c));
  }

  function canAll(input: PermInput): boolean {
    const list = toArray(input).filter(Boolean);
    if (list.length === 0) return true;
    if (isStrictButtonPerm()) {
      return canAccessCodes(list, { requireAll: true });
    }
    if (isSuper.value) return true;
    return list.every((c) => checkOne(c));
  }

  function can(input: PermInput): boolean {
    return canAny(input);
  }

  function hasRole(_input: PermInput): boolean {
    return isSuper.value;
  }

  return {
    can,
    canAll,
    canAny,
    hasRole,
    isSuper,
    accessCodes: codes,
  };
}
