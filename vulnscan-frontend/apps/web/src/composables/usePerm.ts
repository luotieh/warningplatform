/**
 * 权限工具
 * - usePerm()：在 setup 中判断用户是否拥有某些权限码
 * - v-perm 指令：用法见 directives/perm.ts
 *
 * 权限码来源：accessStore.accessCodes（由 getAccessCodesApi 收集自后端 /me/profile）
 *
 * 智能放行规则（按以下顺序判断，命中即放行）：
 *   1) 用户拥有 super 角色，或拥有通配权限 *:*
 *   2) 用户的 userRoles 中包含常见管理员角色（admin / administrator / superadmin）
 *   3) 待校验的权限码所在 namespace（前两段，例如 identity:user）在 accessCodes 中
 *      没有任何同 namespace 的权限码 —— 视为系统尚未开启按钮级权限，默认放行
 *   4) 否则严格校验 accessCodes 是否包含该码
 */
import { computed } from 'vue';

import { useAccessStore, useUserStore } from '@vben/stores';

export type PermInput = string | string[];

const ADMIN_ROLES = new Set(['super', 'admin', 'administrator', 'superadmin']);

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
  const userStore = useUserStore();

  const codes = computed(() => new Set(accessStore.accessCodes || []));
  const roles = computed(() => new Set(userStore.userRoles || []));

  /** 是否为管理员（拥有 super/admin 角色 或 *:* 通配） */
  const isSuper = computed(() => {
    if (codes.value.has('*:*')) return true;
    for (const r of roles.value) {
      if (ADMIN_ROLES.has(String(r).toLowerCase())) return true;
    }
    return false;
  });

  /**
   * 命名空间是否在系统中已注册任何按钮级权限码
   * 如果没有任何同命名空间码 —— 说明系统未启用此模块的按钮权限，应默认放行
   */
  function namespaceRegistered(ns: string): boolean {
    for (const c of codes.value) {
      if (c === ns || c.startsWith(`${ns}:`)) return true;
    }
    return false;
  }

  function checkOne(code: string): boolean {
    if (codes.value.has(code)) return true;
    const ns = getNamespace(code);
    if (!namespaceRegistered(ns)) return true;
    return false;
  }

  function canAny(input: PermInput): boolean {
    if (isSuper.value) return true;
    const list = toArray(input).filter(Boolean);
    if (list.length === 0) return true;
    return list.some((c) => checkOne(c));
  }

  function canAll(input: PermInput): boolean {
    if (isSuper.value) return true;
    const list = toArray(input).filter(Boolean);
    if (list.length === 0) return true;
    return list.every((c) => checkOne(c));
  }

  function can(input: PermInput): boolean {
    return canAny(input);
  }

  function hasRole(input: PermInput): boolean {
    if (isSuper.value) return true;
    return toArray(input).some((r) => roles.value.has(r));
  }

  return {
    can,
    canAll,
    canAny,
    hasRole,
    isSuper,
    accessCodes: codes,
    userRoles: roles,
  };
}
