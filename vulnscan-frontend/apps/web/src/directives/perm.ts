/**
 * v-perm 指令：按钮级权限控制
 *
 * 用法：
 *   v-perm="'user:create'"                        // 单个权限
 *   v-perm="['user:update', 'user:delete']"       // 任意一个即可（OR）
 *   v-perm.all="['user:update', 'user:delete']"   // 全部满足（AND）
 *   v-perm.disable="'user:create'"                // 无权限时禁用而非移除
 *   v-perm.hide="'user:create'"                   // 无权限时移除（默认行为）
 *
 * 与官方 v-access:code 的区别：
 *   - 支持 .all 修饰符（AND）
 *   - 支持 .disable 修饰符（无权限禁用元素而非移除，便于保留布局位置）
 *   - 默认 codes 为空 / undefined 时不限制（不删除节点）
 */
import type { App, Directive, DirectiveBinding } from 'vue';

import { useAccessStore, useUserStore } from '@vben/stores';

type PermValue = string | string[] | undefined | null;

const ADMIN_ROLES = new Set(['super', 'admin', 'administrator', 'superadmin']);

function getNamespace(code: string): string {
  const parts = code.split(':');
  return parts.length < 2 ? code : parts.slice(0, 2).join(':');
}

function checkPerm(value: PermValue, all: boolean): boolean {
  if (!value) return true;
  const accessStore = useAccessStore();
  const userStore = useUserStore();
  const list = (Array.isArray(value) ? value : [value]).filter(Boolean);
  if (list.length === 0) return true;

  const codes = new Set(accessStore.accessCodes || []);
  const roles = new Set(userStore.userRoles || []);

  if (codes.has('*:*')) return true;
  for (const r of roles) {
    if (ADMIN_ROLES.has(String(r).toLowerCase())) return true;
  }

  const checkOne = (c: string) => {
    if (codes.has(c)) return true;
    const ns = getNamespace(c);
    for (const cc of codes) {
      if (cc === ns || cc.startsWith(`${ns}:`)) return false;
    }
    return true;
  };

  return all ? list.every(checkOne) : list.some(checkOne);
}

function applyDisable(el: HTMLElement) {
  el.style.pointerEvents = 'none';
  el.style.opacity = '0.5';
  el.style.cursor = 'not-allowed';
  el.setAttribute('disabled', 'disabled');
  el.setAttribute('aria-disabled', 'true');
  el.dataset.permDisabled = '1';
}

function update(el: HTMLElement, binding: DirectiveBinding<PermValue>) {
  const all = !!binding.modifiers.all;
  const ok = checkPerm(binding.value, all);
  if (ok) {
    if (el.dataset.permDisabled) {
      el.style.pointerEvents = '';
      el.style.opacity = '';
      el.style.cursor = '';
      el.removeAttribute('disabled');
      el.removeAttribute('aria-disabled');
      delete el.dataset.permDisabled;
    }
    return;
  }

  if (binding.modifiers.disable) {
    applyDisable(el);
  } else {
    el.parentNode?.removeChild(el);
  }
}

const permDirective: Directive<HTMLElement, PermValue> = {
  mounted(el, binding) {
    update(el, binding);
  },
  updated(el, binding) {
    if (binding.value === binding.oldValue) return;
    update(el, binding);
  },
};

export function registerPermDirective(app: App) {
  app.directive('perm', permDirective);
}

export { permDirective };
