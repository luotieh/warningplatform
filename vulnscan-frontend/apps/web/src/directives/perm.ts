/**
 * v-perm 指令：按钮级权限控制
 */
import type { App, Directive, DirectiveBinding } from 'vue';

import { useAccessStore, useUserStore } from '@vben/stores';

import { canAccessCodes } from '#/permissions/access-check';
import { isStrictButtonPerm } from '#/permissions/access-mode';

type PermValue = string | string[] | undefined | null;

const ADMIN_ROLES = new Set(['super', 'admin', 'administrator', 'superadmin']);

function getNamespace(code: string): string {
  const parts = code.split(':');
  return parts.length < 2 ? code : parts.slice(0, 2).join(':');
}

function checkPermLegacy(value: PermValue, all: boolean): boolean {
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

function checkPerm(value: PermValue, all: boolean): boolean {
  if (!value) return true;
  const list = (Array.isArray(value) ? value : [value]).filter(Boolean);
  if (list.length === 0) return true;

  if (isStrictButtonPerm()) {
    return canAccessCodes(list, { requireAll: all });
  }

  return checkPermLegacy(value, all);
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
