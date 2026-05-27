import type { RouteRecordRaw } from 'vue-router';

import type { SyncMenuItem } from '#/api/authorize/menu';

import { $t } from '#/locales';
import {
  getRouteApisByAction,
  getRouteApisForPageAccess,
  getRoutePerms,
  resolvePermNamespace,
  buildPermCode,
  validateRoutePermBindings,
} from '#/permissions/route-perm';
import { accessRoutes } from '#/router/routes';

function resolveTitle(raw: unknown): string {
  if (!raw) return '';
  const s = String(raw);
  if (/^[a-z]+(\.[a-z_]+)+$/i.test(s)) {
    const translated = $t(s);
    return translated && translated !== s ? translated : s;
  }
  return s;
}

/**
 * 从路由组件中提取组件路径字符串。
 *
 * 优先级：
 * 1. meta.component（手动声明的字符串路径）
 * 2. 从动态 import 函数的 toString() 中正则提取（仅开发环境可靠）
 *    例如 () => import('#/views/dashboard/analytics/index.vue')
 *    提取后得到 views/dashboard/analytics/index.vue
 */
function resolveComponentPath(
  route: RouteRecordRaw,
): string | undefined {
  const meta = (route.meta || {}) as Record<string, any>;
  if (meta.component && typeof meta.component === 'string') {
    return meta.component;
  }
  if (!route.component || typeof route.component !== 'function') {
    return undefined;
  }
  const fnStr = route.component.toString();
  const match = fnStr.match(
    /import\(\s*["'](?:#\/|\.\.\/|\.\/|\/src\/)(views\/[^"']+)["']\s*\)/,
  );
  return match?.[1] ?? undefined;
}

function routeToSyncItem(
  route: RouteRecordRaw,
  parentPath?: string,
): SyncMenuItem | null {
  const meta = (route.meta || {}) as Record<string, any>;

  const name = (route.name as string) || '';
  const title = resolveTitle(meta.title) || name;
  if (!name) return null;

  let fullPath = route.path || '';
  if (parentPath && !fullPath.startsWith('/')) {
    fullPath = `${parentPath}/${fullPath}`.replace(/\/+/g, '/');
  }
  // 清理路由参数前缀 ':' 避免 IAM 权限码产生双冒号（如 :id → id）
  const cleanPath = fullPath
    .split('/')
    .map((s) => (s.startsWith(':') ? s.slice(1) : s))
    .join('/');

  const componentPath = resolveComponentPath(route);

  const isDetailPage =
    meta.hideInMenu === true && !!(meta.activePath || !meta.icon);

  if (import.meta.env.DEV) {
    for (const issue of validateRoutePermBindings(meta)) {
      console.warn(`[route-sync] ${fullPath}: ${issue.message}`);
    }
  }

  const pageApis = getRouteApisForPageAccess(meta);

  let redirect: string | undefined;
  const rawRedirect = route.redirect;
  if (typeof rawRedirect === 'string') {
    redirect = rawRedirect;
  } else if (
    rawRedirect &&
    typeof rawRedirect === 'object' &&
    'path' in rawRedirect
  ) {
    const loc = rawRedirect as { path?: string; query?: Record<string, unknown> };
    const base = String(loc.path || '').trim();
    if (base) {
      const qs = loc.query
        ? new URLSearchParams(
            Object.entries(loc.query).map(([k, v]) => [k, String(v ?? '')]),
          ).toString()
        : '';
      redirect = qs ? `${base}?${qs}` : base;
    }
  }

  const item: SyncMenuItem = {
    name,
    title,
    path: cleanPath,
    component: componentPath,
    icon: (meta.icon as string) || undefined,
    rank: (meta.order as number) || (meta.rank as number) || undefined,
    redirect,
    hide_in_menu: isDetailPage ? true : undefined,
    menu_type: 1,
    backend_refs: pageApis.length > 0 ? pageApis : undefined,
  };

  const children: SyncMenuItem[] = [];

  if (route.children?.length) {
    for (const child of route.children) {
      const childItem = routeToSyncItem(child, fullPath);
      if (childItem) children.push(childItem);
    }
  }

  const perms = getRoutePerms(meta);
  const apisByAction = getRouteApisByAction(meta);
  if (perms.length > 0) {
    const ns = resolvePermNamespace(meta, cleanPath);
    const existed = new Set<string>();
    for (const p of perms) {
      const code = buildPermCode(ns, p.action);
      if (existed.has(code)) continue;
      existed.add(code);
      const btnRefs = apisByAction[p.action];
      children.push({
        name: `${name}__${p.action}`,
        title: p.title,
        unique_value: code,
        menu_type: 4,
        backend_refs: btnRefs?.length ? btnRefs : undefined,
      });
    }
  }

  if (children.length > 0) {
    item.children = children;
  }

  return item;
}

export function collectRouteManifest(): SyncMenuItem[] {
  const items: SyncMenuItem[] = [];
  for (const route of accessRoutes) {
    const item = routeToSyncItem(route);
    if (item) items.push(item);
  }
  return items;
}

export interface RoutePermAuditRow {
  path: string;
  title: string;
  name: string;
  buttonCount: number;
  missingPerms: boolean;
}

function walkAudit(
  route: RouteRecordRaw,
  parentPath: string | undefined,
  rows: RoutePermAuditRow[],
) {
  const meta = (route.meta || {}) as Record<string, any>;
  const name = (route.name as string) || '';
  let fullPath = route.path || '';
  if (parentPath && fullPath && !fullPath.startsWith('/')) {
    fullPath = `${parentPath}/${fullPath}`.replace(/\/+/g, '/');
  }
  const isMenuPage =
    name &&
    meta.hideInMenu !== true &&
    route.path !== '' &&
    !String(route.redirect || '').startsWith('http');
  if (isMenuPage) {
    const perms = getRoutePerms(meta);
    rows.push({
      path: fullPath,
      title: resolveTitle(meta.title) || name,
      name,
      buttonCount: perms.length,
      missingPerms: perms.length === 0,
    });
  }
  if (route.children?.length) {
    for (const child of route.children) {
      walkAudit(child, fullPath, rows);
    }
  }
}

/** 审计：哪些菜单页未声明 meta.perms（同步后 IAM 无按钮权限可分配） */
export function auditRouteManifest(): RoutePermAuditRow[] {
  const rows: RoutePermAuditRow[] = [];
  for (const route of accessRoutes) {
    walkAudit(route, undefined, rows);
  }
  return rows;
}
