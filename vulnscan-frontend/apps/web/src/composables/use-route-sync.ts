import type { RouteRecordRaw } from 'vue-router';

import type { SyncMenuItem } from '#/api/authorize/menu';

import {
  getRoutePerms,
  pathToNamespace,
  buildPermCode,
} from '#/permissions/route-perm';
import { accessRoutes } from '#/router/routes';

function resolveComponentPath(route: RouteRecordRaw): string | undefined {
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
  const title = (meta.title as string) || name;
  if (!name) return null;

  let fullPath = route.path || '';
  if (parentPath && !fullPath.startsWith('/')) {
    fullPath = `${parentPath}/${fullPath}`.replace(/\/+/g, '/');
  }

  const componentPath = resolveComponentPath(route);

  // 纯重定向兼容项不同步到 IAM（避免在仪表盘等模块下多出「扫描报告」等菜单）
  if (route.redirect && !componentPath && !(route.children?.length)) {
    return null;
  }

  const isDetailPage =
    meta.hideInMenu === true && !!(meta.activePath || !meta.icon);

  const item: SyncMenuItem = {
    name,
    title,
    path: fullPath,
    component: componentPath,
    icon: (meta.icon as string) || undefined,
    rank: (meta.order as number) || (meta.rank as number) || undefined,
    redirect: (route.redirect as string) || undefined,
    hide_in_menu: isDetailPage ? true : undefined,
    // IAM FrontendItem.show_link 缺省为 false，同步时必须显式 true 才能在侧栏显示
    show_link: isDetailPage ? false : true,
    menu_type: 1,
  };

  const children: SyncMenuItem[] = [];

  if (route.children?.length) {
    for (const child of route.children) {
      const childItem = routeToSyncItem(child, fullPath);
      if (childItem) children.push(childItem);
    }
  }

  const perms = getRoutePerms(meta);
  if (perms.length > 0) {
    const ns = pathToNamespace(fullPath);
    for (const p of perms) {
      children.push({
        name: `${name}__${p.action}`,
        title: p.title,
        unique_value: buildPermCode(ns, p.action),
        menu_type: 4,
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
      title: (meta.title as string) || name,
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
