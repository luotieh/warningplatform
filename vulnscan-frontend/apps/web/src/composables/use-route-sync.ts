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
