import type { RouteRecordStringComponent } from '@vben/types';

import { getUserMenusApi } from './auth';

/**
 * 后端 VisibleMenu 结构
 */
export interface IamMenu {
  id: string;
  app: string;
  parent_id: string;
  menu_type: string | number;
  title: string;
  name: string;
  path: string;
  component: string;
  redirect?: string;
  icon?: string;
  sort: number;
  show_link?: boolean;
  hide_in_menu?: boolean;
  unique_value?: string;
  children?: IamMenu[];
  buttons?: IamMenu[];
}

export interface IamAppMenuGroup {
  app_id: string;
  app_name: string;
  menus: IamMenu[];
}

function isButtonMenu(menu: IamMenu): boolean {
  const t = menu.menu_type;
  return t === 4 || t === '4';
}

function shouldHideInMenu(menu: IamMenu): boolean {
  const t = menu.menu_type;
  if (t === 3 || t === '3') return true;
  if (menu.hide_in_menu === true) return true;
  // IAM 后端返回的目录菜单(1/2)可能只有 redirect 没有 component，不应隐藏
  if (t === 1 || t === '1' || t === 2 || t === '2') return false;
  if (menu.redirect && !menu.component) return true;
  return menu.show_link === false;
}

/** 可用于侧栏展示的菜单路由数量 */
export function countVisibleMenuRoutes(
  routes: RouteRecordStringComponent[],
): number {
  let count = 0;
  const walk = (list: RouteRecordStringComponent[]) => {
    for (const route of list) {
      if (!route.meta?.hideInMenu) count += 1;
      if (route.children?.length) walk(route.children);
    }
  };
  walk(routes);
  return count;
}

/**
 * 兼容 IAM 多种 /iam/menus 响应结构
 */
export function normalizeMenuGroups(raw: unknown): IamAppMenuGroup[] {
  if (!raw) return [];

  if (Array.isArray(raw)) {
    if (raw.length === 0) return [];
    const first = raw[0] as Record<string, unknown>;
    if (Array.isArray(first.menus)) {
      return raw.map((g: Record<string, unknown>) => ({
        app_id: String(g.app_id ?? g.appId ?? g.AppID ?? ''),
        app_name: String(g.app_name ?? g.appName ?? ''),
        menus: (g.menus as IamMenu[]) ?? [],
      }));
    }
    if (first.path || first.name || first.title) {
      return [{ app_id: '', app_name: '', menus: raw as IamMenu[] }];
    }
    return [];
  }

  if (typeof raw === 'object') {
    const o = raw as Record<string, unknown>;
    if (Array.isArray(o.menus)) {
      return [
        {
          app_id: String(o.app_id ?? o.appId ?? ''),
          app_name: String(o.app_name ?? o.appName ?? ''),
          menus: o.menus as IamMenu[],
        },
      ];
    }
    if (Array.isArray(o.applications)) {
      return (o.applications as Record<string, unknown>[]).map((app) => ({
        app_id: String(app.id ?? app.app_id ?? app.client_id ?? ''),
        app_name: String(app.app_name ?? app.display_name ?? app.name ?? ''),
        menus: (app.menus as IamMenu[]) ?? [],
      }));
    }
    if (Array.isArray(o.data)) {
      return normalizeMenuGroups(o.data);
    }
  }

  return [];
}

/**
 * menu_type:
 *  "1" = 菜单（常规）
 *  "2" = iframe（外链嵌入）
 *  "3" = 额外页面（不在菜单中显示）
 *  "4" = 按钮权限
 */
function transformMenuToRoute(menu: IamMenu): RouteRecordStringComponent | null {
  if (isButtonMenu(menu)) return null;

  const routeChildren: IamMenu[] = [];
  const buttons: IamMenu[] = [...(menu.buttons ?? [])];

  for (const child of menu.children ?? []) {
    if (isButtonMenu(child)) {
      buttons.push(child);
    } else {
      routeChildren.push(child);
    }
  }

  const route: RouteRecordStringComponent = {
    name: menu.name,
    path: menu.path,
    component: menu.component || 'BasicLayout',
    meta: {
      title: menu.title || menu.name,
      icon: menu.icon,
      order: menu.sort,
      hideInMenu: shouldHideInMenu(menu),
    },
  };

  const menuType = menu.menu_type;
  if ((menuType === 2 || menuType === '2') && menu.path) {
    (route.meta as Record<string, unknown>).iframeSrc = menu.path;
  }

  if (menu.redirect) {
    route.redirect = menu.redirect;
  }

  if (routeChildren.length > 0) {
    route.children = routeChildren
      .map(transformMenuToRoute)
      .filter((r): r is RouteRecordStringComponent => r != null);
  }

  if (buttons.length > 0) {
    const authority = buttons
      .map((b) => b.unique_value || b.name || b.id)
      .filter(Boolean);
    (route.meta as Record<string, unknown>).authority = authority;
  }

  return route;
}

/**
 * 获取菜单（路由）列表
 */
export async function getAllMenusApi(
  appId?: string,
  reconcile?: (idsWithMenus: string[]) => string | undefined,
): Promise<RouteRecordStringComponent[]> {
  const raw = await getUserMenusApi(appId);
  const menuGroups = normalizeMenuGroups(raw);

  let effectiveAppId = appId;
  if (reconcile) {
    const idsWithMenus = menuGroups
      .filter((g) => Array.isArray(g.menus) && g.menus.length > 0)
      .map((g) => g.app_id);
    const reconciled = reconcile(idsWithMenus);
    if (reconciled !== undefined) {
      effectiveAppId = reconciled;
    }
  }

  const allMenus: IamMenu[] = [];
  for (const group of menuGroups) {
    if (effectiveAppId && group.app_id && group.app_id !== effectiveAppId) {
      continue;
    }
    if (group.menus?.length) {
      allMenus.push(...group.menus);
    }
  }

  return allMenus
    .map(transformMenuToRoute)
    .filter((r): r is RouteRecordStringComponent => r != null);
}
