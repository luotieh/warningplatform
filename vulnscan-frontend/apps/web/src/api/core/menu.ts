import type { RouteRecordStringComponent } from '@vben/types';

import { getUserMenusApi } from './auth';

/**
 * 后端 VisibleMenu 结构
 */
export interface IamMenu {
  id: string;
  app: string;
  parent_id: string;
  menu_type: string;
  title: string;
  name: string;
  path: string;
  component: string;
  redirect?: string;
  icon?: string;
  sort: number;
  show_link: boolean;
  children?: IamMenu[];
  buttons?: IamMenu[];
}

export interface IamAppMenuGroup {
  app_id: string;
  app_name: string;
  menus: IamMenu[];
}

/**
 * menu_type:
 *  "1" = 菜单（常规）
 *  "2" = iframe（外链嵌入）
 *  "3" = 额外页面（不在菜单中显示）
 *  "4" = 按钮权限
 */
function transformMenuToRoute(menu: IamMenu): RouteRecordStringComponent {
  const route: RouteRecordStringComponent = {
    name: menu.name,
    path: menu.path,
    component: menu.component || 'BasicLayout',
    meta: {
      title: menu.title || menu.name,
      icon: menu.icon,
      order: menu.sort,
      hideInMenu: !menu.show_link,
    },
  };

  if (menu.menu_type === '2' && menu.path) {
    (route.meta as any).iframeSrc = menu.path;
  }

  if (menu.redirect) {
    route.redirect = menu.redirect;
  }

  if (menu.children && menu.children.length > 0) {
    route.children = menu.children.map(transformMenuToRoute);
  }

  if (menu.buttons && menu.buttons.length > 0) {
    const authority = menu.buttons.map((b) => b.name || b.id);
    (route.meta as any).authority = authority;
  }

  return route;
}

/**
 * 获取菜单（路由）列表
 *
 * @param appId 可选的应用过滤；不传则返回当前用户在所有应用下的菜单合集
 *              传入则只返回指定应用的菜单
 * @param reconcile 拉到 menu groups 后回调，调用方可以根据"哪些 app_id 有菜单"
 *                  纠偏 currentAppId，并返回最终用于过滤的 appId
 */
export async function getAllMenusApi(
  appId?: string,
  reconcile?: (idsWithMenus: string[]) => string | undefined,
): Promise<RouteRecordStringComponent[]> {
  // 仅请求菜单接口，避免拉整个 PermissionBundle
  const raw = await getUserMenusApi(appId);
  const menuGroups: IamAppMenuGroup[] = (raw as unknown as IamAppMenuGroup[]) ?? [];

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
    if (effectiveAppId && group.app_id !== effectiveAppId) continue;
    if (group.menus) {
      allMenus.push(...group.menus);
    }
  }

  return allMenus.map(transformMenuToRoute);
}
