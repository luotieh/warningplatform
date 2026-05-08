import type {
  ComponentRecordType,
  GenerateMenuAndRoutesOptions,
} from '@vben/types';

import { generateAccessible } from '@vben/access';
import { preferences } from '@vben/preferences';

import { message } from '#/adapter/naive';
import { getAllMenusApi } from '#/api';
import { BasicLayout, IFrameView } from '#/layouts';
import { $t } from '#/locales';

const forbiddenComponent = () => import('#/views/_core/fallback/forbidden.vue');

async function generateAccess(options: GenerateMenuAndRoutesOptions) {
  const pageMap: ComponentRecordType = import.meta.glob('../views/**/*.vue');

  const layoutMap: ComponentRecordType = {
    BasicLayout,
    IFrameView,
  };

  let accessMode = preferences.app.accessMode;

  return await generateAccessible(accessMode, {
    ...options,
    fetchMenuListAsync: async () => {
      message.loading(`${$t('common.loadingMenu')}...`, {
        duration: 1.5,
      });
      try {
        const menus = await getAllMenusApi();
        if (accessMode === 'backend' && (!menus || menus.length === 0)) {
          message.warning(
            '后端未返回菜单，请先在「系统管理 → 系统初始化」中同步菜单到 IAM，并在 IAM 后台为角色分配菜单权限。当前回退为前端路由模式。',
            { duration: 6 },
          );
          accessMode = 'frontend';
        }
        return menus;
      } catch {
        if (accessMode === 'backend') {
          message.warning('菜单接口不可用，回退为前端路由模式', {
            duration: 4,
          });
          accessMode = 'frontend';
        }
        return [];
      }
    },
    forbiddenComponent,
    layoutMap,
    pageMap,
  });
}

export { generateAccess };
