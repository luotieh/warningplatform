import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:settings', order: 99, title: '系统管理' },
    name: 'System',
    path: '/system',
    redirect: '/system/settings',
    children: [
      {
        name: 'SystemSettings',
        path: 'settings',
        component: () => import('#/views/system/settings.vue'),
        meta: {
          title: '系统设置',
          icon: 'lucide:sliders-horizontal',
        },
      },
      {
        name: 'SystemDict',
        path: 'dict',
        component: () => import('#/views/system/dict.vue'),
        meta: {
          title: '数据字典',
          icon: 'lucide:list-tree',
        },
      },
      {
        name: 'SystemInit',
        path: 'init',
        component: () => import('#/views/system/init.vue'),
        meta: {
          title: '系统初始化',
          icon: 'lucide:database',
        },
      },
    ],
  },
];

export default routes;
