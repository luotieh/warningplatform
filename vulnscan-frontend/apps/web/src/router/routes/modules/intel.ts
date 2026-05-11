import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { hideInMenu: true, title: '威胁情报' },
    name: 'IntelCompat',
    path: '/intel',
    redirect: '/knowledge/intel',
    children: [
      {
        name: 'IntelCVECompat',
        path: 'cve',
        component: () => import('#/views/intel/index.vue'),
        meta: { hideInMenu: true, title: '情报库', activePath: '/knowledge/intel' },
      },
    ],
  },
];

export default routes;
