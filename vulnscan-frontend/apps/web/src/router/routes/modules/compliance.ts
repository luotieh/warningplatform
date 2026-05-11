import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { hideInMenu: true, title: '合规检查' },
    name: 'ComplianceCompat',
    path: '/compliance',
    redirect: '/monitor/baselines',
    children: [
      {
        name: 'ComplianceBaselinesCompat',
        path: 'baselines',
        component: () => import('#/views/compliance/index.vue'),
        meta: { hideInMenu: true, title: '基线检查', activePath: '/monitor/baselines' },
      },
    ],
  },
];

export default routes;
