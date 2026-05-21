import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:layout-dashboard', order: 1, title: '仪表盘' },
    name: 'Dashboard',
    path: '/dashboard',
    redirect: '/dashboard/overview',
    children: [
      {
        name: 'DashboardOverview',
        path: 'overview',
        component: () => import('#/views/dashboard/overview.vue'),
        meta: {
          icon: 'lucide:gauge',
          title: '总览',
          perms: [{ action: 'view', label: '查看' }],
        },
      },
    ],
  },
];

export default routes;
