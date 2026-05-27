import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:layout-dashboard', order: 1, title: '安全看板' },
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
          apis: [
            'GET /dashboard/overview',
            'GET /dashboard/vuln-trend',
            'GET /dashboard/task-trend',
            'GET /dashboard/top-vuln-assets',
            'GET /dashboard/task-status',
            'GET /dashboard/recent-activity',
            'GET /task/list',
          ],
          apisByAction: {
            view: ['GET /dashboard/overview'],
          },
        },
      },
    ],
  },
];

export default routes;
