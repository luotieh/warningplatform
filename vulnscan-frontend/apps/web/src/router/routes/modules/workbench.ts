import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: {
      hideChildrenInMenu: true,
      icon: 'lucide:briefcase',
      order: 0,
      title: '工作台',
    },
    name: 'Workbench',
    path: '/workbench',
    redirect: '/workbench/overview',
    children: [
      {
        name: 'WorkbenchOverview',
        path: 'overview',
        component: () => import('#/views/workbench/index.vue'),
        meta: {
          icon: 'lucide:gauge',
          title: '工作台',
          perms: [{ action: 'view', label: '查看' }],
          apis: [
            'GET /dashboard/overview',
            'GET /dashboard/recent-activity',
            'GET /incident/dashboard/stats',
            'GET /incident/incidents',
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
