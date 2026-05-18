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
        meta: { icon: 'lucide:gauge', title: '总览' },
      },
      {
        name: 'DashboardReportCompat',
        path: 'report',
        redirect: '/reports/scan',
        meta: { hideInMenu: true, title: '报告中心' },
      },
      {
        name: 'DashboardCompareCompat',
        path: 'compare',
        redirect: '/scan/compare',
        meta: { hideInMenu: true, title: '任务对比' },
      },
    ],
  },
];

export default routes;
