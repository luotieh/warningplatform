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
        name: 'DashboardReport',
        path: 'report',
        component: () => import('#/views/dashboard/report.vue'),
        meta: { icon: 'lucide:file-bar-chart', title: '报告中心' },
      },
      {
        name: 'DashboardCompare',
        path: 'compare',
        component: () => import('#/views/dashboard/compare.vue'),
        meta: { icon: 'lucide:git-compare', title: '扫描对比' },
      },
    ],
  },
];

export default routes;
