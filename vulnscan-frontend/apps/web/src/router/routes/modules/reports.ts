import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:file-bar-chart-2', order: 6, title: '报告中心' },
    name: 'Reports',
    path: '/reports',
    redirect: '/reports/scan',
    children: [
      {
        name: 'ReportsScan',
        path: 'scan',
        component: () => import('#/views/dashboard/report.vue'),
        meta: {
          icon: 'lucide:bug',
          title: '漏洞扫描报告',
        },
      },
      {
        name: 'ReportsMonitor',
        path: 'monitor',
        component: () => import('#/views/site-monitor/report.vue'),
        meta: {
          icon: 'ri:radar-line',
          title: '风险监测报告',
        },
      },
      {
        name: 'ReportsIncident',
        path: 'incident',
        component: () => import('#/views/incident/reports/index.vue'),
        meta: {
          icon: 'lucide:shield-alert',
          title: '安全事件报告',
        },
      },
    ],
  },
];

export default routes;
