import type { RouteRecordRaw } from 'vue-router';

/** 报告中心已取消，保留旧链接重定向 */
const routes: RouteRecordRaw[] = [
  { path: '/dashboard/report', redirect: '/scan/report' },
  { path: '/reports', redirect: '/scan/report' },
  { path: '/reports/scan', redirect: '/scan/report' },
  { path: '/reports/monitor', redirect: '/monitor/report' },
  { path: '/reports/incident', redirect: '/incident/analytics' },
];

export default routes;
