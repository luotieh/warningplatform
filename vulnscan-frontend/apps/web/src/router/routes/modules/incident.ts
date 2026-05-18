import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:shield-alert', order: 5, title: '安全事件' },
    name: 'Incident',
    path: '/incident',
    redirect: '/incident/dashboard',
    children: [
      {
        name: 'IncidentDashboard',
        path: 'dashboard',
        component: () => import('#/views/incident/dashboard/index.vue'),
        meta: {
          icon: 'lucide:bar-chart-3',
          title: '统计概览',
        },
      },
      {
        name: 'IncidentList',
        path: 'list',
        component: () => import('#/views/incident/list/index.vue'),
        meta: {
          icon: 'lucide:list',
          title: '事件列表',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
            { action: 'ai-audit', label: 'AI预审' },
            { action: 'manual-audit', label: '人工审核' },
            { action: 'import', label: '导入' },
            { action: 'export', label: '导出' },
          ],
        },
      },
      {
        name: 'IncidentDetail',
        path: 'list/:id',
        component: () => import('#/views/incident/list/detail.vue'),
        meta: { hideInMenu: true, title: '事件详情' },
      },
      {
        name: 'IncidentReports',
        path: 'reports',
        redirect: '/reports/incident',
        meta: { hideInMenu: true, title: '报告中心' },
      },
    ],
  },
];

export default routes;
