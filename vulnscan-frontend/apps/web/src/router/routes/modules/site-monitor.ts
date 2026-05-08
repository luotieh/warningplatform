import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'ri:radar-line', order: 3, title: '站点监控' },
    name: 'SiteMonitor',
    path: '/monitor',
    redirect: '/monitor/dashboard',
    children: [
      {
        name: 'MonitorDashboard',
        path: 'dashboard',
        component: () =>
          import('#/views/site-monitor/dashboard/analysis.vue'),
        meta: { title: '数据分析', icon: 'ri:dashboard-line' },
      },
      {
        name: 'MonitorLedger',
        path: 'ledger',
        component: () => import('#/views/site-monitor/ledger/index.vue'),
        meta: { title: '监测台账', icon: 'ri:file-list-line' },
      },
      {
        name: 'MonitorTasks',
        path: 'tasks',
        component: () => import('#/views/site-monitor/tasks/index.vue'),
        meta: {
          title: '监测任务',
          icon: 'ri:task-line',
          perms: [
            { action: 'create', label: '新建任务' },
            { action: 'update', label: '编辑任务' },
            { action: 'delete', label: '删除任务' },
            { action: 'run', label: '手动执行' },
            { action: 'import', label: '批量导入' },
          ],
        },
      },
      {
        name: 'MonitorExecutions',
        path: 'tasks/executions',
        component: () =>
          import('#/views/site-monitor/executions/index.vue'),
        meta: {
          title: '执行结果',
          activePath: '/monitor/tasks',
          hideInMenu: true,
        },
      },
      {
        name: 'ExecutionDetail',
        path: 'tasks/executions/detail/:id',
        component: () =>
          import('#/views/site-monitor/executions/detail.vue'),
        meta: {
          title: '结果详情',
          activePath: '/monitor/tasks',
          hideInMenu: true,
        },
      },
      {
        name: 'MonitorConfig',
        path: 'config',
        component: () => import('#/views/site-monitor/config/index.vue'),
        meta: { title: '监测配置', icon: 'ri:settings-4-line' },
      },
    ],
  },
];

export default routes;
