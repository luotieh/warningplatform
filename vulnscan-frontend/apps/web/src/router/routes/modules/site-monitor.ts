import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'ri:radar-line', order: 3, title: '风险监测' },
    name: 'SiteMonitor',
    path: '/monitor',
    redirect: '/monitor/center',
    children: [
      {
        name: 'MonitorCenter',
        path: 'center',
        component: () => import('#/views/site-monitor/monitor-center.vue'),
        meta: { title: '监测中心', icon: 'ri:dashboard-line' },
      },
      {
        name: 'MonitorTargets',
        path: 'targets',
        component: () => import('#/views/site-monitor/targets/index.vue'),
        meta: {
          title: '网站监测',
          icon: 'ri:task-line',
          perms: [
            { action: 'create', label: '新建目标' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
            { action: 'run', label: '手动执行' },
            { action: 'import', label: '批量导入' },
          ],
        },
      },
      {
        name: 'MonitorTargetDetail',
        path: 'targets/:id',
        component: () => import('#/views/site-monitor/targets/detail.vue'),
        meta: {
          title: '目标详情',
          hideInMenu: true,
          activePath: '/monitor/targets',
        },
      },
      {
        name: 'MonitorTasks',
        path: 'tasks',
        redirect: '/monitor/targets',
        meta: { hideInMenu: true },
      },
      {
        name: 'MonitorLedger',
        path: 'ledger',
        redirect: '/monitor/targets',
        meta: {
          title: '监测台账',
          hideInMenu: true,
        },
      },
      {
        name: 'MonitorExecutions',
        path: 'tasks/executions',
        component: () => import('#/views/site-monitor/executions/index.vue'),
        meta: {
          title: '执行结果',
          activePath: '/monitor/targets',
          hideInMenu: true,
        },
      },
      {
        name: 'MonitorRecordDetail',
        path: 'records/detail/:id',
        component: () => import('#/views/site-monitor/records/detail.vue'),
        meta: {
          title: '监测记录详情',
          activePath: '/monitor/targets',
          hideInMenu: true,
        },
      },
      {
        name: 'ExecutionDetail',
        path: 'tasks/executions/detail/:id',
        redirect: (to) => ({
          path: `/monitor/records/detail/${to.params.id as string}`,
          query: to.query,
        }),
        meta: { hideInMenu: true },
      },
      {
        name: 'MonitorRecords',
        path: 'records/:pathTaskId',
        component: () => import('#/views/site-monitor/records/index.vue'),
        meta: {
          title: '监测记录',
          icon: 'ri:file-list-line',
          hideInMenu: true,
          activePath: '/monitor/targets',
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

/** 兼容旧链接：/site-monitor/executions/:id → 监测记录详情 */
const legacyRoutes: RouteRecordRaw[] = [
  {
    path: '/site-monitor/executions/:id',
    redirect: (to) => ({
      path: `/monitor/records/detail/${to.params.id as string}`,
      query: to.query,
    }),
    meta: { hideInMenu: true, title: '监测记录详情' },
  },
];

export default [...routes, ...legacyRoutes];
