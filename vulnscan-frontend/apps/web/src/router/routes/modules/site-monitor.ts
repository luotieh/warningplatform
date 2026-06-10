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
        meta: {
          title: '监测中心',
          icon: 'ri:dashboard-line',
          order: 1,
          perms: [{ action: 'view', label: '查看' }],
          apis: [
            'GET /sitemonitor/dashboard/stats',
            'GET /sitemonitor/execution-stats',
            'GET /sitemonitor/targets',
            'GET /sitemonitor/executions',
          ],
          apisByAction: {
            view: ['GET /sitemonitor/dashboard/stats'],
          },
        },
      },
      {
        name: 'MonitorTargets',
        path: 'targets',
        component: () => import('#/views/site-monitor/targets/index.vue'),
        meta: {
          title: '监测任务',
          icon: 'ri:task-line',
          order: 2,
          perms: [
            { action: 'create', label: '新建目标' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
            { action: 'run', label: '手动执行' },
            { action: 'import', label: '批量导入' },
          ],
          apis: [
            'GET /sitemonitor/targets',
            'GET /sitemonitor/path-tasks',
            'GET /sitemonitor/fetch-meta',
          ],
          apisByAction: {
            create: ['POST /sitemonitor/targets', 'POST /sitemonitor/path-tasks'],
            update: ['PUT /sitemonitor/targets/:id', 'PUT /sitemonitor/path-tasks/:id'],
            delete: ['DELETE /sitemonitor/targets/:id', 'DELETE /sitemonitor/path-tasks/:id'],
            run: [
              'POST /sitemonitor/targets/run/:id',
              'POST /sitemonitor/path-tasks/run/:id',
            ],
            import: ['POST /sitemonitor/import'],
          },
        },
      },
      {
        name: 'MonitorIssues',
        path: 'issues',
        component: () => import('#/views/site-monitor/issues/index.vue'),
        meta: {
          title: '问题处置',
          icon: 'ri:alarm-warning-line',
          order: 3,
          perms: [
            { action: 'view', label: '查看' },
            { action: 'dispose', label: '处置' },
            { action: 'export', label: '导出' },
          ],
          apis: [
            'GET /sitemonitor/executions',
            'GET /sitemonitor/executions/:id',
          ],
          apisByAction: {
            view: ['GET /sitemonitor/executions'],
            dispose: [
              'PUT /sitemonitor/executions/:id/disposition',
              'PUT /sitemonitor/executions/batch/disposition',
            ],
            export: ['GET /sitemonitor/executions/export'],
          },
        },
      },
      {
        name: 'MonitorReport',
        path: 'report',
        component: () => import('#/views/site-monitor/report.vue'),
        meta: {
          title: '监测报告',
          icon: 'lucide:file-bar-chart-2',
          order: 4,
          perms: [{ action: 'view', label: '查看' }, { action: 'export', label: '导出' }],
          apis: ['GET /sitemonitor/reports'],
          apisByAction: {
            view: ['GET /sitemonitor/reports'],
            export: ['POST /sitemonitor/reports/generate'],
          },
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
          apis: [
            'GET /sitemonitor/targets/:id',
            'GET /sitemonitor/path-tasks',
            'GET /sitemonitor/path-tasks/:id',
            'GET /sitemonitor/executions',
            'GET /sitemonitor/crawl-jobs/:jobId',
          ],
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
        redirect: '/monitor/issues',
        meta: {
          title: '问题处置',
          activePath: '/monitor/issues',
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
          apis: [
            'GET /sitemonitor/executions/:id',
            'GET /sitemonitor/executions/:id/evidence/:type',
          ],
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
          apis: ['GET /sitemonitor/executions', 'GET /sitemonitor/path-tasks/:id'],
        },
      },
      {
        name: 'MonitorConfig',
        path: 'config',
        component: () => import('#/views/site-monitor/config/index.vue'),
        meta: {
          title: '监测配置',
          icon: 'ri:settings-4-line',
          order: 5,
          perms: [
            { action: 'view', label: '查看' },
            { action: 'update', label: '保存配置' },
          ],
          apis: [
            'GET /sitemonitor/word-libraries',
            'GET /sitemonitor/file-libraries',
            'GET /sitemonitor/default-configs',
            'GET /sitemonitor/rule-data',
            'GET /sitemonitor/alert-config',
            'GET /sitemonitor/agents',
          ],
          apisByAction: {
            view: ['GET /sitemonitor/default-configs', 'GET /sitemonitor/rule-data'],
            update: [
              'PUT /sitemonitor/default-configs/:dimension',
              'PUT /sitemonitor/alert-config',
              'PUT /sitemonitor/rule-data/:moduleKey',
            ],
          },
        },
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
