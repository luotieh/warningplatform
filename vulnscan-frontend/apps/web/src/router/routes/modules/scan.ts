import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:radar', order: 4, title: '漏洞扫描' },
    name: 'Scan',
    path: '/scan',
    redirect: '/scan/task',
    children: [
      {
        name: 'ScanTask',
        path: 'task',
        component: () => import('#/views/scan/task/list.vue'),
        meta: {
          icon: 'lucide:play',
          title: '扫描任务',
          perms: [
            { action: 'create', label: '创建任务' },
            { action: 'cancel', label: '取消任务' },
            { action: 'delete', label: '删除任务' },
          ],
          apis: [
            'GET /task/list',
            'GET /task/:id',
            'GET /organize/tree',
            'GET /scan/templates',
            'GET /scan/status',
            'GET /scan/engine-presets',
            'GET /scan/engine-rules',
            'GET /scan/task-parameter-schema',
            'GET /report/task/:task_id',
            'GET /notify/unread-count',
            'GET /pipeline/modules',
            'GET /pipeline/modules/config',
            'GET /pipeline/templates',
          ],
          apisByAction: {
            create: ['POST /scan/launch', 'POST /scan/suggest-parameters'],
            cancel: ['POST /scan/cancel/:id'],
            delete: ['DELETE /task/:id'],
          },
        },
      },
      {
        name: 'ScanTaskDetail',
        path: 'task/:id',
        component: () => import('#/views/scan/task/detail.vue'),
        meta: {
          hideInMenu: true,
          title: '任务详情',
          apis: [
            'GET /task/:id',
            'GET /task/:id/findings',
            'GET /task/:id/findings/summary',
            'GET /task/:id/assets',
            'GET /task/:id/logs',
            'GET /scan/events/:id',
            'GET /scan/progress/:id',
            'GET /report/task/:task_id',
          ],
        },
      },
      {
        name: 'ScanVulnList',
        path: 'vulns',
        component: () => import('#/views/vuln/list.vue'),
        meta: {
          icon: 'lucide:bug',
          title: '漏洞列表',
          perms: [
            { action: 'verify', label: '验证' },
            { action: 'delete', label: '删除' },
          ],
          apis: ['GET /vuln/list', 'GET /vuln/stats'],
          apisByAction: {
            verify: ['POST /vuln/:id/fix'],
            delete: ['DELETE /vuln/:id'],
          },
        },
      },
      {
        name: 'ScanVulnDetail',
        path: 'vulns/:id',
        component: () => import('#/views/vuln/detail.vue'),
        meta: {
          hideInMenu: true,
          title: '漏洞详情',
          activePath: '/scan/vulns',
          apis: [
            'GET /vuln/:id',
            'GET /vuln/:id/history',
          ],
          apisByAction: {
            verify: ['POST /vuln/:id/fix', 'POST /vuln/:id/ignore', 'POST /vuln/:id/retest'],
            delete: ['DELETE /vuln/:id'],
          },
        },
      },
      {
        name: 'ScanReport',
        path: 'report',
        component: () => import('#/views/dashboard/report.vue'),
        meta: {
          icon: 'lucide:file-bar-chart-2',
          title: '扫描报告',
          perms: [{ action: 'view', label: '查看' }, { action: 'export', label: '导出' }],
          apis: ['GET /report/tasks'],
          apisByAction: {
            view: ['GET /report/tasks', 'POST /report/preview'],
            export: ['GET /report/task/:task_id'],
          },
        },
      },
      {
        name: 'ScanExclusions',
        path: 'exclusions',
        component: () => import('#/views/scan/exclusions/list.vue'),
        meta: {
          icon: 'lucide:shield-off',
          title: '目标排除',
          perms: [
            { action: 'create', label: '创建规则' },
            { action: 'update', label: '编辑规则' },
            { action: 'delete', label: '删除规则' },
          ],
          apis: ['GET /scan-exclusions'],
          apisByAction: {
            create: ['POST /scan-exclusions'],
            update: ['PUT /scan-exclusions/:id'],
            delete: ['DELETE /scan-exclusions/:id'],
          },
        },
      },
      {
        name: 'ScanFPRules',
        path: 'fp-rules',
        component: () => import('#/views/scan/fp-rules/list.vue'),
        meta: {
          icon: 'lucide:shield-check',
          title: '误报管理',
          perms: [
            { action: 'create', label: '创建规则' },
            { action: 'update', label: '编辑规则' },
            { action: 'delete', label: '删除规则' },
          ],
          apis: ['GET /fp-rules'],
          apisByAction: {
            create: ['POST /fp-rules'],
            update: ['PUT /fp-rules/:id'],
            delete: ['DELETE /fp-rules/:id'],
          },
        },
      },
      {
        name: 'ScanTemplate',
        path: 'template',
        component: () => import('#/views/scan/template/list.vue'),
        meta: {
          icon: 'lucide:file-code',
          title: '扫描模板',
          perms: [
            { action: 'create', label: '创建模板' },
            { action: 'delete', label: '删除模板' },
          ],
          apis: ['GET /template/list', 'GET /template/builtins', 'GET /pipeline/modules'],
          apisByAction: {
            create: ['POST /template'],
            delete: ['DELETE /template/:id'],
          },
        },
      },
      {
        name: 'ScanSchedule',
        path: 'schedule',
        component: () => import('#/views/scan/schedule/list.vue'),
        meta: {
          icon: 'lucide:clock',
          title: '定时调度',
          perms: [
            { action: 'create', label: '创建调度' },
            { action: 'delete', label: '删除调度' },
            { action: 'toggle', label: '启停调度' },
          ],
          apis: ['GET /schedule/list'],
          apisByAction: {
            create: ['POST /schedule'],
            delete: ['DELETE /schedule/:id'],
            toggle: ['POST /schedule/:id/toggle'],
          },
        },
      },
    ],
  },
];

export default routes;
