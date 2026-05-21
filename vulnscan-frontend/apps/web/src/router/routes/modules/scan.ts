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
        },
      },
      {
        name: 'ScanTaskDetail',
        path: 'task/:id',
        component: () => import('#/views/scan/task/detail.vue'),
        meta: { hideInMenu: true, title: '任务详情' },
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
        },
      },
      {
        name: 'ScanVulnDetail',
        path: 'vulns/:id',
        component: () => import('#/views/vuln/detail.vue'),
        meta: { hideInMenu: true, title: '漏洞详情', activePath: '/scan/vulns' },
      },
      {
        name: 'ScanReport',
        path: 'report',
        component: () => import('#/views/dashboard/report.vue'),
        meta: {
          icon: 'lucide:file-bar-chart-2',
          title: '扫描报告',
          perms: [{ action: 'view', label: '查看' }, { action: 'export', label: '导出' }],
        },
      },
      {
        name: 'ScanExclusions',
        path: 'exclusions',
        component: () => import('#/views/scan/exclusions/list.vue'),
        meta: {
          icon: 'lucide:shield-off',
          title: '例外/排除项',
          perms: [
            { action: 'create', label: '创建规则' },
            { action: 'update', label: '编辑规则' },
            { action: 'delete', label: '删除规则' },
          ],
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
        },
      },
    ],
  },
];

export default routes;
