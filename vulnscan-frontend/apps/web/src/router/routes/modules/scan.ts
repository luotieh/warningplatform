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
      {
        name: 'ScanPipeline',
        path: 'pipeline',
        component: () => import('#/views/scan/pipeline/editor.vue'),
        meta: {
          icon: 'lucide:workflow',
          title: '流程编排',
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
        },
      },
      {
        name: 'ScanVulnDetail',
        path: 'vulns/:id',
        component: () => import('#/views/vuln/detail.vue'),
        meta: { hideInMenu: true, title: '漏洞详情', activePath: '/scan/vulns' },
      },
    ],
  },
];

export default routes;
