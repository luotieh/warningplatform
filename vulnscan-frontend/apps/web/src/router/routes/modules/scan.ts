import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:radar', order: 4, title: '扫描中心' },
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
    ],
  },
];

export default routes;
