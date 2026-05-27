import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:bell', order: 14, title: '消息中心' },
    name: 'Notify',
    path: '/notify',
    redirect: '/notify/list',
    children: [
      {
        name: 'NotifyList',
        path: 'list',
        component: () => import('#/views/notify/index.vue'),
        meta: {
          icon: 'lucide:inbox',
          title: '通知列表',
          perms: [{ action: 'view', label: '查看' }, { action: 'read', label: '标记已读' }],
          apis: ['GET /notify/list', 'GET /notify/unread-count'],
          apisByAction: {
            view: ['GET /notify/list', 'GET /notify/unread-count'],
            read: ['POST /notify/:id/read', 'POST /notify/read-all'],
          },
        },
      },
      {
        name: 'TodoList',
        path: 'todo',
        component: () => import('#/views/todo/index.vue'),
        meta: {
          icon: 'lucide:check-square',
          title: '待办事项',
          perms: [
            { action: 'create', label: '创建待办' },
            { action: 'manage', label: '管理待办' },
          ],
          apis: ['GET /iam/todos', 'GET /iam/todos/stats'],
          apisByAction: {
            create: ['POST /iam/todos'],
            manage: [
              'PUT /iam/todos/:id',
              'PUT /iam/todos/:id/status',
              'DELETE /iam/todos/:id',
            ],
          },
        },
      },
    ],
  },
];

export default routes;
