import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:send', order: 7, title: '任务派发' },
    name: 'Dispatch',
    path: '/dispatch',
    redirect: '/dispatch/orders',
    children: [
      {
        name: 'DispatchBoard',
        path: 'board',
        component: () => import('#/views/dispatch/board/index.vue'),
        meta: {
          icon: 'lucide:kanban',
          title: '派发工作台',
          apis: ['GET /dispatch/orders'],
        },
      },
      {
        name: 'DispatchOrders',
        path: 'orders',
        component: () => import('#/views/dispatch/orders/index.vue'),
        meta: {
          icon: 'lucide:clipboard-list',
          title: '派发单列表',
          perms: [
            { action: 'create', label: '创建派发单' },
            { action: 'assign', label: '指派' },
            { action: 'cancel', label: '取消' },
          ],
          apis: ['GET /dispatch/orders'],
          apisByAction: {
            create: ['POST /dispatch/orders'],
            assign: ['POST /dispatch/orders/:id/assign'],
            cancel: ['POST /dispatch/orders/:id/cancel'],
          },
        },
      },
      {
        name: 'DispatchOrderDetail',
        path: 'orders/:id',
        component: () => import('#/views/dispatch/orders/detail.vue'),
        meta: {
          hideInMenu: true,
          title: '派发单详情',
          activePath: '/dispatch/orders',
          apis: [
            'GET /dispatch/orders/:id',
            'GET /dispatch/orders/:id/oplogs',
          ],
        },
      },
      {
        name: 'DispatchContacts',
        path: 'contacts',
        component: () => import('#/views/dispatch/contacts/index.vue'),
        meta: {
          icon: 'lucide:contact',
          title: '外部人员',
          perms: [
            { action: 'create', label: '新增联系人' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
          apis: ['GET /dispatch/contacts'],
          apisByAction: {
            create: ['POST /dispatch/contacts'],
            update: ['PUT /dispatch/contacts/:id'],
            delete: ['DELETE /dispatch/contacts/:id'],
          },
        },
      },
    ],
  },
];

export default routes;
