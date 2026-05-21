import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:bell', order: 14, title: '通知中心' },
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
        },
      },
    ],
  },
];

export default routes;
