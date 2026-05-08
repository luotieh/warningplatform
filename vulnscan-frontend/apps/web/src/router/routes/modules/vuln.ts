import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:shield-alert', order: 5, title: '漏洞管理' },
    name: 'Vuln',
    path: '/vuln',
    redirect: '/vuln/list',
    children: [
      {
        name: 'VulnList',
        path: 'list',
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
        name: 'VulnDetail',
        path: ':id',
        component: () => import('#/views/vuln/detail.vue'),
        meta: { hideInMenu: true, title: '漏洞详情' },
      },
    ],
  },
];

export default routes;
