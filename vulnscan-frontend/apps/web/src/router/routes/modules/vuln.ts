import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { hideInMenu: true, title: '漏洞管理' },
    name: 'VulnCompat',
    path: '/vuln',
    redirect: '/scan/vulns',
    children: [
      {
        name: 'VulnListCompat',
        path: 'list',
        component: () => import('#/views/vuln/list.vue'),
        meta: { hideInMenu: true, title: '漏洞列表', activePath: '/scan/vulns' },
      },
      {
        name: 'VulnDetailCompat',
        path: ':id',
        component: () => import('#/views/vuln/detail.vue'),
        meta: { hideInMenu: true, title: '漏洞详情', activePath: '/scan/vulns' },
      },
    ],
  },
];

export default routes;
