import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:network', order: 7, title: '集群管理' },
    name: 'Cluster',
    path: '/cluster',
    redirect: '/cluster/nodes',
    children: [
      {
        name: 'ClusterNodes',
        path: 'nodes',
        component: () => import('#/views/cluster/nodes.vue'),
        meta: {
          icon: 'lucide:cpu',
          title: '节点管理',
          perms: [
            { action: 'drain', label: '排干' },
            { action: 'resume', label: '恢复' },
            { action: 'remove', label: '注销节点' },
            { action: 'stop', label: '停止节点' },
          ],
        },
      },
      {
        name: 'FederationManage',
        path: 'federation',
        component: () => import('#/views/cluster/federation.vue'),
        meta: {
          icon: 'lucide:globe',
          title: '联邦管理',
        },
      },
    ],
  },
];

export default routes;
