import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:network', order: 13, title: '集群管理' },
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
            { action: 'remove', label: '注销节点' },
            { action: 'stop', label: '停止节点' },
          ],
          apis: [
            'GET /cluster/workers',
            'GET /nodes',
            'GET /scan/status',
            'GET /cluster/connectivity-modes',
          ],
          apisByAction: {
            remove: ['POST /cluster/workers/:id/unregister'],
            stop: ['DELETE /cluster/scan-nodes/:uuid'],
          },
        },
      },
      {
        name: 'FederationManage',
        path: 'federation',
        component: () => import('#/views/cluster/federation.vue'),
        meta: {
          icon: 'lucide:globe',
          title: '联邦管理',
          perms: [{ action: 'enroll', label: '注册节点' }],
          apis: ['GET /nodes', 'GET /federation/sub-masters'],
          apisByAction: {
            enroll: ['POST /cluster/scan-nodes/enroll'],
          },
        },
      },
    ],
  },
];

export default routes;
