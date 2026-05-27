import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:server', order: 2, title: '资产管理' },
    name: 'Asset',
    path: '/asset',
    redirect: '/asset/ledger',
    children: [
      {
        name: 'AssetDiscovery',
        path: 'discovery',
        component: () => import('#/views/asset/discovery/index.vue'),
        meta: {
          icon: 'lucide:radar',
          title: '资产探测',
          keepAlive: true,
          perms: [
            { action: 'create', label: '新建探测' },
            { action: 'verify', label: '下发核验' },
            { action: 'import', label: '候选入库' },
          ],
          apis: [
            'GET /asset/discovery/probes',
          ],
          apisByAction: {
            create: ['POST /asset/discovery/probes'],
            verify: ['POST /asset/discovery/probes/:id/sync'],
            import: ['POST /asset/discovery/probes/:id/candidates/import'],
          },
        },
      },
      {
        name: 'AssetLedger',
        path: 'ledger',
        component: () => import('#/views/asset/ledger/index.vue'),
        meta: {
          icon: 'lucide:book-open',
          title: '资产台账',
          /** 应用内多标签切换时保留列表状态，避免每次切回都重新 init / 打接口 */
          keepAlive: true,
          perms: [
            { action: 'create', label: '新建资产' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
            { action: 'import', label: '导入' },
          ],
          apis: [
            'GET /asset/list',
            'GET /asset/stats',
            'GET /asset/group/list',
            'GET /organize/tree',
            'GET /tagging/tags/list',
          ],
          apisByAction: {
            create: ['POST /asset', 'POST /asset/group'],
            update: ['PUT /asset/:id', 'PUT /asset/group/:id'],
            delete: ['DELETE /asset/:id', 'DELETE /asset/group/:id'],
            import: ['POST /asset/import'],
          },
        },
      },
      {
        name: 'AssetDetail',
        path: 'detail/:id',
        component: () => import('#/views/asset/detail.vue'),
        meta: {
          hideInMenu: true,
          icon: 'lucide:file-search',
          title: '资产详情',
          apis: [
            'GET /asset/:id',
            'GET /asset/:id/enrich',
            'GET /tagging/asset-tags/:asset_id',
          ],
        },
      },
      {
        name: 'AssetGroup',
        path: 'group',
        component: () => import('#/views/asset/group.vue'),
        meta: {
          hideInMenu: true,
          icon: 'lucide:folder',
          title: '资产分组',
          perms: [
            { action: 'create', label: '新建分组' },
            { action: 'delete', label: '删除' },
          ],
          apis: ['GET /asset/group/list'],
          apisByAction: {
            create: ['POST /asset/group'],
            delete: ['DELETE /asset/group/:id'],
          },
        },
      },
      {
        name: 'AssetOrgTag',
        path: 'org-tag',
        component: () => import('#/views/asset/org-tag.vue'),
        meta: {
          icon: 'lucide:building-2',
          title: '单位标签',
          perms: [{ action: 'view', label: '查看' }, { action: 'update', label: '维护' }],
          apis: [
            'GET /organize/tree',
            'GET /organize/list',
            'GET /tagging/tags/list',
          ],
          apisByAction: {
            view: ['GET /organize/tree', 'GET /organize/list', 'GET /tagging/tags/list'],
            update: ['POST /tagging/tags', 'POST /tagging/asset-tags'],
          },
        },
      },
      {
        name: 'AssetVerifyTasks',
        path: 'verify-tasks',
        component: () => import('#/views/asset/verify-tasks.vue'),
        meta: {
          icon: 'lucide:clipboard-check',
          title: '核验任务',
          perms: [{ action: 'view', label: '查看' }, { action: 'verify', label: '核验' }],
          apis: ['GET /assetmgr/verify/tasks/list'],
          apisByAction: {
            view: ['GET /assetmgr/verify/tasks/list'],
            verify: ['PUT /assetmgr/verify/tasks/:id/confirm'],
          },
        },
      },
      {
        name: 'AssetArchive',
        path: 'archive',
        component: () => import('#/views/asset/archive.vue'),
        meta: {
          icon: 'lucide:archive',
          title: '资产归档',
          perms: [{ action: 'view', label: '查看' }],
          apis: ['GET /asset/list'],
          apisByAction: {
            view: ['GET /asset/list'],
          },
        },
      },
    ],
  },
];

export default routes;
