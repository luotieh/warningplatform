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
        name: 'AssetLedger',
        path: 'ledger',
        component: () => import('#/views/asset/ledger.vue'),
        meta: {
          icon: 'lucide:book-open',
          title: '资产台账',
          perms: [
            { action: 'create', label: '新建资产' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
            { action: 'import', label: '导入' },
          ],
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
        },
      },
      {
        name: 'AssetOrgTag',
        path: 'org-tag',
        component: () => import('#/views/asset/org-tag.vue'),
        meta: { icon: 'lucide:building-2', title: '单位标签' },
      },
      {
        name: 'AssetVerifyTasks',
        path: 'verify-tasks',
        component: () => import('#/views/asset/verify-tasks.vue'),
        meta: { icon: 'lucide:clipboard-check', title: '核验任务' },
      },
      {
        name: 'AssetArchive',
        path: 'archive',
        component: () => import('#/views/asset/archive.vue'),
        meta: { icon: 'lucide:archive', title: '资产归档' },
      },
    ],
  },
];

export default routes;
