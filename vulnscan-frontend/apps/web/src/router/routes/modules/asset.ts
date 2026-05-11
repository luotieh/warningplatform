import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:server', order: 2, title: '资产中心' },
    name: 'Asset',
    path: '/asset',
    redirect: '/asset/overview',
    children: [
      {
        name: 'AssetOverview',
        path: 'overview',
        component: () => import('#/views/asset/overview.vue'),
        meta: { icon: 'lucide:layout-dashboard', title: '资产总览' },
      },
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
        name: 'AssetGroup',
        path: 'group',
        component: () => import('#/views/asset/group.vue'),
        meta: {
          icon: 'lucide:folder',
          title: '资产分组',
          perms: [
            { action: 'create', label: '新建分组' },
            { action: 'delete', label: '删除' },
          ],
        },
      },
      {
        name: 'CyberspaceSearch',
        path: 'cyberspace',
        component: () => import('#/views/asset/cyberspace.vue'),
        meta: { icon: 'lucide:globe', title: '网络空间搜索' },
      },
      {
        name: 'AssetSecurity',
        path: 'security',
        component: () => import('#/views/asset/security.vue'),
        meta: { icon: 'lucide:activity', title: '安全态势' },
      },
      {
        name: 'AssetOrgTag',
        path: 'org-tag',
        component: () => import('#/views/asset/org-tag.vue'),
        meta: { icon: 'lucide:building-2', title: '组织与标签' },
      },
      {
        name: 'AssetLifecycle',
        path: 'lifecycle',
        component: () => import('#/views/asset/lifecycle.vue'),
        meta: { icon: 'lucide:refresh-cw', title: '生命周期' },
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
      {
        name: 'AssetChangeLog',
        path: 'changelog',
        component: () => import('#/views/asset/changelog.vue'),
        meta: { icon: 'lucide:file-clock', title: '变更日志' },
      },
    ],
  },
];

export default routes;
