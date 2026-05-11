import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:mail-warning', order: 5, title: '通报处置' },
    name: 'Circular',
    path: '/circular',
    redirect: '/circular/input',
    children: [
      {
        name: 'CircularInput',
        path: 'input',
        component: () => import('#/views/circular/input/list.vue'),
        meta: {
          icon: 'lucide:file-input',
          title: '通报录入',
          perms: [
            { action: 'create', label: '新建通报' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
            { action: 'import', label: '导入' },
            { action: 'export', label: '导出' },
            { action: 'submit', label: '提交核验' },
          ],
        },
      },
      {
        name: 'CircularInputAdd',
        path: 'input/add',
        component: () => import('#/views/circular/input/add.vue'),
        meta: {
          hideInMenu: true,
          title: '新建通报',
          activePath: '/circular/input',
        },
      },
      {
        name: 'CircularInputDetail',
        path: 'input/:id',
        component: () => import('#/views/circular/input/detail.vue'),
        meta: {
          hideInMenu: true,
          title: '通报详情',
          activePath: '/circular/input',
        },
      },
      {
        name: 'CircularVerify',
        path: 'verify',
        component: () => import('#/views/circular/verify/list.vue'),
        meta: {
          icon: 'lucide:check-circle',
          title: '通报核验',
          perms: [
            { action: 'verify', label: '核验' },
          ],
        },
      },
      {
        name: 'CircularDistribute',
        path: 'distribute',
        component: () => import('#/views/circular/distribute/list.vue'),
        meta: {
          icon: 'lucide:send',
          title: '通报派发',
          perms: [
            { action: 'distribute', label: '派发' },
          ],
        },
      },
      {
        name: 'CircularDisposal',
        path: 'disposal',
        component: () => import('#/views/circular/disposal/list.vue'),
        meta: {
          icon: 'lucide:wrench',
          title: '通报处置',
          perms: [
            { action: 'dispose', label: '处置' },
            { action: 'redistribute', label: '转派' },
          ],
        },
      },
      {
        name: 'CircularDisposalHandle',
        path: 'disposal/:id',
        component: () => import('#/views/circular/disposal/handle.vue'),
        meta: {
          hideInMenu: true,
          title: '处置通报',
          activePath: '/circular/disposal',
        },
      },
      {
        name: 'CircularReview',
        path: 'review',
        component: () => import('#/views/circular/review/list.vue'),
        meta: {
          icon: 'lucide:clipboard-check',
          title: '通报审核',
          perms: [
            { action: 'review', label: '审核' },
          ],
        },
      },
      {
        name: 'CircularLedger',
        path: 'ledger',
        component: () => import('#/views/circular/ledger/list.vue'),
        meta: {
          icon: 'lucide:book-open',
          title: '通报台账',
        },
      },
      {
        name: 'CircularLedgerDetail',
        path: 'ledger/:id',
        component: () => import('#/views/circular/ledger/detail.vue'),
        meta: {
          hideInMenu: true,
          title: '台账详情',
          activePath: '/circular/ledger',
        },
      },
      {
        name: 'CircularTemplate',
        path: 'template',
        component: () => import('#/views/circular/template/list.vue'),
        meta: {
          icon: 'lucide:file-text',
          title: '模板管理',
          perms: [
            { action: 'create', label: '新建模板' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
        },
      },
      {
        name: 'CircularTemplateAdd',
        path: 'template/add',
        component: () => import('#/views/circular/template/add.vue'),
        meta: {
          hideInMenu: true,
          title: '新建模板',
          activePath: '/circular/template',
        },
      },
    ],
  },
];

export default routes;
