import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:mail-warning', order: 6, title: '通报处置' },
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
          title: '通报列表',
          perms: [
            { action: 'create', label: '新建通报' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
            { action: 'import', label: '导入' },
            { action: 'export', label: '导出' },
            { action: 'submit', label: '提交核验' },
          ],
          apis: ['GET /circular/inputs', 'GET /organize/tree'],
          apisByAction: {
            create: ['POST /circular/inputs'],
            update: ['PUT /circular/inputs/:id'],
            delete: ['DELETE /circular/inputs/:id'],
            import: ['POST /circular/inputs/import'],
            export: ['POST /circular/inputs/export'],
            submit: ['POST /circular/inputs/:id/submit'],
          },
        },
      },
      {
        name: 'CircularInputAdd',
        path: 'input/add',
        component: () => import('#/views/circular/input/add.vue'),
        meta: {
          hideInMenu: true,
          hideInTab: true,
          title: '新建通报',
          activePath: '/circular/input',
          apis: ['GET /organize/tree'],
          apisByAction: {
            create: ['POST /circular/inputs'],
          },
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
          apis: [
            'GET /circular/inputs/:id',
            'GET /circular/oplogs/:id',
          ],
          apisByAction: {
            update: ['PUT /circular/inputs/:id'],
          },
        },
      },
      {
        name: 'CircularWorkstation',
        path: 'workstation',
        component: () => import('#/views/circular/flow-board.vue'),
        meta: {
          icon: 'lucide:workflow',
          title: '通报工作台',
          perms: [
            { action: 'verify', label: '核验' },
            { action: 'distribute', label: '派发' },
            { action: 'review', label: '审核' },
          ],
          apis: [
            'GET /circular/verifications',
            'GET /circular/distributions',
            'GET /circular/reviews',
          ],
          apisByAction: {
            verify: ['POST /circular/verifications'],
            distribute: ['POST /circular/distributions'],
            review: ['POST /circular/reviews/:id'],
          },
        },
      },
      {
        name: 'CircularVerifyCompat',
        path: 'verify',
        redirect: '/circular/workstation?tab=verify',
        meta: { hideInMenu: true, title: '通报核验' },
      },
      {
        name: 'CircularDistributeCompat',
        path: 'distribute',
        redirect: '/circular/workstation?tab=distribute',
        meta: { hideInMenu: true, title: '通报派发' },
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
          apis: ['GET /circular/disposals'],
          apisByAction: {
            dispose: ['POST /circular/disposals/:id'],
            redistribute: ['POST /circular/disposals/redistribute'],
          },
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
          apis: ['GET /circular/disposals'],
          apisByAction: {
            dispose: ['POST /circular/disposals/:id'],
          },
        },
      },
      {
        name: 'CircularReviewCompat',
        path: 'review',
        redirect: '/circular/workstation?tab=review',
        meta: { hideInMenu: true, title: '通报审核' },
      },
      {
        name: 'CircularLedger',
        path: 'ledger',
        component: () => import('#/views/circular/ledger/list.vue'),
        meta: {
          icon: 'lucide:book-open',
          title: '通报台账',
          perms: [{ action: 'view', label: '查看' }, { action: 'export', label: '导出' }],
          apis: ['GET /circular/ledgers'],
          apisByAction: {
            view: ['GET /circular/ledgers'],
            export: ['POST /circular/inputs/export'],
          },
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
          apis: [
            'GET /circular/ledgers/:id',
            'GET /circular/oplogs/:id',
            'GET /circular/transfers/reports/:id/:format',
          ],
        },
      },
    ],
  },
];

export default routes;
