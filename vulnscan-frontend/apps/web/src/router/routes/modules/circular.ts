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
          title: '通报录入',
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
        name: 'CircularVerify',
        path: 'verify',
        component: () => import('#/views/circular/flow-board.vue'),
        props: { mode: 'verify' },
        meta: {
          icon: 'lucide:check-circle',
          title: '通报核验',
          perms: [
            { action: 'verify', label: '核验' },
          ],
          apis: ['GET /circular/verifications'],
          apisByAction: { verify: ['POST /circular/verifications'] },
        },
      },
      {
        name: 'CircularDistribute',
        path: 'distribute',
        component: () => import('#/views/circular/flow-board.vue'),
        props: { mode: 'distribute' },
        meta: {
          icon: 'lucide:send',
          title: '通报派发',
          perms: [
            { action: 'distribute', label: '派发' },
          ],
          apis: ['GET /circular/distributions'],
          apisByAction: { distribute: ['POST /circular/distributions'] },
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
        name: 'CircularReview',
        path: 'review',
        component: () => import('#/views/circular/flow-board.vue'),
        props: { mode: 'review' },
        meta: {
          icon: 'lucide:clipboard-check',
          title: '通报审核',
          perms: [
            { action: 'review', label: '审核' },
          ],
          apis: ['GET /circular/reviews'],
          apisByAction: { review: ['POST /circular/reviews/:id'] },
        },
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
