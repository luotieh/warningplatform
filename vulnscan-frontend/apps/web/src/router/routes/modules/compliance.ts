import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:clipboard-check', order: 5, title: '合规检查' },
    name: 'Compliance',
    path: '/compliance',
    redirect: '/compliance/baselines',
    children: [
      {
        name: 'ComplianceBaselines',
        path: 'baselines',
        component: () => import('#/views/compliance/index.vue'),
        meta: { icon: 'lucide:shield-check', title: '基线检查' },
      },
    ],
  },
];

export default routes;
