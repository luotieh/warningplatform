import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:shield-alert', order: 4, title: '威胁情报' },
    name: 'Intel',
    path: '/intel',
    redirect: '/intel/cve',
    children: [
      {
        name: 'IntelCVE',
        path: 'cve',
        component: () => import('#/views/intel/index.vue'),
        meta: { icon: 'lucide:database', title: '情报库' },
      },
    ],
  },
];

export default routes;
