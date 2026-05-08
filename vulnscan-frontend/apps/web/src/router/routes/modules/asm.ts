import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:radar', order: 3, title: '攻击面管理' },
    name: 'ASM',
    path: '/asm',
    redirect: '/asm/projects',
    children: [
      {
        name: 'ASMProjects',
        path: 'projects',
        component: () => import('#/views/asm/index.vue'),
        meta: {
          icon: 'lucide:folder-search',
          title: '发现项目',
          perms: [
            { action: 'create', label: '新建项目' },
            { action: 'delete', label: '删除' },
            { action: 'discover', label: '执行发现' },
          ],
        },
      },
    ],
  },
];

export default routes;
