import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:radar', order: 7, title: '攻击面管理' },
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
      {
        name: 'ASMCyberspaceSearch',
        path: 'cyberspace',
        component: () => import('#/views/asset/cyberspace.vue'),
        meta: { icon: 'lucide:globe', title: '空间搜索' },
      },
      {
        name: 'ASMSecurity',
        path: 'security',
        component: () => import('#/views/asset/security.vue'),
        meta: { icon: 'lucide:activity', title: '安全态势' },
      },
    ],
  },
];

export default routes;
