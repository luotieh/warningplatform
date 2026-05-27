import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:settings', order: 99, title: '系统管理' },
    name: 'System',
    path: '/system',
    redirect: '/system/settings',
    children: [
      {
        name: 'SystemSettings',
        path: 'settings',
        component: () => import('#/views/system/settings.vue'),
        meta: {
          title: '系统设置',
          icon: 'lucide:sliders-horizontal',
          perms: [{ action: 'view', label: '查看' }, { action: 'update', label: '保存' }],
          apis: ['GET /setting/list'],
          apisByAction: {
            view: ['GET /setting/list'],
            update: ['PUT /setting/batch'],
          },
        },
      },
      {
        name: 'SystemDict',
        path: 'dict',
        component: () => import('#/views/system/dict.vue'),
        meta: {
          title: '数据字典',
          icon: 'lucide:list-tree',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
          apis: ['GET /system/dict'],
          apisByAction: {
            create: ['POST /system/dict'],
            update: ['PUT /system/dict/detail/:id'],
            delete: ['DELETE /system/dict/detail/:id'],
          },
        },
      },
      {
        name: 'SystemInit',
        path: 'init',
        component: () => import('#/views/system/init.vue'),
        meta: {
          title: '系统初始化',
          icon: 'lucide:database',
          perms: [{ action: 'sync-menu', label: '同步菜单到IAM' }],
          apis: [],
          apisByAction: {
            'sync-menu': ['POST /system/iam/sync-frontends'],
          },
        },
      },
    ],
  },
];

export default routes;
