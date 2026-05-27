import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:clipboard-list', order: 12, title: '表单中心' },
    name: 'FormCenter',
    path: '/form',
    redirect: '/form/templates',
    children: [
      {
        name: 'FormTemplates',
        path: 'templates',
        component: () => import('#/views/form/templates.vue'),
        meta: {
          icon: 'lucide:panel-top',
          title: '表单模板',
          perms: [
            { action: 'create', label: '新建模板' },
            { action: 'update', label: '编辑模板' },
            { action: 'delete', label: '删除模板' },
          ],
          apis: ['GET /formdesign/templates'],
          apisByAction: {
            create: ['POST /formdesign/templates'],
            update: ['PUT /formdesign/templates/:id'],
            delete: ['DELETE /formdesign/templates/:id'],
          },
        },
      },
      {
        name: 'FormDesigner',
        path: 'designer/:id?',
        component: () => import('#/views/form/designer.vue'),
        meta: { hideInMenu: true, icon: 'lucide:square-pen', title: '表单设计' },
      },
      {
        name: 'FormSubmissions',
        path: 'submissions',
        component: () => import('#/views/form/submissions.vue'),
        meta: { icon: 'lucide:database', title: '表单数据' },
      },
    ],
  },
];

export default routes;
