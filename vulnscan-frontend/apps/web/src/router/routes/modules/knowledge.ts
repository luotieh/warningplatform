import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:database', order: 6, title: '知识库' },
    name: 'Knowledge',
    path: '/knowledge',
    redirect: '/knowledge/poc',
    children: [
      {
        name: 'PocManage',
        path: 'poc',
        component: () => import('#/views/knowledge/poc/list.vue'),
        meta: {
          icon: 'lucide:file-code',
          title: 'PoC 管理',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'import', label: '导入' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
        },
      },
      {
        name: 'FingerprintManage',
        path: 'fingerprint',
        component: () => import('#/views/knowledge/fingerprint/list.vue'),
        meta: {
          icon: 'lucide:fingerprint',
          title: '指纹库',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
        },
      },
      {
        name: 'DictManage',
        path: 'dict',
        component: () => import('#/views/knowledge/dict/list.vue'),
        meta: {
          icon: 'lucide:book-open',
          title: '字典管理',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'import', label: '导入' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
        },
      },
      {
        name: 'DictWordDetail',
        path: 'dict/word/:id',
        component: () =>
          import('#/views/knowledge/rule-dict/word-detail.vue'),
        meta: {
          hideInMenu: true,
          title: '词库详情',
          activePath: '/knowledge/dict',
        },
      },
      {
        name: 'DictFileDetail',
        path: 'dict/file/:id',
        component: () =>
          import('#/views/knowledge/rule-dict/file-detail.vue'),
        meta: {
          hideInMenu: true,
          title: '文件库详情',
          activePath: '/knowledge/dict',
        },
      },
      {
        name: 'RuleEngine',
        path: 'rule-engine',
        component: () => import('#/views/knowledge/rule-engine/index.vue'),
        meta: {
          icon: 'lucide:settings-2',
          title: '规则引擎',
          perms: [
            { action: 'update', label: '编辑' },
            { action: 'import', label: '导入' },
            { action: 'sync', label: '同步' },
          ],
        },
      },
      {
        name: 'RuleEngineDetail',
        path: 'rule-engine/detail/:key',
        component: () => import('#/views/knowledge/rule-engine/detail.vue'),
        meta: {
          hideInMenu: true,
          title: '规则编辑',
          activePath: '/knowledge/rule-engine',
        },
      },
      {
        name: 'KnowledgeArticles',
        path: 'articles',
        component: () => import('#/views/knowledge/articles/index.vue'),
        meta: {
          icon: 'lucide:notebook-pen',
          title: '安全知识',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
            { action: 'archive', label: '归档' },
          ],
        },
      },
      {
        name: 'KnowledgeArticleDetail',
        path: 'articles/:id',
        component: () => import('#/views/knowledge/articles/detail.vue'),
        meta: { hideInMenu: true, title: '知识详情' },
      },
    ],
  },
];

export default routes;
