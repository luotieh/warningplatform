import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:database', order: 11, title: '知识仓库' },
    name: 'Knowledge',
    path: '/knowledge',
    redirect: '/knowledge/poc',
    children: [
      {
        name: 'ProductManage',
        path: 'product',
        component: () => import('#/views/knowledge/product/list.vue'),
        meta: {
          icon: 'lucide:box',
          title: '产品库',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
          apis: ['GET /products/list'],
          apisByAction: {
            create: ['POST /products'],
            update: ['PUT /products/:id'],
            delete: ['DELETE /products/:id'],
          },
        },
      },
      {
        name: 'PocManage',
        path: 'poc',
        component: () => import('#/views/knowledge/poc/list.vue'),
        meta: {
          icon: 'lucide:file-code',
          title: '检测模板',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'import', label: '导入' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
          apis: ['GET /poc/list'],
          apisByAction: {
            create: ['POST /poc'],
            import: ['POST /poc/import'],
            update: ['PUT /poc/:id'],
            delete: ['DELETE /poc/:id'],
          },
        },
      },
      {
        name: 'FingerprintManage',
        path: 'fingerprint',
        component: () => import('#/views/knowledge/fingerprint/list.vue'),
        meta: {
          icon: 'lucide:fingerprint',
          title: '识别指纹',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
          apis: ['GET /fingerprint/list'],
          apisByAction: {
            create: ['POST /fingerprint'],
            update: ['PUT /fingerprint/:id'],
            delete: ['DELETE /fingerprint/:id'],
          },
        },
      },
      {
        name: 'DataLibManage',
        path: 'datalib',
        component: () => import('#/views/knowledge/datalib/list.vue'),
        meta: {
          icon: 'lucide:book-open',
          title: '扫描字典',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'import', label: '导入' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
          apis: ['GET /data-libraries'],
          apisByAction: {
            create: ['POST /data-libraries'],
            import: ['POST /data-libraries/:id/entries'],
            update: ['PUT /data-libraries/:id'],
            delete: ['DELETE /data-libraries/:id'],
          },
        },
      },
      {
        name: 'DictWordDetail',
        path: 'datalib/word/:id',
        component: () =>
          import('#/views/knowledge/rule-dict/word-detail.vue'),
        meta: {
          hideInMenu: true,
          title: '词库详情',
          activePath: '/knowledge/datalib',
          apis: ['GET /data-libraries/:id', 'GET /data-libraries/:id/entries'],
        },
      },
      {
        name: 'DictFileDetail',
        path: 'datalib/file/:id',
        component: () =>
          import('#/views/knowledge/rule-dict/file-detail.vue'),
        meta: {
          hideInMenu: true,
          title: '文件库详情',
          activePath: '/knowledge/datalib',
          apis: ['GET /data-libraries/:id', 'GET /data-libraries/:id/entries'],
        },
      },
      {
        name: 'PromptManage',
        path: 'prompt',
        component: () => import('#/views/knowledge/prompt/list.vue'),
        meta: {
          icon: 'lucide:message-square-code',
          title: '提示模板',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
          apis: ['GET /prompt-templates'],
          apisByAction: {
            create: ['POST /prompt-templates'],
            update: ['PUT /prompt-templates/:id', 'POST /prompt-templates/:id/toggle'],
            delete: ['DELETE /prompt-templates/:id'],
          },
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
          apis: ['GET /sitemonitor/rule-data', 'GET /cluster/node-knowledge/manifest'],
          apisByAction: {
            update: ['PUT /sitemonitor/rule-data/:moduleKey'],
            import: ['POST /sitemonitor/rule-data/:moduleKey/import'],
            sync: ['POST /sitemonitor/rule-data/sync'],
          },
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
          apis: [
            'GET /sitemonitor/rule-data/:moduleKey',
          ],
          apisByAction: {
            update: ['PUT /sitemonitor/rule-data/:moduleKey'],
          },
        },
      },
      {
        name: 'KnowledgeArticles',
        path: 'articles',
        component: () => import('#/views/knowledge/articles/index.vue'),
        meta: {
          icon: 'lucide:notebook-pen',
          title: '安全知识',
          hideInMenu: true,
          perms: [
            { action: 'create', label: '新建' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
            { action: 'archive', label: '归档' },
          ],
          apis: ['GET /incident/knowledge'],
          apisByAction: {
            create: ['POST /incident/knowledge'],
            update: ['PUT /incident/knowledge/:id'],
            delete: ['DELETE /incident/knowledge/:id'],
            archive: ['POST /incident/knowledge/archive'],
          },
        },
      },
      {
        name: 'KnowledgeIntel',
        path: 'intel',
        component: () => import('#/views/intel/index.vue'),
        meta: {
          icon: 'lucide:shield-alert',
          title: '威胁情报',
          apis: [
            'GET /intel/cve',
            'GET /intel/stats',
            'GET /intel/sources',
            'GET /intel/ioc',
          ],
        },
      },
      {
        name: 'KnowledgeArticleDetail',
        path: 'articles/:id',
        component: () => import('#/views/knowledge/articles/detail.vue'),
        meta: {
          hideInMenu: true,
          title: '知识详情',
          apis: ['GET /incident/knowledge/:id'],
        },
      },
    ],
  },
];

export default routes;
