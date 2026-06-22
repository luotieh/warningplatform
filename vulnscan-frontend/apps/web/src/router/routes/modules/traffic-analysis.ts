import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

/**
 * 流量分析（trafficAnalysis）业务子系统
 *
 * 作为左侧菜单的一项接入：父级 BasicLayout 承载 "流量分析" 菜单，
 * 子路由为总览 / 事件列表 / 配置。后端接口统一挂载在 /api/traffic 下。
 */
const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    name: 'TrafficAnalysis',
    path: '/traffic-analysis',
    redirect: '/ly/overview/om',
    meta: {
      icon: 'lucide:radar',
      order: 15,
      title: '流量分析',
    },
    children: [
      {
        name: 'LyOverview',
        path: '/ly/overview',
        redirect: '/ly/overview/om',
        meta: {
          icon: 'lucide:layout-dashboard',
          order: 10,
          title: '总览',
        },
        children: [
          {
            name: 'LyOverviewOM',
            path: 'om',
            component: () => import('#/views/ly/overview/om/index.vue'),
            meta: {
              order: 10,
              title: '运维总览',
            },
          },
          {
            name: 'LyOverviewMA',
            path: 'ma',
            component: () => import('#/views/ly/overview/ma/index.vue'),
            meta: {
              order: 20,
              title: '管理总览',
            },
          },
          {
            name: 'LySearch',
            path: '/ly/search',
            component: () => import('#/views/ly/search/index.vue'),
            meta: {
              order: 30,
              title: '搜索',
            },
          },
        ],
      },
      {
        name: 'LyEventList',
        path: '/ly/event/list',
        component: () => import('#/views/ly/event/list/index.vue'),
        meta: {
          icon: 'lucide:triangle-alert',
          order: 20,
          title: '事件列表',
        },
      },
      {
        name: 'LyEventDetail',
        path: '/ly/event/detail',
        component: () => import('#/views/ly/event/detail/index.vue'),
        meta: {
          hideInMenu: true,
          title: '事件详情',
        },
      },
      {
        name: 'LyEventDeepflowDetail',
        path: '/ly/event/deepflow-detail',
        component: () => import('#/views/ly/event/deepflow-detail/index.vue'),
        meta: {
          hideInMenu: true,
          title: 'AI事件分析',
        },
      },
      {
        name: 'LyConfig',
        path: '/ly/config',
        redirect: '/ly/config/rules',
        meta: {
          icon: 'lucide:settings',
          order: 40,
          title: '配置',
        },
        children: [
          {
            name: 'LyConfigRules',
            path: 'rules',
            component: () => import('#/views/ly/config/rules/index.vue'),
            meta: {
              order: 10,
              title: '规则查看',
            },
          },
          {
            name: 'LyConfigNode',
            path: 'node',
            component: () => import('#/views/ly/config/node/index.vue'),
            meta: {
              order: 20,
              title: '节点配置',
            },
          },
          {
            name: 'LyConfigModel',
            path: 'model',
            component: () => import('#/views/ly/config/model/index.vue'),
            meta: {
              order: 30,
              title: '模型配置',
            },
          },
        ],
      },
    ],
  },
];

export default routes;
