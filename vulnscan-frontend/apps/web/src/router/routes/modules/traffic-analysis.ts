import type { RouteRecordRaw } from 'vue-router';

import { BasicLayout } from '#/layouts';

/**
 * 流量分析（trafficAnalysis）业务子系统
 *
 * 二级菜单结构（仿「通报处置/通报工作台」）：父级 BasicLayout 承载
 * "流量分析" 菜单，二级为 总览 / 事件列表 / 配置；其中"总览"与"配置"
 * 各为单页 + 页签（同通报工作台 ?tab= 模式）。后端接口挂载在 /api/traffic。
 */
const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    name: 'TrafficAnalysis',
    path: '/traffic-analysis',
    redirect: '/ly/overview',
    meta: {
      icon: 'lucide:radar',
      order: 15,
      title: '流量分析',
    },
    children: [
      {
        name: 'LyOverview',
        path: '/ly/overview',
        component: () => import('#/views/ly/overview/index.vue'),
        meta: {
          icon: 'lucide:layout-dashboard',
          order: 10,
          title: '总览',
        },
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
        name: 'LyAssets',
        path: '/ly/assets',
        component: () => import('#/views/ly/assets/index.vue'),
        meta: {
          icon: 'lucide:database',
          order: 25,
          title: '资产管理',
        },
      },
      {
        name: 'LyConfig',
        path: '/ly/config',
        component: () => import('#/views/ly/config/index.vue'),
        meta: {
          icon: 'lucide:settings',
          order: 30,
          title: '配置',
        },
      },
      // 事件详情（隐藏）
      {
        name: 'LyEventDetail',
        path: '/ly/event/detail',
        component: () => import('#/views/ly/event/detail/index.vue'),
        meta: {
          hideInMenu: true,
          title: '事件详情',
          activePath: '/ly/event/list',
        },
      },
      {
        name: 'LyEventDeepflowDetail',
        path: '/ly/event/deepflow-detail',
        component: () => import('#/views/ly/event/deepflow-detail/index.vue'),
        meta: {
          hideInMenu: true,
          title: 'AI事件分析',
          activePath: '/ly/event/list',
        },
      },
      // 旧三级路径的兼容跳转（隐藏），保留 query（如搜索关键字）
      {
        name: 'LyOverviewOMCompat',
        path: '/ly/overview/om',
        redirect: (to) => ({ path: '/ly/overview', query: { ...to.query, tab: 'om' } }),
        meta: { hideInMenu: true, title: '运维总览' },
      },
      {
        name: 'LyOverviewMACompat',
        path: '/ly/overview/ma',
        redirect: (to) => ({ path: '/ly/overview', query: { ...to.query, tab: 'ma' } }),
        meta: { hideInMenu: true, title: '管理总览' },
      },
      {
        name: 'LySearchCompat',
        path: '/ly/search',
        redirect: (to) => ({ path: '/ly/overview', query: { ...to.query, tab: 'search' } }),
        meta: { hideInMenu: true, title: '搜索' },
      },
      {
        name: 'LyConfigRulesCompat',
        path: '/ly/config/rules',
        redirect: (to) => ({ path: '/ly/config', query: { ...to.query, tab: 'rules' } }),
        meta: { hideInMenu: true, title: '规则查看' },
      },
      {
        name: 'LyConfigNodeCompat',
        path: '/ly/config/node',
        redirect: (to) => ({ path: '/ly/config', query: { ...to.query, tab: 'node' } }),
        meta: { hideInMenu: true, title: '节点配置' },
      },
      {
        name: 'LyConfigModelCompat',
        path: '/ly/config/model',
        redirect: (to) => ({ path: '/ly/config', query: { ...to.query, tab: 'model' } }),
        meta: { hideInMenu: true, title: '模型配置' },
      },
    ],
  },
];

export default routes;
