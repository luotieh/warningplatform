import { createApp, watchEffect } from 'vue';

import { registerAccessDirective } from '@vben/access';
import { registerLoadingDirective } from '@vben/common-ui';

import { registerCustomDirectives } from '#/directives';
import { preferences, updatePreferences } from '@vben/preferences';
import { initStores } from '@vben/stores';
import '@vben/styles';
import '@vben/styles/naive';

import { useTitle } from '@vueuse/core';

import { $t, setupI18n } from '#/locales';

import { initComponentAdapter } from './adapter/component';
import { initSetupVbenForm } from './adapter/form';
import { message } from './adapter/naive';
import App from './app.vue';
import { router } from './router';

function setupGlobalErrorHandlers(app: ReturnType<typeof createApp>) {
  app.config.errorHandler = (err, _instance, info) => {
    console.error('[VueErrorHandler]', err, info);
    const msg =
      err instanceof Error ? err.message : String(err ?? 'Unknown error');
    if (msg) message.error(msg);
  };

  if (typeof window !== 'undefined') {
    window.addEventListener('unhandledrejection', (event) => {
      const reason = event.reason;
      if (reason?.__silent) return;
      console.error('[UnhandledRejection]', reason);
      const msg =
        reason instanceof Error
          ? reason.message
          : typeof reason === 'string'
            ? reason
            : '';
      if (msg && !/network|cancel|aborted|chunk|auth_revoked|token.*expired|unauthorized|401/i.test(msg)) {
        message.error(msg);
      }
    });
  }
}

async function bootstrap(namespace: string) {
  // 初始化组件适配器
  await initComponentAdapter();

  // 初始化表单组件
  await initSetupVbenForm();

  // // 设置弹窗的默认配置
  // setDefaultModalProps({
  //   fullscreenButton: false,
  // });
  // // 设置抽屉的默认配置
  // setDefaultDrawerProps({
  //   // zIndex: 2000,
  // });

  const app = createApp(App);

  setupGlobalErrorHandlers(app);

  // 注册v-loading指令
  registerLoadingDirective(app, {
    loading: 'loading', // 在这里可以自定义指令名称,也可以明确提供false表示不注册这个指令
    spinning: 'spinning',
  });

  // 国际化 i18n 配置
  await setupI18n(app);

  // 配置 pinia-tore
  await initStores(app, { namespace });

  // embed 模式：URL 含 ?embed 时隐藏顶栏（IAM 已提供），保留侧边栏菜单
  if (new URLSearchParams(window.location.search).has('embed')) {
    updatePreferences({
      app: { layout: 'sidebar-nav' },
      header: { hidden: true },
      sidebar: { hidden: false },
      footer: { enable: false },
    });
  }

  // 安装权限指令
  registerAccessDirective(app);
  registerCustomDirectives(app);

  // 初始化 tippy
  const { initTippy } = await import('@vben/common-ui/es/tippy');
  initTippy(app);

  // 配置路由及路由守卫
  app.use(router);

  // 配置Motion插件
  const { MotionPlugin } = await import('@vben/plugins/motion');
  app.use(MotionPlugin);

  // 动态更新标题
  watchEffect(() => {
    if (preferences.app.dynamicTitle) {
      const routeTitle = router.currentRoute.value.meta?.title;
      const pageTitle =
        (routeTitle ? `${$t(routeTitle)} - ` : '') + preferences.app.name;
      useTitle(pageTitle);
    }
  });

  app.mount('#app');
}

export { bootstrap };
