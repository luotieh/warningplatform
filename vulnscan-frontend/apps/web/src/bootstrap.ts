import { computed, createApp } from 'vue';

import { registerAccessDirective } from '@vben/access';
import { registerLoadingDirective } from '@vben/common-ui';

import { registerCustomDirectives } from '#/directives';
import { preferences, updatePreferences } from '@vben/preferences';
import { initStores } from '@vben/stores';
import '@vben/styles';
import '@vben/styles/naive';

import formCreatePlugin from '@form-create/naive-ui';
import formCreateAutoImport from '@form-create/naive-ui/auto-import';
import '@form-create/naive-ui/src/style/index.css';
import FcDesigner from '@form-create/designer';
import '@form-create/designer/src/style/index.css';
import ElementPlus from 'element-plus';
import 'element-plus/dist/index.css';
import '#/assets/styles/form-designer-element-dark.css';
import '#/assets/styles/app-theme.css';
import '#/assets/styles/app-fonts.css';
import '#/assets/styles/app-typography.css';
/* 最后加载壳层（参考 iam-frontend：iam-global 紧跟 naive；此处压过 Element / form-create） */
import './styles/app-shell.css';
import { useTitle } from '@vueuse/core';

import { $t, setupI18n } from '#/locales';

import { initComponentAdapter } from './adapter/component';
import { initSetupVbenForm } from './adapter/form';
import { message } from './adapter/naive';
import App from './app.vue';
import { router } from './router';

function setupLoadingDirectives(app: ReturnType<typeof createApp>) {
  const spinning = app.directive('spinning');

  if (spinning) {
    return;
  }

  // Element Plus registers v-loading globally. Keep Vben on v-spinning to
  // avoid duplicate directive warnings during startup and HMR.
  registerLoadingDirective(app, {
    loading: false,
    spinning: 'spinning',
  });
}

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
      if (
        msg &&
        !/network|cancel|aborted|chunk|auth_revoked|token.*expired|unauthorized|401/i.test(
          msg,
        )
      ) {
        message.error(msg);
      }
    });
  }
}

async function bootstrap(namespace: string) {
  const [, , { initTippy }, { MotionPlugin }] = await Promise.all([
    initComponentAdapter(),
    initSetupVbenForm(),
    import('@vben/common-ui/es/tippy'),
    import('@vben/plugins/motion'),
  ]);

  const app = createApp(App);
  const formCreate =
    (formCreatePlugin as any).default ?? formCreatePlugin;

  ((formCreateAutoImport as any).default ?? formCreateAutoImport)(formCreate);

  setupGlobalErrorHandlers(app);
  app.use(formCreate);
  app.use(ElementPlus);
  app.use((FcDesigner as any).default ?? FcDesigner);

  setupLoadingDirectives(app);

  await Promise.all([setupI18n(app), initStores(app, { namespace })]);

  if (new URLSearchParams(window.location.search).has('embed')) {
    updatePreferences({
      app: { layout: 'sidebar-nav' },
      header: { hidden: true },
      sidebar: { hidden: false },
      footer: { enable: false },
    });
  }

  registerAccessDirective(app);
  registerCustomDirectives(app);

  initTippy(app);
  app.use(MotionPlugin);
  app.use(router);

  const pageTitle = computed(() => {
    if (!preferences.app.dynamicTitle) return preferences.app.name;
    const routeTitle = router.currentRoute.value.meta?.title;
    return (routeTitle ? `${$t(routeTitle)} - ` : '') + preferences.app.name;
  });
  useTitle(pageTitle);

  app.mount('#app');
}

export { bootstrap };
