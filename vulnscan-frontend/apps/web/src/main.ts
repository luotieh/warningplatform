import './compat-polyfills';

import { initPreferences } from '@vben/preferences';
import { unmountGlobalLoading } from '@vben/utils';

import {
  applyInitialThemeFromParent,
  enforceAppShellTheme,
} from './composables/use-theme-sync';
import { overridesPreferences } from './preferences';
import { registerCustomFontFaces } from './utils/apply-custom-fonts';
import { installFrontendNetworkGuard } from './utils/network-guard';

installFrontendNetworkGuard();
registerCustomFontFaces();

/**
 * Initialize preferences before mounting the application.
 */
async function initApplication() {
  const env = import.meta.env.PROD ? 'prod' : 'dev';
  const appVersion = import.meta.env.VITE_APP_VERSION;
  const namespace = `${import.meta.env.VITE_APP_NAMESPACE}-${appVersion}-${env}`;

  // Bump this when cached Vben preferences become incompatible with app defaults.
  const PREFS_SCHEMA_VERSION = '7';
  const versionKey = `${namespace}__schema_v`;
  if (localStorage.getItem(versionKey) !== PREFS_SCHEMA_VERSION) {
    for (const key of Object.keys(localStorage)) {
      if (key.startsWith(namespace)) {
        localStorage.removeItem(key);
      }
    }
    localStorage.removeItem('iam_theme');
    localStorage.setItem(versionKey, PREFS_SCHEMA_VERSION);
  }

  await initPreferences({
    namespace,
    overrides: overridesPreferences,
  });

  // 锁定为 IAM 后端菜单模式，避免偏好缓存被改成 frontend 导致全量菜单
  const { updatePreferences } = await import('@vben/preferences');
  updatePreferences({
    app: { accessMode: 'backend' },
  });

  if (!applyInitialThemeFromParent()) {
    enforceAppShellTheme();
  }

  const { bootstrap } = await import('./bootstrap');
  await bootstrap(namespace);

  unmountGlobalLoading();
}

initApplication();
