import './compat-polyfills';

import { initPreferences } from '@vben/preferences';
import { unmountGlobalLoading } from '@vben/utils';

import {
  applyInitialThemeFromParent,
  enforceAppShellTheme,
} from './composables/use-theme-sync';
import { overridesPreferences } from './preferences';

/**
 * Initialize preferences before mounting the application.
 */
async function initApplication() {
  const env = import.meta.env.PROD ? 'prod' : 'dev';
  const appVersion = import.meta.env.VITE_APP_VERSION;
  const namespace = `${import.meta.env.VITE_APP_NAMESPACE}-${appVersion}-${env}`;

  // Bump this when cached Vben preferences become incompatible with app defaults.
  const PREFS_SCHEMA_VERSION = '6';
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

  if (!applyInitialThemeFromParent()) {
    enforceAppShellTheme();
  }

  const { bootstrap } = await import('./bootstrap');
  await bootstrap(namespace);

  unmountGlobalLoading();
}

initApplication();
