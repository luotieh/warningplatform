import { computed } from 'vue';

import { preferences } from '@vben/preferences';
import '@vben/styles';

import { createDiscreteApi, darkTheme, lightTheme } from 'naive-ui';

function resolveNaiveTheme() {
  if (preferences.theme.mode === 'dark') return darkTheme;
  if (preferences.theme.mode === 'auto') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches
      ? darkTheme
      : lightTheme;
  }
  return lightTheme;
}

const themeOverridesProviderProps = computed(() => ({
  themeOverrides: resolveNaiveTheme(),
}));

const themeProviderProps = computed(() => ({
  theme: resolveNaiveTheme(),
}));

export const { dialog, loadingBar, message, modal, notification } =
  createDiscreteApi(
    ['message', 'dialog', 'notification', 'loadingBar', 'modal'],
    {
      configProviderProps: themeProviderProps,
      loadingBarProviderProps: themeOverridesProviderProps,
      messageProviderProps: themeOverridesProviderProps,
      notificationProviderProps: themeOverridesProviderProps,
    },
  );
