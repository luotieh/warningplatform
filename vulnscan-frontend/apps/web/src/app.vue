<script lang="ts" setup>
import type { GlobalThemeOverrides } from 'naive-ui';

import { computed, onMounted, onUnmounted, ref } from 'vue';

import { useNaiveDesignTokens } from '@vben/hooks';
import { preferences } from '@vben/preferences';

import { useThemeSync } from '#/composables/use-theme-sync';

import {
  darkTheme,
  dateEnUS,
  dateZhCN,
  enUS,
  lightTheme,
  NConfigProvider,
  NMessageProvider,
  NNotificationProvider,
  zhCN,
} from 'naive-ui';

defineOptions({ name: 'App' });

useThemeSync();

const { commonTokens } = useNaiveDesignTokens();

const tokenLocale = computed(() =>
  preferences.app.locale === 'zh-CN' ? zhCN : enUS,
);
const tokenDateLocale = computed(() =>
  preferences.app.locale === 'zh-CN' ? dateZhCN : dateEnUS,
);
const systemDark = ref(false);
let mediaQuery: MediaQueryList | null = null;
const handleSystemTheme = (e: MediaQueryListEvent | MediaQueryList) => {
  systemDark.value = e.matches;
};

onMounted(() => {
  if (typeof window !== 'undefined' && window.matchMedia) {
    mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    handleSystemTheme(mediaQuery);
    mediaQuery.addEventListener?.('change', handleSystemTheme);
  }
});

onUnmounted(() => {
  mediaQuery?.removeEventListener?.('change', handleSystemTheme);
});

const tokenTheme = computed(() => {
  const mode = preferences.theme.mode;
  if (mode === 'dark') return darkTheme;
  if (mode === 'auto') return systemDark.value ? darkTheme : lightTheme;
  return lightTheme;
});

const themeOverrides = computed((): GlobalThemeOverrides => {
  return {
    common: {
      ...commonTokens,
      borderRadius: '6px',
      borderRadiusSmall: '4px',
    },
    Card: {
      borderRadius: '10px',
      paddingSmall: '16px 20px',
      titleFontSizeSmall: '15px',
      titleFontWeight: '600',
    },
    DataTable: {
      borderRadius: '8px',
      thPaddingSmall: '10px 12px',
      tdPaddingSmall: '8px 12px',
      fontSizeSmall: '13px',
    },
    Tag: {
      borderRadius: '6px',
    },
    Button: {
      borderRadiusSmall: '6px',
      borderRadiusMedium: '8px',
    },
    Statistic: {
      valueFontSize: '24px',
      labelFontSize: '12px',
    },
    Drawer: {
      borderRadius: '12px 0 0 12px',
    },
    Progress: {
      borderRadius: '6px',
    },
  };
});
</script>

<template>
  <NConfigProvider
    :date-locale="tokenDateLocale"
    :locale="tokenLocale"
    :theme="tokenTheme"
    :theme-overrides="themeOverrides"
    class="h-full"
  >
    <NNotificationProvider>
      <NMessageProvider>
        <RouterView />
      </NMessageProvider>
    </NNotificationProvider>
  </NConfigProvider>
</template>
