<script lang="ts" setup>
import type { GlobalThemeOverrides } from 'naive-ui';

import { computed, onMounted, onUnmounted, ref } from 'vue';

import { useElementPlusDesignTokens, useNaiveDesignTokens } from '@vben/hooks';
import { preferences } from '@vben/preferences';

import { useThemeSync } from '#/composables/use-theme-sync';

import {
  darkTheme,
  dateEnUS,
  dateZhCN,
  enUS,
  lightTheme,
  NConfigProvider,
  NDialogProvider,
  NMessageProvider,
  NNotificationProvider,
  zhCN,
} from 'naive-ui';

defineOptions({ name: 'App' });

useThemeSync();

const { commonTokens } = useNaiveDesignTokens();
/** 将 Element Plus --el-* 与 CSS 设计令牌对齐（IAM 前端无 Element，此处需显式同步以免 dark/css-vars 残留冷色底） */
useElementPlusDesignTokens();

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
  const fontFamily = getComputedStyle(document.documentElement)
    .getPropertyValue('--font-family')
    .trim();
  return {
    common: {
      ...commonTokens,
      ...(fontFamily ? { fontFamily } : {}),
      fontFamilyMono:
        getComputedStyle(document.documentElement)
          .getPropertyValue('--font-family-mono')
          .trim() || undefined,
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
      <NDialogProvider>
        <NMessageProvider>
          <RouterView />
        </NMessageProvider>
      </NDialogProvider>
    </NNotificationProvider>
  </NConfigProvider>
</template>
