import { defineOverridesPreferences } from '@vben/preferences';

/**
 * 项目配置文件
 * 只需覆盖一部分配置，其余使用默认值
 * 更改配置后请清空浏览器缓存
 */
export const overridesPreferences = defineOverridesPreferences({
  app: {
    accessMode: 'frontend',
    defaultHomePath: '/dashboard/overview',
    name: import.meta.env.VITE_APP_TITLE,
  },
  logo: {
    source: '/logo.webp',
  },
  tabbar: {
    maxCount: 8,
  },
  widget: {
    languageToggle: false,
    timezone: false,
  },
});
