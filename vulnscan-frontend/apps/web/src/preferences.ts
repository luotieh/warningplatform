import { defineOverridesPreferences } from '@vben/preferences';

/**
 * 项目偏好配置。
 * 这里只覆盖业务子系统需要调整的部分，其余配置沿用 Vben 默认值。
 * 修改配置后如果未立即生效，请清理浏览器缓存或提升偏好配置 schema 版本。
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
  theme: {
    builtinType: 'default',
    mode: 'light',
    semiDarkHeader: false,
    semiDarkSidebar: false,
  },
  widget: {
    languageToggle: false,
    timezone: false,
  },
});
