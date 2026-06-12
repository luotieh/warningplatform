import { defineOverridesPreferences } from '@vben/preferences';

import { resolveFontFamilyStack } from '#/config/custom-fonts';

const envFontFamily = import.meta.env.VITE_APP_FONT_FAMILY?.trim();
const themeFontFamily = envFontFamily
  ? resolveFontFamilyStack(envFontFamily)
  : undefined;

/**
 * 项目偏好配置。
 * 这里只覆盖业务子系统需要调整的部分，其余配置沿用 Vben 默认值。
 * 修改配置后如果未立即生效，请清理浏览器缓存或提升偏好配置 schema 版本。
 */
export const overridesPreferences = defineOverridesPreferences({
  app: {
    accessMode: 'backend',
    defaultAvatar: '/avatar.webp',
    defaultHomePath: '/workbench/overview',
    enableCheckUpdates: false,
    enableRefreshToken: true,
    name: import.meta.env.VITE_APP_TITLE,
  },
  copyright: {
    companySiteLink: '',
  },
  logo: {
    source: '/logo.webp',
  },
  tabbar: {
    maxCount: 0,
  },
  theme: {
    builtinType: 'default',
    mode: 'light',
    fontSize: 14,
    semiDarkHeader: false,
    semiDarkSidebar: false,
    ...(themeFontFamily ? { fontFamily: themeFontFamily } : {}),
  },
  widget: {
    languageToggle: false,
    timezone: false,
  },
});
