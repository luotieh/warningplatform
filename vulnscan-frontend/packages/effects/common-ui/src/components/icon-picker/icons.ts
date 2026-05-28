import type { Recordable } from '@vben/types';

import { getOfflineIconNames } from '@vben/icons';

export const ICONS_MAP: Recordable<string[]> = {};

/**
 * 从本地预置 Iconify 图标集中获取图标名称。
 * 禁止访问 api.iconify.design / api.unisvg.com 等外部服务，避免业务前端产生非后端请求。
 * @param prefix 图标集名称
 * @returns 图标集中包含的所有图标名称
 */
export async function fetchIconsData(prefix: string): Promise<string[]> {
  if (Reflect.has(ICONS_MAP, prefix) && ICONS_MAP[prefix]) {
    return ICONS_MAP[prefix];
  }

  ICONS_MAP[prefix] = getOfflineIconNames(prefix);
  return ICONS_MAP[prefix];
}
