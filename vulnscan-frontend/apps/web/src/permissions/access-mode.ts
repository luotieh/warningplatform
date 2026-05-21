import { preferences } from '@vben/preferences';

/** 是否使用 IAM 后端菜单（生产推荐） */
export function isBackendAccessMode(): boolean {
  return preferences.app.accessMode === 'backend';
}

/**
 * 按钮权限是否严格校验（无权限码即隐藏/禁用，不再“未配置则放行”）
 */
export function isStrictButtonPerm(): boolean {
  return isBackendAccessMode();
}
