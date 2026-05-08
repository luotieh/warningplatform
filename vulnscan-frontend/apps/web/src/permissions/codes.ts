/**
 * 权限码常量（由路由路径自动推导）
 *
 * 推导规则：路由 path + action → 权限码
 *   /asset/list + create → asset:list:create
 */

export const PERM = {} as const;

export type PermCode = string;
