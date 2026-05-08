/**
 * 声明式路由权限系统
 *
 * 权限码由路由路径自动推导，不需要手动维护常量文件。
 *
 * 推导规则：
 *   路由 path  "/identity/user"  → namespace "identity:user"
 *   action     "create"          → 完整码    "identity:user:create"
 *
 * 使用方式：
 *   路由定义中声明 meta.perms: [{ action: 'create', title: '新增用户' }]
 *   组件中使用    v-perm="perm('create')"
 */

export interface RoutePerm {
  action: string;
  title: string;
}

/**
 * 将路由路径转换为权限命名空间
 * /identity/user → identity:user
 * /authorize/role → authorize:role
 * /governance/risk-case → governance:risk-case
 */
export function pathToNamespace(routePath: string): string {
  return routePath
    .replace(/^\/+/, '')
    .replace(/\/+$/, '')
    .split('/')
    .filter(Boolean)
    .join(':');
}

/**
 * 生成完整权限码
 */
export function buildPermCode(namespace: string, action: string): string {
  return `${namespace}:${action}`;
}

/**
 * 从路由 meta 中提取 perms 声明
 */
export function getRoutePerms(meta: Record<string, any>): RoutePerm[] {
  return Array.isArray(meta.perms) ? meta.perms : [];
}

/**
 * 创建当前路由的权限码生成器
 *
 * @example
 * const perm = createPermResolver('/identity/user');
 * perm('create')  // → 'identity:user:create'
 * perm('delete')  // → 'identity:user:delete'
 */
export function createPermResolver(routePath: string): (action: string) => string {
  const ns = pathToNamespace(routePath);
  return (action: string) => buildPermCode(ns, action);
}
