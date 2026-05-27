/**
 * 路由权限声明预设工具
 *
 * 用于简化路由定义中的 meta.perms 声明。
 * 与 use-route-sync.ts 配合，声明的 perms 会在路由同步时自动注册到后端。
 *
 * @example
 * // 标准 CRUD
 * meta: { perms: crud('角色') }
 *
 * // CRUD + 额外操作
 * meta: { perms: crud('角色', { batch: '批量操作', 'assign-permission': '分配权限' }) }
 *
 * // 自定义操作
 * meta: { perms: actions({ export: '导出审计', config: '配置规则' }) }
 */
import type { RoutePerm } from './route-perm';

export function crud(
  label?: string,
  extra?: Record<string, string>,
): RoutePerm[] {
  const l = label || '';
  const result: RoutePerm[] = [
    { action: 'create', title: `新增${l}` },
    { action: 'update', title: `编辑${l}` },
    { action: 'delete', title: `删除${l}` },
  ];
  if (extra) {
    for (const [action, title] of Object.entries(extra)) {
      result.push({ action, title });
    }
  }
  return result;
}

export function actions(mapping: Record<string, string>): RoutePerm[] {
  return Object.entries(mapping).map(([action, title]) => ({ action, title }));
}
