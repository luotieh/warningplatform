/**
 * 行操作列统一封装
 *
 * 用法：
 *   const renderActions = useActionColumn<UserItem>([
 *     { label: '查看', onClick: row => view(row), type: 'info' },
 *     { label: '编辑', onClick: row => edit(row), perm: PERM.USER.UPDATE, type: 'primary' },
 *     {
 *       label: '删除',
 *       onClick: row => del(row),
 *       perm: PERM.USER.DELETE,
 *       type: 'error',
 *       confirm: row => `确定删除「${row.name}」？`,
 *     },
 *     { label: '禁用', onClick: row => disable(row), show: row => row.enabled, type: 'warning' },
 *   ]);
 *
 *   columns: [
 *     ...
 *     { field: 'action', title: '操作', width: 280, fixed: 'right',
 *       slots: { default: ({ row }) => renderActions(row) } },
 *   ]
 *
 * 自动处理：
 *   - 权限码（perm/perms） + 智能放行（基于 usePerm）
 *   - 显隐回调（show）
 *   - 二次确认（confirm，字符串或函数）
 *   - 排版：自动 NSpace 包裹
 */
import type { PermInput } from '#/composables/usePerm';

import { h, type VNode } from 'vue';

import { NButton, NPopconfirm, NSpace } from 'naive-ui';

import { usePerm } from '#/composables/usePerm';

export type ActionType =
  | 'default'
  | 'error'
  | 'info'
  | 'primary'
  | 'success'
  | 'warning';

export interface ActionItem<T = any> {
  /** 显示文案 */
  label: ((row: T) => string) | string;
  /** 点击事件 */
  onClick?: (row: T, evt?: Event) => void;
  /** 按钮类型 */
  type?: ((row: T) => ActionType) | ActionType;
  /** 单个或多个权限码，任一命中即可显示 */
  perm?: PermInput;
  /** 严格全部权限码均需命中 */
  permAll?: PermInput;
  /** 是否显示，返回 false 则不渲染 */
  show?: (row: T) => boolean;
  /** 是否禁用 */
  disabled?: ((row: T) => boolean) | boolean;
  /** 是否 loading */
  loading?: ((row: T) => boolean) | boolean;
  /** 是否需要二次确认（true 用默认文案；string 用固定文案；function 动态文案） */
  confirm?: ((row: T) => string) | boolean | string;
  /** Naive 按钮额外 props */
  buttonProps?: Record<string, any>;
}

export interface UseActionColumnOptions {
  /** 按钮间距（NSpace 的 size） */
  size?: 'large' | 'medium' | 'small' | [number, number] | number;
  /** 排版方向 */
  justify?:
    | 'center'
    | 'end'
    | 'space-around'
    | 'space-between'
    | 'space-evenly'
    | 'start';
  /** 操作过多时折叠为下拉（暂未实现，预留） */
  maxInline?: number;
}

function valueOf<T, V>(v: ((row: T) => V) | V, row: T): V {
  return typeof v === 'function' ? (v as (row: T) => V)(row) : v;
}

export function useActionColumn<T = any>(
  items: ActionItem<T>[],
  options: UseActionColumnOptions = {},
) {
  const { can, canAll } = usePerm();

  return function renderActions(row: T): VNode {
    const buttons: VNode[] = [];

    for (const item of items) {
      if (item.show && !item.show(row)) continue;
      if (item.permAll && !canAll(item.permAll)) continue;
      if (item.perm && !can(item.perm)) continue;

      const label = valueOf(item.label, row);
      const type = valueOf(item.type, row) ?? 'default';
      const disabled = valueOf(item.disabled, row) ?? false;
      const loading = valueOf(item.loading, row) ?? false;

      const btn = h(
        NButton,
        {
          size: 'small',
          type,
          quaternary: true,
          disabled,
          loading,
          ...(item.buttonProps || {}),
          onClick: (evt: Event) => {
            evt?.stopPropagation?.();
            if (item.confirm) return; // 由 popconfirm 处理
            item.onClick?.(row, evt);
          },
        },
        { default: () => label },
      );

      if (item.confirm) {
        const confirmText =
          typeof item.confirm === 'function'
            ? item.confirm(row)
            : typeof item.confirm === 'string'
              ? item.confirm
              : '确定执行该操作？';
        buttons.push(
          h(
            NPopconfirm,
            {
              onPositiveClick: () => item.onClick?.(row),
            },
            {
              trigger: () => btn,
              default: () => confirmText,
            },
          ),
        );
      } else {
        buttons.push(btn);
      }
    }

    if (buttons.length === 0) {
      return h('span', { class: 'text-gray-400 text-xs' }, '—');
    }

    return h(
      NSpace,
      {
        size: options.size ?? 2,
        justify: options.justify ?? 'center',
        align: 'center',
        wrap: false,
        wrapItem: false,
      } as any,
      () => buttons,
    );
  };
}
