/**
 * 通用单元格渲染器集合
 *
 * 用于 vxe-table / 表格场景下重复使用的列渲染逻辑：
 *   - 状态 Tag（启用/停用）
 *   - 枚举映射 Tag
 *   - 时间戳/日期时间格式化
 *   - 布尔值
 *   - 空值占位
 *   - 截断+Tooltip
 *   - 拷贝单元格
 *   - 链接/操作按钮
 *   - 头像 + 主副标题
 *   - 状态点
 *
 * 全部以 () => VNode 形式返回，方便直接在 vxe column.slots.default 中使用。
 */
import { h, type VNode } from 'vue';

import { NAvatar, NButton, NTag, NTooltip } from 'naive-ui';

import { message } from '#/adapter/naive';

// =============== 时间格式 ===============

const PLACEHOLDER = '—';

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/** 解析后端可能返回的多种时间值：unix秒、unix毫秒、ISO 字符串、已格式化字符串 */
function parseTime(input: unknown): Date | null {
  if (input === null || input === undefined || input === '') return null;
  if (input instanceof Date) return input;
  if (typeof input === 'number') {
    // 10 位 -> 秒，13 位 -> 毫秒
    const ms = input < 1e12 ? input * 1000 : input;
    const d = new Date(ms);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  if (typeof input === 'string') {
    // 数字字符串
    if (/^\d+$/.test(input)) return parseTime(Number(input));
    // 已经是格式化字符串
    const d = new Date(input);
    if (!Number.isNaN(d.getTime())) return d;
  }
  return null;
}

/** 将 0001-01-01 之类的 zero time 视为空 */
function isZeroTime(d: Date): boolean {
  return d.getUTCFullYear() < 1970;
}

export function formatDateTime(input: unknown, fallback = PLACEHOLDER): string {
  const d = parseTime(input);
  if (!d || isZeroTime(d)) return fallback;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
    d.getHours(),
  )}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function formatDate(input: unknown, fallback = PLACEHOLDER): string {
  const d = parseTime(input);
  if (!d || isZeroTime(d)) return fallback;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** 相对时间 */
export function formatRelative(input: unknown, fallback = PLACEHOLDER): string {
  const d = parseTime(input);
  if (!d || isZeroTime(d)) return fallback;
  const diff = Date.now() - d.getTime();
  if (diff < 0) return formatDateTime(d);
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec} 秒前`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min} 分钟前`;
  const hour = Math.floor(min / 60);
  if (hour < 24) return `${hour} 小时前`;
  const day = Math.floor(hour / 24);
  if (day < 30) return `${day} 天前`;
  return formatDate(d);
}

// =============== Tag/状态 ===============

export type TagType =
  | 'default'
  | 'error'
  | 'info'
  | 'primary'
  | 'success'
  | 'warning';

export interface StatusOption {
  value: any;
  label: string;
  type?: TagType;
}

export function renderStatus(value: any, options: StatusOption[]): VNode {
  const opt =
    options.find((o) => o.value === value) ??
    options.find((o) => String(o.value) === String(value));
  if (!opt) {
    return h('span', { class: 'text-gray-400 text-xs' }, String(value ?? PLACEHOLDER));
  }
  return h(
    NTag,
    {
      type: opt.type ?? 'default',
      size: 'small',
      round: true,
      bordered: false,
    },
    { default: () => opt.label },
  );
}

/**
 * 通用枚举渲染：基于 key->{label,type} 映射
 *
 *   const USER_STATUS = {
 *     normal:   { label: '正常', type: 'success' },
 *     disabled: { label: '停用', type: 'error' },
 *   };
 *   renderEnum(row.status, USER_STATUS);
 */
export interface EnumMeta {
  label: string;
  type?: TagType;
}

export type EnumMap = Record<number | string, EnumMeta | string>;

export function renderEnum(
  value: any,
  enums: EnumMap,
  fallback: string = PLACEHOLDER,
): VNode {
  const raw = enums[value as any] ?? enums[String(value) as any];
  if (raw === undefined || raw === null) {
    if (value === undefined || value === null || value === '') {
      return h('span', { class: 'text-gray-400' }, fallback);
    }
    return h('span', { class: 'text-gray-400 text-xs' }, String(value));
  }
  const meta: EnumMeta = typeof raw === 'string' ? { label: raw } : raw;
  return h(
    NTag,
    {
      type: meta.type ?? 'default',
      size: 'small',
      round: true,
      bordered: false,
    },
    { default: () => meta.label },
  );
}

/** 把枚举映射转为 NSelect/AdvancedFilter 用的 options */
export function enumToOptions(enums: EnumMap): Array<{ label: string; value: any }> {
  return Object.entries(enums).map(([k, v]) => ({
    label: typeof v === 'string' ? v : v.label,
    value: /^\d+$/.test(k) ? Number(k) : k,
  }));
}

/** 通用启用/停用状态 */
export function renderEnabled(
  enabled: any,
  labels: { on?: string; off?: string } = {},
): VNode {
  const onLabel = labels.on ?? '启用';
  const offLabel = labels.off ?? '停用';
  const truthy =
    enabled === true || enabled === 1 || enabled === '1' || enabled === 'normal';
  return renderStatus(truthy ? 1 : 0, [
    { value: 1, label: onLabel, type: 'success' },
    { value: 0, label: offLabel, type: 'error' },
  ]);
}

/** 单纯渲染布尔值 */
export function renderBoolean(
  v: any,
  labels: { yes?: string; no?: string } = {},
): VNode {
  const yes = labels.yes ?? '是';
  const no = labels.no ?? '否';
  return renderStatus(Boolean(v) ? 1 : 0, [
    { value: 1, label: yes, type: 'info' },
    { value: 0, label: no, type: 'default' },
  ]);
}

// =============== 文本 ===============

/** 空值占位 */
export function renderText(v: any, fallback = PLACEHOLDER): VNode | string {
  if (v === null || v === undefined || v === '') {
    return h('span', { class: 'text-gray-400' }, fallback);
  }
  return String(v);
}

/** 截断 + Tooltip 全文 */
export function renderEllipsis(v: any, max = 32): VNode {
  if (v === null || v === undefined || v === '') {
    return h('span', { class: 'text-gray-400' }, PLACEHOLDER);
  }
  const text = String(v);
  if (text.length <= max) return h('span', null, text);
  return h(NTooltip, null, {
    trigger: () =>
      h(
        'span',
        { class: 'truncate inline-block max-w-full align-bottom' },
        `${text.slice(0, max)}…`,
      ),
    default: () => text,
  });
}

/** 副标题/双行文本 */
export function renderTwoLine(primary: any, secondary?: any): VNode {
  return h('div', { class: 'flex flex-col leading-tight min-w-0' }, [
    h(
      'span',
      { class: 'text-sm truncate' },
      primary === null || primary === undefined || primary === ''
        ? PLACEHOLDER
        : String(primary),
    ),
    secondary
      ? h('span', { class: 'text-xs text-gray-500 truncate' }, String(secondary))
      : null,
  ]);
}

/** 时间单元格（主+相对副） */
export function renderTimeCell(input: unknown): VNode {
  const d = parseTime(input);
  if (!d || isZeroTime(d)) {
    return h('span', { class: 'text-gray-400' }, PLACEHOLDER);
  }
  return h(NTooltip, null, {
    trigger: () =>
      h(
        'div',
        { class: 'flex flex-col leading-tight' },
        [
          h('span', { class: 'text-sm truncate' }, formatDateTime(d)),
          h('span', { class: 'text-xs text-gray-500' }, formatRelative(d)),
        ],
      ),
    default: () => formatDateTime(d),
  });
}

// =============== 拷贝 ===============

export function renderCopyText(v: any): VNode {
  if (v === null || v === undefined || v === '') {
    return h('span', { class: 'text-gray-400' }, PLACEHOLDER);
  }
  const text = String(v);
  return h(
    'span',
    {
      class: 'cursor-pointer hover:text-primary',
      title: '点击复制',
      onClick: async (e: Event) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(text);
          message.success('已复制');
        } catch {
          message.warning('复制失败');
        }
      },
    },
    text,
  );
}

// =============== 链接 ===============

export interface LinkOption {
  label: string;
  href?: string;
  onClick?: (e: Event) => void;
  type?: TagType;
}

export function renderLink(opt: LinkOption): VNode {
  return h(
    NButton,
    {
      text: true,
      type: opt.type ?? 'primary',
      size: 'small',
      tag: opt.href ? 'a' : 'button',
      href: opt.href,
      target: opt.href ? '_blank' : undefined,
      onClick: opt.onClick,
    },
    { default: () => opt.label },
  );
}

// =============== 数字 ===============

/** 数字千分位 */
export function renderNumber(v: any, fallback = PLACEHOLDER): VNode {
  if (v === null || v === undefined || v === '') {
    return h('span', { class: 'text-gray-400' }, fallback);
  }
  const n = Number(v);
  if (Number.isNaN(n)) return h('span', null, String(v));
  return h('span', { class: 'tabular-nums' }, n.toLocaleString());
}

// =============== 头像 + 主副标题 ===============

export interface UserCellInput {
  /** 主标题（昵称等） */
  title?: string;
  /** 副标题（账号、邮箱等） */
  subtitle?: string;
  /** 头像 url */
  avatar?: string;
  /** 头像点击事件 */
  onClick?: (e: Event) => void;
}

/** 头像 + 主副标题 */
export function renderUserCell(input: UserCellInput): VNode {
  const title = input.title || PLACEHOLDER;
  const fallback = (input.title || input.subtitle || '?').slice(0, 1).toUpperCase();
  return h(
    'div',
    {
      class: 'flex items-center gap-3 min-w-0',
      onClick: input.onClick,
    },
    [
      h(
        NAvatar,
        {
          size: 36,
          round: true,
          src: input.avatar || undefined,
          style:
            'background:linear-gradient(135deg,#5b8cff,#7d4dff);color:#fff;font-weight:600;flex-shrink:0;',
        },
        { default: () => (input.avatar ? '' : fallback) },
      ),
      h('div', { class: 'flex flex-col leading-tight min-w-0' }, [
        h('span', { class: 'font-medium text-sm truncate' }, title),
        input.subtitle
          ? h('span', { class: 'text-xs text-gray-500 truncate' }, input.subtitle)
          : null,
      ]),
    ],
  );
}

// =============== 状态点 ===============

/** 圆点 + 文字（适合简单状态展示） */
export function renderDot(
  value: any,
  enums: EnumMap,
  fallback = PLACEHOLDER,
): VNode {
  const raw = enums[value as any] ?? enums[String(value) as any];
  if (raw === undefined || raw === null) {
    return h('span', { class: 'text-gray-400' }, fallback);
  }
  const meta: EnumMeta = typeof raw === 'string' ? { label: raw } : raw;
  const colorMap: Record<string, string> = {
    default: '#909399',
    error: '#f56c6c',
    info: '#3b82f6',
    primary: '#5b8cff',
    success: '#10b981',
    warning: '#f59e0b',
  };
  const color = colorMap[meta.type ?? 'default'] ?? '#909399';
  return h(
    'span',
    { class: 'inline-flex items-center gap-1.5' },
    [
      h('span', {
        style: `width:6px;height:6px;border-radius:50%;background:${color};display:inline-block;`,
      }),
      h('span', null, meta.label),
    ],
  );
}

// =============== JSON / 代码块 ===============

/** 简单 JSON 缩略展示，点击复制 */
export function renderJSON(v: any): VNode {
  if (v === null || v === undefined || v === '') {
    return h('span', { class: 'text-gray-400' }, PLACEHOLDER);
  }
  let text: string;
  try {
    text = typeof v === 'string' ? v : JSON.stringify(v);
  } catch {
    text = String(v);
  }
  return h(NTooltip, null, {
    trigger: () =>
      h(
        'code',
        {
          class:
            'cursor-pointer rounded px-1 py-0.5 text-xs bg-gray-100 dark:bg-gray-800 truncate inline-block max-w-full align-bottom',
          onClick: async (e: Event) => {
            e.stopPropagation();
            try {
              await navigator.clipboard.writeText(text);
              message.success('已复制');
            } catch {
              message.warning('复制失败');
            }
          },
        },
        text.length > 60 ? `${text.slice(0, 60)}…` : text,
      ),
    default: () =>
      h('pre', { class: 'text-xs whitespace-pre-wrap max-w-md' }, text),
  });
}
