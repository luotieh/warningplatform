import { h, type VNode } from 'vue';

import type { ScanFinding } from '#/api/task';

/** 表格内主标题（可多行换行，避免单行省略堆在一起） */
export function findingCellTitle(text: string, bold = true): VNode {
  const t = text?.trim() || '-';
  return h(
    'div',
    {
      class: 'finding-cell-title',
      title: t,
    },
    t,
  );
}

/** 表格内副文本（最多显示 N 行，悬停看全文） */
export function findingCellSubtext(text: string, maxLines = 3): VNode | null {
  const t = text?.trim();
  if (!t) return null;
  return h(
    'div',
    {
      class: 'finding-cell-sub',
      style: { WebkitLineClamp: maxLines },
      title: t,
    },
    t,
  );
}

/** 标题 + 摘要纵向排列 */
export function findingCellStack(title?: string, subtitle?: string, subLines = 3): VNode {
  return h('div', { class: 'finding-cell-stack' }, [
    title ? findingCellTitle(title) : h('span', { class: 'finding-cell-muted' }, '-'),
    subtitle && subtitle !== title ? findingCellSubtext(subtitle, subLines) : null,
  ]);
}

export function formatFindingDataValue(val: unknown): string {
  if (val === null || val === undefined) return '-';
  if (typeof val === 'object') {
    try {
      return JSON.stringify(val, null, 2);
    } catch {
      return String(val);
    }
  }
  return String(val);
}

/** 从 data 提取简短摘要（不再用 | 拼成一行） */
export function primaryDataHint(row: ScanFinding, pick: (key: string) => string): string {
  const d = row.data ?? {};
  const candidates = [
    pick('url'),
    pick('path'),
    pick('domain'),
    pick('email'),
    pick('value'),
    pick('service') ? `${pick('service')}${pick('version') ? ` ${pick('version')}` : ''}` : '',
    pick('banner') ? pick('banner').split('\n')[0]?.slice(0, 200) : '',
    row.description,
  ].filter(Boolean);
  return candidates[0] ?? '';
}

export function estimateTableScrollX(columns: Array<{ width?: number; minWidth?: number }>): number {
  let total = 48;
  for (const col of columns) {
    total += col.width ?? col.minWidth ?? 120;
  }
  return Math.max(total, 1100);
}
