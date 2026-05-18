import dayjs from 'dayjs';

import type { CircularItem } from '#/api/circular';

/** 列表/详情统一时间展示 */
export function formatCircularTime(raw?: string | null): string {
  if (!raw) return '-';
  const d = dayjs(raw);
  return d.isValid() ? d.format('YYYY-MM-DD HH:mm:ss') : String(raw);
}

const UNIT_FIELD_TITLES = ['隶属单位', '所属单位', '责任单位', '单位'];

/** 从通报表单数据中提取资产隶属单位名称或 ID */
export function extractCircularUnitHint(
  item?: Pick<CircularItem, 'circular_data' | 'disposal_organize'> | null,
): string {
  if (!item) return '';
  if (item.disposal_organize?.trim()) {
    return item.disposal_organize.trim();
  }
  const rows = item.circular_data;
  if (!Array.isArray(rows)) return '';
  for (const title of UNIT_FIELD_TITLES) {
    const row = rows.find((r: Record<string, unknown>) => {
      const t = String(r?.title ?? r?.field ?? r?.name ?? '');
      return t === title;
    });
    const value = row?.value;
    if (value != null && String(value).trim()) {
      return String(value).trim();
    }
  }
  const fuzzy = rows.find((r: Record<string, unknown>) => {
    const t = String(r?.title ?? r?.field ?? '');
    return t.includes('单位') && !t.includes('类型');
  });
  const fuzzyVal = fuzzy?.value;
  if (fuzzyVal != null && String(fuzzyVal).trim()) {
    return String(fuzzyVal).trim();
  }
  return '';
}

export function circularDataToFormMap(rows: unknown): Record<string, unknown> {
  if (!Array.isArray(rows)) return {};
  return rows.reduce((acc: Record<string, unknown>, item: Record<string, unknown>) => {
    const field = item?.field ?? item?.name ?? item?.key ?? item?.title;
    if (field) acc[String(field)] = item?.value;
    return acc;
  }, {});
}

/** 将单位名称/ID 解析为组织树节点 ID */
export function resolveOrganizeIdByHint(
  hint: string,
  labelToId: Record<string, string>,
  knownIds: Set<string>,
): string | null {
  const text = hint.trim();
  if (!text) return null;
  if (knownIds.has(text)) return text;
  if (labelToId[text]) return labelToId[text];
  const lower = text.toLowerCase();
  for (const [label, id] of Object.entries(labelToId)) {
    if (label === text || label.toLowerCase() === lower) return id;
  }
  for (const [label, id] of Object.entries(labelToId)) {
    if (label.includes(text) || text.includes(label)) return id;
  }
  return null;
}

export function buildLabelToIdMap(idToLabel: Record<string, string>): Record<string, string> {
  const map: Record<string, string> = {};
  Object.entries(idToLabel).forEach(([id, label]) => {
    if (label) map[label] = id;
  });
  return map;
}

/** 详情页摘要字段（优先展示） */
export const CIRCULAR_SUMMARY_FIELDS = [
  '隐患编号',
  '隐患名称',
  '隐患类型',
  '隐患URL',
  'CVE编号',
  'CVSS评分',
  '资产名称',
  '系统名称',
  '网站域名IP',
  '隶属单位',
] as const;

export function pickCircularSummary(formData: Record<string, unknown>) {
  return CIRCULAR_SUMMARY_FIELDS.filter((key) => {
    const v = formData[key];
    return v != null && String(v).trim() !== '';
  }).map((key) => ({ key, value: formData[key] }));
}
