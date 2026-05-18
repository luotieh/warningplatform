import type { TreeOption } from 'naive-ui';

import type { Asset } from '#/api/asset';
import type { Organize } from '#/api/assetmgr';
import { regionCodeFromLabel, regionLabelFromCode } from '#/utils/region';

import type { LedgerOption, LedgerUnitExtra } from './types';

/** 仅存于组织表，不应写入资产 extra 的字段 */
export const UNIT_PROFILE_EXTRA_KEYS = [
  'unit_location_code',
  'unit_address',
  'unit_detail_address',
  'unit_type',
  'industry_category',
  'is_notification_member',
  'unified_social_credit_code',
  'leader_name',
  'leader_title',
  'responsible_department_name',
  'department_leader_name',
  'department_leader_title',
  'department_leader_phone',
  'contact_name',
  'contact_title',
  'contact_phone',
  'region_code',
] as const;

export function stripUnitProfileFromExtra(extra: Record<string, unknown> = {}): Record<string, unknown> {
  const out = { ...extra };
  for (const key of UNIT_PROFILE_EXTRA_KEYS) {
    delete out[key];
  }
  return out;
}

/** 将组织档案映射为资产登记表单中的单位信息 */
export function mapOrganizeToUnitExtra(org: Organize): LedgerUnitExtra {
  const unit_address = mergeUnitAddress(org.address, org.unit_detail_address);
  const regionHint = String(org.address ?? '').trim();
  const unit_location_code = regionHint ? regionCodeFromLabel(regionHint) : null;

  return {
    unit_type: org.unit_type ?? '',
    industry_category: org.industry_category ?? '',
    is_notification_member: org.is_notification_member ?? false,
    unified_social_credit_code: org.unified_social_credit_code ?? '',
    unit_location_code,
    unit_address,
    leader_name: org.leader_name ?? '',
    leader_title: org.leader_title ?? '',
    responsible_department_name: org.responsible_department_name ?? '',
    department_leader_name: org.department_leader_name ?? '',
    department_leader_title: org.department_leader_title ?? '',
    department_leader_phone: org.department_leader_phone ?? '',
    contact_name: org.contact_name ?? '',
    contact_title: org.contact_title ?? '',
    contact_phone: org.contact_phone ?? '',
  };
}

/** 将登记表单中的单位信息回写为组织档案更新体 */
export function mapUnitExtraToOrganizeUpdate(extra: LedgerUnitExtra): Partial<Organize> {
  const detail = String(extra.unit_address ?? '').trim();
  const regionLabel = regionLabelFromCode(extra.unit_location_code ?? null).trim();
  let address = detail;
  if (regionLabel && detail) {
    address = detail.includes(regionLabel) ? detail : `${regionLabel} ${detail}`;
  } else if (regionLabel) {
    address = regionLabel;
  }

  return {
    unit_type: extra.unit_type ?? '',
    industry_category: extra.industry_category ?? '',
    is_notification_member: extra.is_notification_member ?? false,
    unified_social_credit_code: extra.unified_social_credit_code ?? '',
    address,
    unit_detail_address: '',
    leader_name: extra.leader_name ?? '',
    leader_title: extra.leader_title ?? '',
    responsible_department_name: extra.responsible_department_name ?? '',
    department_leader_name: extra.department_leader_name ?? '',
    department_leader_title: extra.department_leader_title ?? '',
    department_leader_phone: extra.department_leader_phone ?? '',
    contact_name: extra.contact_name ?? '',
    contact_title: extra.contact_title ?? '',
    contact_phone: extra.contact_phone ?? '',
  };
}

export function mergeUnitAddress(primary?: string, secondary?: string): string {
  const a = String(primary ?? '').trim();
  const b = String(secondary ?? '').trim();
  if (!a) return b;
  if (!b || a === b) return a;
  if (a.includes(b) || b.includes(a)) return a.length >= b.length ? a : b;
  return `${a} ${b}`;
}

export function appendFallbackOption(options: LedgerOption[], fallback: LedgerOption) {
  return options.some((item) => item.value === fallback.value)
    ? options
    : [...options, fallback];
}

function orgNodeKey(node: any): string {
  return String(node.id ?? node.organize_id ?? node.key ?? node.value ?? '');
}

function orgNodeLabel(node: any, key: string): string {
  return String(node.name ?? node.organize_name ?? node.label ?? key);
}

function orgNodeParentId(node: any): string {
  return String(node.parent_id ?? node.parentId ?? node.parentID ?? '').trim();
}

/** 将扁平组织列表（含 parent_id）组装为 Naive UI 树选项 */
export function buildOrgTreeFromFlat(nodes: any[] = []): TreeOption[] {
  const nodeMap = new Map<string, TreeOption>();
  const roots: TreeOption[] = [];

  nodes.forEach((item) => {
    const key = orgNodeKey(item);
    if (!key) return;
    nodeMap.set(key, { key, label: orgNodeLabel(item, key), value: key, children: [] });
  });

  nodes.forEach((item) => {
    const key = orgNodeKey(item);
    const node = nodeMap.get(key);
    if (!node) return;
    const parentId = orgNodeParentId(item);
    if (parentId && nodeMap.has(parentId)) {
      const parent = nodeMap.get(parentId)!;
      (parent.children as TreeOption[]).push(node);
    } else {
      roots.push(node);
    }
  });

  const prune = (list: TreeOption[]) => {
    list.forEach((n) => {
      const kids = n.children as TreeOption[] | undefined;
      if (!kids || kids.length === 0) {
        n.children = undefined;
      } else {
        prune(kids);
      }
    });
  };
  prune(roots);
  return roots.filter((n) => n.key && n.label);
}

export function normalizeOrgTree(nodes: any[] = []): TreeOption[] {
  return nodes
    .map((node) => {
      const key = orgNodeKey(node);
      const label = orgNodeLabel(node, key);
      const children = normalizeOrgTree(node.children ?? []);
      return {
        key,
        label,
        value: key,
        children: children.length > 0 ? children : undefined,
      } satisfies TreeOption;
    })
    .filter((node) => node.key && node.label);
}

/** 将嵌套组织树展平为带 parent_id 的列表（供单位管理表格等使用） */
export function flattenOrganizeList(nodes: any[] = []): any[] {
  const result: any[] = [];
  const walk = (list: any[]) => {
    list.forEach((node) => {
      const children = node.children;
      const { children: _c, ...item } = node;
      result.push(item);
      if (Array.isArray(children) && children.length) {
        walk(children);
      }
    });
  };
  walk(nodes);
  return result;
}

/** 兼容接口返回的树形或扁平组织数据 */
export function buildOrgTreeOptions(nodes: any[] = []): TreeOption[] {
  if (!nodes.length) return [];
  const hasNestedChildren = nodes.some(
    (n) => Array.isArray(n.children) && n.children.length > 0,
  );
  if (hasNestedChildren) {
    return normalizeOrgTree(nodes);
  }
  return buildOrgTreeFromFlat(nodes);
}

export function flattenOrgTree(nodes: TreeOption[], map: Record<string, string> = {}) {
  nodes.forEach((node) => {
    const key = String(node.key ?? node.value ?? '');
    const label = String(node.label ?? key);
    if (key) {
      map[key] = label;
    }
    flattenOrgTree((node.children as TreeOption[] | undefined) ?? [], map);
  });
  return map;
}

export function assetIdentifier(row: Partial<Asset>) {
  return row.address || row.domain || row.ipv4 || row.ipv6 || '-';
}

export function optionLabelOf(options: LedgerOption[], value?: string) {
  if (!value) return '-';
  return options.find((item) => item.value === value)?.label ?? value;
}
