import type { TreeOption } from 'naive-ui';

import type { Asset } from '#/api/asset';
import type { Organize } from '#/api/assetmgr';
import { regionCodeFromLabel, regionLabelFromCode, regionOptions } from '#/utils/region';

import type { LedgerOption, LedgerScopeDimension, LedgerUnitExtra } from './types';

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
  const unit_location_code = org.region_code || (regionHint ? regionCodeFromLabel(regionHint) : null);

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

  const credit = String(extra.unified_social_credit_code ?? '').trim();
  const payload: Partial<Organize> = {
    unit_type: extra.unit_type ?? '',
    industry_category: extra.industry_category ?? '',
    is_notification_member: extra.is_notification_member ?? false,
    address,
    region_code: extra.unit_location_code || '',
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
  if (credit) {
    payload.unified_social_credit_code = credit;
  }
  return payload;
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

function orgNodeAssetCount(node: any): number {
  return Number(node.asset_count ?? 0);
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
    const opt: TreeOption & { assetCount?: number } = { key, label: orgNodeLabel(item, key), value: key, children: [] };
    const count = orgNodeAssetCount(item);
    if (count > 0) opt.assetCount = count;
    nodeMap.set(key, opt);
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
      const count = orgNodeAssetCount(node);
      const opt: TreeOption & { assetCount?: number } = {
        key,
        label,
        value: key,
        children: children.length > 0 ? children : undefined,
      };
      if (count > 0) opt.assetCount = count;
      return opt;
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

export function flattenOrgTree(
  nodes: TreeOption[],
  map: Record<string, string> = {},
  parentMap: Record<string, string> = {},
  parentKey = '',
) {
  nodes.forEach((node) => {
    const key = String(node.key ?? node.value ?? '');
    const label = String(node.label ?? key);
    if (key) {
      map[key] = label;
      if (parentKey) {
        parentMap[key] = parentKey;
      }
    }
    flattenOrgTree(
      (node.children as TreeOption[] | undefined) ?? [],
      map,
      parentMap,
      key,
    );
  });
  return map;
}

/** 根据 parent 链拼接单位路径标签 */
export function buildOrganizePathLabel(
  id: string,
  nameMap: Record<string, string>,
  parentMap: Record<string, string>,
): string {
  const parts: string[] = [];
  const visited = new Set<string>();
  let current: string | undefined = id;
  while (current && !visited.has(current)) {
    visited.add(current);
    parts.unshift(nameMap[current] ?? current);
    current = parentMap[current];
  }
  return parts.filter(Boolean).join(' / ');
}

/** 组织搜索：仅展示命中项（扁平列表，label 含上级路径） */
/** 省市区 code → 列表查询参数（区精确，市/省用前缀） */
export function regionAssetQueryFromCode(code: string | null | undefined): {
  region_code?: string;
  region_prefix?: string;
} {
  const raw = String(code ?? '').trim();
  if (!raw) return {};
  if (raw.endsWith('0000')) {
    return { region_prefix: raw.slice(0, 2) };
  }
  if (raw.endsWith('00')) {
    return { region_prefix: raw.slice(0, 4) };
  }
  return { region_code: raw };
}

export function regionScopeLabelFromCode(code: string | null | undefined): string {
  const raw = String(code ?? '').trim();
  if (!raw) return '';
  return regionLabelFromCode(raw) || raw;
}

type RegionAreaOption = {
  label: string;
  value: string;
  children?: RegionAreaOption[];
};

export type RegionScopeRow = {
  region_code: string;
  count: number;
};


/** 将区县级 code 展开为省 / 市祖先，便于裁剪完整行政区划树 */
export function expandRegionAncestorCodes(codes: Iterable<string>): Set<string> {
  const set = new Set<string>();
  for (const raw of codes) {
    const code = String(raw ?? '').trim();
    if (code.length < 2) continue;
    set.add(code);
    set.add(`${code.slice(0, 2)}0000`);
    if (!code.endsWith('0000')) {
      set.add(`${code.slice(0, 4)}00`);
    }
  }
  return set;
}

function collectRegionTreeKeys(nodes: TreeOption[], into: Set<string> = new Set()): Set<string> {
  for (const node of nodes) {
    const key = String(node.key ?? node.value ?? '').trim();
    if (key) into.add(key);
    if (node.children?.length) collectRegionTreeKeys(node.children, into);
  }
  return into;
}

type PrunedRegionNode = {
  option: TreeOption;
  total: number;
};

function pruneRegionTreeByCodes(
  nodes: RegionAreaOption[],
  allowed: Set<string>,
  countMap: Map<string, number>,
): PrunedRegionNode[] {
  const result: PrunedRegionNode[] = [];
  for (const node of nodes) {
    if (!allowed.has(node.value)) continue;
    const childResults = node.children?.length
      ? pruneRegionTreeByCodes(node.children, allowed, countMap)
      : [];
    const direct = countMap.get(node.value) ?? 0;
    const childSum = childResults.reduce((sum, child) => sum + child.total, 0);
    const total = direct + childSum;
    if (total <= 0) continue;
    const opt: TreeOption & { assetCount?: number } = {
      key: node.value,
      label: node.label,
      value: node.value,
      children:
        childResults.length > 0 ? childResults.map((child) => child.option) : undefined,
    };
    if (total > 0) opt.assetCount = total;
    result.push({ total, option: opt });
  }
  return result;
}

/** 仅保留资产中已登记的地域，并汇总各级节点资产数 */
export function buildRegionTreeFromAssetCodes(
  items: RegionScopeRow[] = [],
  areas: RegionAreaOption[] = regionOptions,
): TreeOption[] {
  const countMap = new Map<string, number>();
  for (const item of items) {
    const code = String(item.region_code ?? '').trim();
    if (!code) continue;
    countMap.set(code, (countMap.get(code) ?? 0) + Number(item.count ?? 0));
  }
  if (countMap.size === 0) return [];

  const allowed = expandRegionAncestorCodes(countMap.keys());
  const tree = pruneRegionTreeByCodes(areas, allowed, countMap).map((node) => node.option);
  const known = collectRegionTreeKeys(tree);

  const orphans: (TreeOption & { assetCount?: number })[] = [];
  for (const [code, count] of countMap) {
    if (known.has(code)) continue;
    const label = regionLabelFromCode(code) || code;
    const opt: TreeOption & { assetCount?: number } = { key: code, label, value: code };
    if (count > 0) opt.assetCount = count;
    orphans.push(opt);
  }
  orphans.sort((a, b) => String(a.label).localeCompare(String(b.label), 'zh-CN'));
  return orphans.length > 0 ? [...tree, ...orphans] : tree;
}

export function buildRegionTreeOptions(
  areas: RegionAreaOption[] = regionOptions,
): TreeOption[] {
  return areas.map((province) => ({
    key: province.value,
    label: province.label,
    value: province.value,
    children: province.children?.map((city) => ({
      key: city.value,
      label: city.label,
      value: city.value,
      children: city.children?.map((county) => ({
        key: county.value,
        label: county.label,
        value: county.value,
      })),
    })),
  }));
}

export function buildDictTreeOptions(options: LedgerOption[] = []): TreeOption[] {
  return options
    .filter((item) => item.value)
    .map((item) => ({
      key: item.value,
      label: item.label,
      value: item.value,
    }));
}

export function ledgerScopeDimensionLabel(dim: LedgerScopeDimension): string {
  switch (dim) {
    case 'organize':
      return '组织';
    case 'region':
      return '地域';
    case 'industry':
      return '行业';
    case 'unit_type':
      return '单位类型';
    case 'asset_family':
      return '资产分类';
    default:
      return '';
  }
}

export function buildOrganizeSearchTreeOptions(
  items: Array<{ id: string; name?: string }>,
  nameMap: Record<string, string>,
  parentMap: Record<string, string>,
): TreeOption[] {
  const nodes: TreeOption[] = [];
  for (const item of items) {
    const id = String(item.id ?? '').trim();
    if (!id) continue;
    const name = String(item.name ?? nameMap[id] ?? id).trim();
    const path = buildOrganizePathLabel(id, { ...nameMap, [id]: name }, parentMap);
    const label = path && path !== name ? path : name;
    nodes.push({ key: id, label, value: id });
  }
  return nodes;
}

export function assetIdentifier(row: Partial<Asset>) {
  return resolveLedgerFormAddress(row) || '-';
}

/** 编辑表单「访问地址」：与列表地址列展示逻辑一致 */
export function resolveLedgerFormAddress(row: Partial<Asset>) {
  const addr = String(row.address ?? '').trim();
  if (addr) return addr;
  const domain = String(row.domain ?? '').trim();
  if (domain) return domain;
  const ipv4 = String(row.ipv4 ?? '').trim();
  if (ipv4) return ipv4;
  const ipv6 = String(row.ipv6 ?? '').trim();
  if (ipv6) return ipv6;
  return '';
}

const DATA_SOURCE_LABEL_FALLBACK: Record<string, string> = {
  manual: '手工录入',
  scan: '扫描发现',
  import: '批量导入',
  discovery: '自动探测',
  manual_import: '手工录入',
  auto_detect: '自动探测',
  external: '外部同步',
};

export function optionLabelOf(options: LedgerOption[], value?: string) {
  if (!value) return '-';
  return options.find((item) => item.value === value)?.label
    ?? DATA_SOURCE_LABEL_FALLBACK[value]
    ?? value;
}
