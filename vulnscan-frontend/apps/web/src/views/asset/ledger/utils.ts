import type { TreeOption } from 'naive-ui';

import type { Asset } from '#/api/asset';

import type { LedgerOption } from './types';

export function appendFallbackOption(options: LedgerOption[], fallback: LedgerOption) {
  return options.some((item) => item.value === fallback.value)
    ? options
    : [...options, fallback];
}

export function normalizeOrgTree(nodes: any[] = []): TreeOption[] {
  return nodes
    .map((node) => {
      const key = String(node.id ?? node.key ?? node.value ?? '');
      const label = String(node.name ?? node.label ?? key);
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
