import type { Asset } from '#/api/asset';
import type { ScanTemplate } from '#/api/template';

import { assetIdentifier } from './utils';

export function assetTarget(row: Asset) {
  if (row.address) return row.address;
  if (row.domain) return row.port ? `${row.domain}:${row.port}` : row.domain;
  if (row.ipv4) return row.port ? `${row.ipv4}:${row.port}` : row.ipv4;
  if (row.ipv6) return row.port ? `[${row.ipv6}]:${row.port}` : row.ipv6;
  return '';
}

export function buildScanTaskName(rows: Asset[]) {
  const first = rows[0];
  if (rows.length === 1 && first) {
    return `资产扫描-${first.name || assetIdentifier(first)}`;
  }
  return `批量扫描-${rows.length}项资产`;
}

export function resolveScanTemplate(rows: Asset[], templates: ScanTemplate[]) {
  const hasWebAsset = rows.some((item) =>
    ['domain_site', 'business_system', 'app', 'mini_program', 'official_account', 'public_mailbox']
      .includes(item.asset_family || ''),
  );
  if (hasWebAsset) {
    return templates.some((item) => item.id === 'web-full') ? 'web-full' : templates[0]?.id ?? '';
  }
  return templates.some((item) => item.id === 'full') ? 'full' : templates[0]?.id ?? '';
}
