import type { DataTableColumns } from 'naive-ui';
import type { ButtonProps } from 'naive-ui';

import { h } from 'vue';
import { IconifyIcon } from '@vben/icons';
import { NButton, NPopconfirm, NSpace, NTag } from 'naive-ui';

import type { Asset } from '#/api/asset';

type UseLedgerColumnsOptions = {
  assetFamilyLabel: (value?: string) => string;
  sourceLabel: (value?: string) => string;
  organizeLabel: (value?: string) => string;
  assetIdentifier: (row: Partial<Asset>) => string;
  onDetail: (row: Asset) => void;
  onScan: (row: Asset) => void;
  onEdit: (row: Asset) => void;
  onDelete: (id: string) => Promise<void>;
};

function renderText(value?: number | string) {
  const text = value === undefined || value === null || value === '' ? '-' : String(value);
  return h('span', { class: text === '-' ? 'ledger-cell ledger-cell--muted' : 'ledger-cell' }, text);
}

function rowActionButton(
  label: string,
  icon: string,
  onClick?: () => void,
  options?: { type?: ButtonProps['type']; emphasize?: boolean },
) {
  return h(
    NButton,
    {
      text: true,
      size: 'small',
      type: options?.type ?? 'default',
      class: options?.emphasize ? 'ledger-row-action ledger-row-action--emphasize' : 'ledger-row-action',
      onClick: onClick ?? (() => undefined),
    },
    {
      icon: () => h(IconifyIcon, { icon, class: 'text-sm' }),
      default: () => label,
    },
  );
}

function renderReachableStatus(row: Asset) {
  if (row.is_online === false) {
    return h('span', { class: 'ledger-cell ledger-cell--muted' }, '—');
  }
  if (row.reachable_checked_at == null || row.reachable_checked_at === '') {
    return h('span', { class: 'ledger-cell ledger-cell--muted' }, '检测中');
  }
  const online = row.reachable === true;
  return h(
    NTag,
    { bordered: false, size: 'small', type: online ? 'success' : 'default' },
    { default: () => (online ? '在线' : '离线') },
  );
}

export function useLedgerColumns(options: UseLedgerColumnsOptions): DataTableColumns<Asset> {
  return [
    { type: 'selection', width: 48 },
    {
      title: '资产名称',
      key: 'name',
      minWidth: 180,
      ellipsis: { tooltip: true },
    },
    {
      title: '资产分类',
      key: 'asset_family',
      width: 120,
      render: (row) => renderText(options.assetFamilyLabel(row.asset_family)),
    },
    {
      title: '地址',
      key: 'address',
      minWidth: 220,
      ellipsis: { tooltip: true },
      render: (row) => renderText(options.assetIdentifier(row)),
    },
    {
      title: '所属单位',
      key: 'organize_id',
      minWidth: 180,
      ellipsis: { tooltip: true },
      render: (row) => renderText(options.organizeLabel(row.organize_id)),
    },
    {
      title: '在线状态',
      key: 'reachable',
      width: 96,
      align: 'center',
      render: (row) => renderReachableStatus(row),
    },
    {
      title: '风险分',
      key: 'risk_score',
      width: 90,
      align: 'center',
      render: (row) => renderText(row.risk_score ?? '-'),
    },
    {
      title: '漏洞数',
      key: 'vuln_count',
      width: 90,
      align: 'center',
      render: (row) => renderText(row.vuln_count ?? '-'),
    },
    {
      title: '来源',
      key: 'data_source',
      width: 120,
      render: (row) => renderText(options.sourceLabel(row.data_source)),
    },
    {
      title: '操作',
      key: 'actions',
      width: 248,
      fixed: 'right',
      align: 'center',
      render: (row) =>
        h(
          NSpace,
          { size: 4, justify: 'center', wrap: false, class: 'ledger-row-actions' },
          () => [
            rowActionButton('详情', 'ri:eye-line', () => options.onDetail(row), { type: 'info' }),
            rowActionButton('编辑', 'ri:edit-2-line', () => options.onEdit(row), {
              type: 'primary',
              emphasize: true,
            }),
            rowActionButton('扫描', 'ri:radar-line', () => options.onScan(row)),
            h(
              NPopconfirm,
              { onPositiveClick: () => options.onDelete(row.id) },
              {
                trigger: () =>
                  rowActionButton('删除', 'ri:delete-bin-line', () => undefined, { type: 'error' }),
                default: () => '确认删除该资产？',
              },
            ),
          ],
        ),
    },
  ];
}
