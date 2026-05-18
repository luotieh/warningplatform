import type { DataTableColumns } from 'naive-ui';

import { h } from 'vue';
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
      key: 'is_online',
      width: 96,
      align: 'center',
      render: (row) =>
        h(
          NTag,
          { bordered: false, size: 'small', type: row.is_online ? 'success' : 'default' },
          { default: () => (row.is_online ? '在线' : '离线') },
        ),
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
      width: 280,
      fixed: 'right',
      render: (row) =>
        h(NSpace, { size: 8, justify: 'center' }, () => [
          h(
            NButton,
            { size: 'small', quaternary: true, type: 'info', onClick: () => options.onDetail(row) },
            { default: () => '详情' },
          ),
          h(
            NButton,
            { size: 'small', quaternary: true, type: 'primary', onClick: () => options.onScan(row) },
            { default: () => '扫描' },
          ),
          h(
            NButton,
            { size: 'small', quaternary: true, onClick: () => options.onEdit(row) },
            { default: () => '编辑' },
          ),
          h(
            NPopconfirm,
            { onPositiveClick: () => options.onDelete(row.id) },
            {
              trigger: () =>
                h(
                  NButton,
                  { size: 'small', quaternary: true, type: 'error' },
                  { default: () => '删除' },
                ),
              default: () => '确认删除该资产？',
            },
          ),
        ]),
    },
  ];
}
