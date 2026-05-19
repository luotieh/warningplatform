import type {
  ImportFailedRowPayload,
  ImportIssuePayload,
} from '#/api/helpers';

export interface ImportRowErrorGroup {
  row: number;
  name: string;
  organizeName: string;
  address: string;
  assetFamily: string;
  isOnline: string;
  issues: ImportIssuePayload[];
  summary: string;
}

/** 将行级错误按 Excel 行号聚合，便于表格展示。 */
export function groupImportIssuesByRow(
  issues: ImportIssuePayload[],
): ImportRowErrorGroup[] {
  const map = new Map<number, ImportIssuePayload[]>();
  for (const issue of issues) {
    const row = Number(issue.row);
    if (!Number.isFinite(row) || row < 1) continue;
    const list = map.get(row) ?? [];
    list.push(issue);
    map.set(row, list);
  }
  return [...map.entries()]
    .sort(([a], [b]) => a - b)
    .map(([row, rowIssues]) => ({
      row,
      name: '',
      organizeName: '',
      address: '',
      assetFamily: '',
      isOnline: '',
      issues: rowIssues,
      summary: rowIssues
        .map((item) => {
          const field = item.field?.trim();
          return field ? `【${field}】${item.message}` : item.message;
        })
        .join('；'),
    }));
}

export function buildImportErrorTableRows(
  failedRows: ImportFailedRowPayload[],
  issues: ImportIssuePayload[],
): ImportRowErrorGroup[] {
  if (failedRows.length > 0) {
    return failedRows.map((row) => ({
      row: row.row,
      name: row.name?.trim() ?? '',
      organizeName: row.organize_name?.trim() ?? '',
      address: row.address?.trim() ?? '',
      assetFamily: row.asset_family?.trim() ?? '',
      isOnline: row.is_online?.trim() ?? '',
      issues: row.issues ?? [],
      summary: row.error_summary?.trim() ?? '',
    }));
  }
  return groupImportIssuesByRow(issues);
}

export function importErrorSummary(
  errorCount: number,
  rowCount: number,
): string {
  if (errorCount <= 0) {
    return '导入失败，请检查文件内容后重试';
  }
  if (rowCount > 0) {
    return `导入校验未通过：共 ${errorCount} 处问题，涉及 ${rowCount} 行（下表为问题行，请对照 Excel 修改后重试）`;
  }
  return `导入校验未通过：共 ${errorCount} 处问题`;
}
