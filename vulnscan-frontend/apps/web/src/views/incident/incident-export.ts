import { downloadBlob } from '#/views/asset/ledger/file-utils';

import { downloadIncidentDetailReport, exportBatch } from '#/api/incident';

export type IncidentExportFormat = 'word' | 'docx' | 'pdf';

export function incidentExportExtension(format: IncidentExportFormat): string {
  switch (format) {
    case 'word':
    case 'docx':
      return 'docx';
    case 'pdf':
      return 'pdf';
    default:
      return 'pdf';
  }
}

export function incidentExportFilename(
  incidentNo: string | undefined,
  id: string,
  format: IncidentExportFormat,
  batch = false,
): string {
  if (batch && (format === 'word' || format === 'pdf' || format === 'docx')) {
    return `incidents_${format}_${Date.now()}.zip`;
  }
  const base = incidentNo?.trim() || id;
  return `${base}.${incidentExportExtension(format)}`;
}

/** 单条事件导出（Docx / PDF） */
export async function downloadOneIncidentExport(
  id: string,
  format: IncidentExportFormat,
  incidentNo?: string,
) {
  const blob = await downloadIncidentDetailReport(id, format);
  downloadBlob(blob as Blob, incidentExportFilename(incidentNo, id, format));
}

/** 批量导出；Word/PDF 为 ZIP 包 */
export async function downloadBatchIncidentExport(
  ids: string[],
  format: IncidentExportFormat,
) {
  const res = await exportBatch({ ids, format });
  const blob = (res as any)?.data ?? res;
  downloadBlob(blob as Blob, incidentExportFilename(undefined, 'batch', format, true));
}
