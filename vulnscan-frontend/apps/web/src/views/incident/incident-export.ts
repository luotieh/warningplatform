import { downloadBlob } from '#/views/asset/ledger/file-utils';

import {
  exportBatch,
  previewIncidentReport,
  type IncidentReportData,
} from '#/api/incident';

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

async function renderHtmlOffscreen(html: string): Promise<HTMLElement> {
  const container = document.createElement('div');
  container.style.cssText =
    'position:fixed;left:-9999px;top:0;width:900px;background:#fff;z-index:-1;';
  container.innerHTML = html;
  document.body.appendChild(container);
  await new Promise((r) => setTimeout(r, 200));
  return container;
}

async function exportPdfFromHtml(
  reportData: IncidentReportData,
  filename: string,
) {
  const { buildIncidentReportHtml } = await import('./incident-report-html');
  const html = buildIncidentReportHtml(reportData);
  const container = await renderHtmlOffscreen(html);
  try {
    const html2canvas = (await import('html2canvas-pro')).default;
    const { jsPDF } = await import('jspdf');

    const canvas = await html2canvas(container, {
      scale: 2,
      useCORS: true,
      backgroundColor: '#fff',
    });

    const imgData = canvas.toDataURL('image/png');
    const pdfW = 210;
    const margin = 10;
    const contentW = pdfW - margin * 2;
    const imgH = (canvas.height * contentW) / canvas.width;

    const pdf = new jsPDF({ unit: 'mm', format: 'a4' });
    const pageH = pdf.internal.pageSize.getHeight() - margin * 2;
    let y = 0;

    while (y < imgH) {
      if (y > 0) pdf.addPage();
      pdf.addImage(imgData, 'PNG', margin, margin - y, contentW, imgH);
      y += pageH;
    }

    const blob = pdf.output('blob');
    downloadBlob(blob, filename);
  } finally {
    document.body.removeChild(container);
  }
}

async function exportDocx(
  reportData: IncidentReportData,
  filename: string,
) {
  const { generateIncidentDocx } = await import('./incident-report-docx');
  const blob = await generateIncidentDocx(reportData);
  downloadBlob(blob, filename);
}

/** 单条事件导出（Docx / PDF）—— 前端 HTML 直接生成 */
export async function downloadOneIncidentExport(
  id: string,
  format: IncidentExportFormat,
  incidentNo?: string,
  reportData?: IncidentReportData | null,
) {
  const filename = incidentExportFilename(incidentNo, id, format);

  const data = reportData || (await previewIncidentReport(id));
  if (!data) throw new Error('无法获取报告数据');

  if (format === 'pdf') {
    await exportPdfFromHtml(data, filename);
  } else {
    await exportDocx(data, filename);
  }
}

/** 批量导出——仍使用后端 ZIP 方式 */
export async function downloadBatchIncidentExport(
  ids: string[],
  format: IncidentExportFormat,
) {
  const res = await exportBatch({ ids, format });
  const blob = (res as any)?.data ?? res;
  downloadBlob(
    blob as Blob,
    incidentExportFilename(undefined, 'batch', format, true),
  );
}
