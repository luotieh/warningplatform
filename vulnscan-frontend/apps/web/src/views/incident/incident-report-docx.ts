import type { IncidentReportData } from '#/api/incident';

import {
  AlignmentType,
  BorderStyle,
  Document,
  HeadingLevel,
  ImageRun,
  Packer,
  Paragraph,
  Table,
  TableCell,
  TableRow,
  TextRun,
  VerticalAlign,
  WidthType,
} from 'docx';

const LABEL_W = 1600;
const BORDER = {
  style: BorderStyle.SINGLE,
  size: 1,
  color: '333333',
};
const CELL_BORDERS = {
  top: BORDER,
  bottom: BORDER,
  left: BORDER,
  right: BORDER,
};
const LABEL_SHADING = { fill: 'FAFAFA' };

function d(v?: string): string {
  return v?.trim() || '-';
}

function labelCell(text: string, colSpan = 1): TableCell {
  return new TableCell({
    width: { size: LABEL_W, type: WidthType.DXA },
    borders: CELL_BORDERS,
    shading: LABEL_SHADING,
    verticalAlign: VerticalAlign.CENTER,
    columnSpan: colSpan,
    children: [
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text, bold: true, size: 20, font: 'Microsoft YaHei' })],
      }),
    ],
  });
}

function valueCell(text: string, colSpan = 1): TableCell {
  const lines = text.split('\n');
  return new TableCell({
    borders: CELL_BORDERS,
    verticalAlign: VerticalAlign.TOP,
    columnSpan: colSpan,
    children: lines.map(
      (line) =>
        new Paragraph({
          children: [new TextRun({ text: line, size: 20, font: 'Microsoft YaHei' })],
        }),
    ),
  });
}

function metaRow4(k1: string, v1: string, k2: string, v2: string): TableRow {
  return new TableRow({
    children: [labelCell(k1), valueCell(v1), labelCell(k2), valueCell(v2)],
  });
}

function metaRowSpan(k: string, v: string): TableRow {
  return new TableRow({
    children: [labelCell(k), valueCell(v, 3)],
  });
}

function formatEvidenceKVLines(text: string): Paragraph[] {
  const paras: Paragraph[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) {
      paras.push(new Paragraph({ children: [] }));
      continue;
    }
    const sectionMatch = trimmed.match(/^(.+?)：$/);
    if (sectionMatch && !trimmed.includes('  ')) {
      paras.push(new Paragraph({
        spacing: { before: 100 },
        children: [new TextRun({ text: `▌ ${sectionMatch[1]}`, bold: true, size: 20, font: 'Microsoft YaHei', color: '2080F0' })],
      }));
      continue;
    }
    const kvMatch = trimmed.match(/^\s*(.+?)[:：]\s*(.+)$/);
    if (kvMatch) {
      paras.push(new Paragraph({
        indent: { left: 200 },
        children: [
          new TextRun({ text: `${kvMatch[1]}：`, bold: true, size: 18, font: 'Microsoft YaHei', color: '666666' }),
          new TextRun({ text: kvMatch[2]!, size: 18, font: 'Microsoft YaHei' }),
        ],
      }));
      continue;
    }
    paras.push(new Paragraph({
      indent: { left: 200 },
      children: [new TextRun({ text: trimmed, size: 18, font: 'Microsoft YaHei' })],
    }));
  }
  return paras;
}

function buildDescriptionParagraphs(r: IncidentReportData): Paragraph[] {
  const paras: Paragraph[] = [];
  const sec = r.description_sections;
  if (sec?.has_sections) {
    const parts: [string, string | undefined, boolean][] = [
      ['一、事件成因', sec.cause, false],
      ['二、证据详情', sec.evidence, false],
      ['三、详细证据', sec.detail, true],
      ['四、溯源信息', sec.trace, false],
    ];
    for (const [title, body, isDetail] of parts) {
      if (!body?.trim()) continue;
      paras.push(
        new Paragraph({
          children: [new TextRun({ text: title, bold: true, size: 20, font: 'Microsoft YaHei' })],
        }),
      );
      if (isDetail) {
        paras.push(...formatEvidenceKVLines(body));
      } else {
        for (const line of body.split('\n')) {
          paras.push(
            new Paragraph({
              children: [new TextRun({ text: line, size: 20, font: 'Microsoft YaHei' })],
            }),
          );
        }
      }
      paras.push(new Paragraph({ children: [] }));
    }
  } else if (r.description?.trim()) {
    for (const line of r.description.split('\n')) {
      paras.push(
        new Paragraph({
          children: [new TextRun({ text: line, size: 20, font: 'Microsoft YaHei' })],
        }),
      );
    }
  }

  if (r.evidence_images?.length) {
    for (const img of r.evidence_images) {
      if (!img.base64?.trim()) continue;
      if (img.caption?.trim()) {
        paras.push(
          new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [new TextRun({ text: img.caption, size: 18, font: 'Microsoft YaHei' })],
          }),
        );
      }
      try {
        const raw = Uint8Array.from(atob(img.base64), (c) => c.charCodeAt(0));
        paras.push(
          new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new ImageRun({
                data: raw,
                transformation: { width: 500, height: 280 },
                type: 'png',
              }),
            ],
          }),
        );
      } catch {
        // skip malformed image
      }
      paras.push(new Paragraph({ children: [] }));
    }
  }

  if (paras.length === 0) {
    paras.push(new Paragraph({ children: [new TextRun({ text: '-', size: 20, font: 'Microsoft YaHei' })] }));
  }
  return paras;
}

function buildRemediationParagraphs(r: IncidentReportData): Paragraph[] {
  const paras: Paragraph[] = [];
  const texts: string[] = [];
  if (r.remediation_plan?.trim()) texts.push(r.remediation_plan);
  if (r.remediation_advice?.trim() && r.remediation_advice !== r.remediation_plan) {
    texts.push(r.remediation_advice);
  }
  for (const t of texts) {
    for (const line of t.split('\n')) {
      paras.push(
        new Paragraph({
          children: [new TextRun({ text: line, size: 20, font: 'Microsoft YaHei' })],
        }),
      );
    }
  }
  if (paras.length === 0) {
    paras.push(new Paragraph({ children: [new TextRun({ text: '-', size: 20, font: 'Microsoft YaHei' })] }));
  }
  return paras;
}

export async function generateIncidentDocx(r: IncidentReportData): Promise<Blob> {
  const rows: TableRow[] = [
    metaRow4('隐患编号', d(r.incident_no), '数据编号', d(r.data_no)),
    metaRowSpan('隐患名称', d(r.name || r.title)),
    metaRowSpan('厂商上报归属地', d(r.vendor_region)),
    metaRowSpan('隐患URL', d(r.incident_url)),
    metaRow4('网站名称', d(r.asset_name), '网站域名IP', d(r.domain_ip)),
    metaRow4('网站IP', d(r.site_ip), '归属地', d(r.region)),
    metaRow4('隐患类型', d(r.incident_type), '预警级别', d(r.warning_level)),
    metaRow4('隐患级别', d(r.level), '发现时间', d(r.discovery_time)),
    metaRow4('上报厂商', d(r.vendor_name), '厂商上报时间', d(r.vendor_time)),
    metaRow4('涉及信息数量', d(r.affected_count), '涉及信息类型', d(r.affected_type)),
    metaRow4('隶属单位', d(r.unit), '单位类型', d(r.unit_type)),
    metaRow4('所属行业', d(r.industry), '工信部备案号', d(r.miit_record_no)),
    metaRow4('等保级别', d(r.mlps_level), '等保备案号', d(r.mlps_record_no)),
  ];

  rows.push(
    new TableRow({
      children: [
        labelCell('隐患描述'),
        new TableCell({
          borders: CELL_BORDERS,
          columnSpan: 3,
          children: buildDescriptionParagraphs(r),
        }),
      ],
    }),
  );

  if (r.remediation_plan?.trim() || r.remediation_advice?.trim()) {
    rows.push(
      new TableRow({
        children: [
          labelCell('整改建议'),
          new TableCell({
            borders: CELL_BORDERS,
            columnSpan: 3,
            children: buildRemediationParagraphs(r),
          }),
        ],
      }),
    );
  }

  if (r.attachment?.trim()) {
    rows.push(metaRowSpan('证据附件', d(r.attachment)));
  }

  const table = new Table({
    rows,
    width: { size: 100, type: WidthType.PERCENTAGE },
    columnWidths: [LABEL_W, 3200, LABEL_W, 3200],
  });

  const doc = new Document({
    sections: [
      {
        properties: {
          page: {
            margin: { top: 720, bottom: 720, left: 720, right: 720 },
          },
        },
        children: [
          new Paragraph({
            heading: HeadingLevel.HEADING_1,
            alignment: AlignmentType.CENTER,
            spacing: { after: 200 },
            children: [
              new TextRun({
                text: '网络安全隐患详情',
                bold: true,
                size: 32,
                font: 'Microsoft YaHei',
              }),
            ],
          }),
          table,
        ],
      },
    ],
  });

  return Packer.toBlob(doc);
}
