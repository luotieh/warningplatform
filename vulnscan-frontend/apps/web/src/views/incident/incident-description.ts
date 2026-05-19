/** 与后端自动转事件写入的 incident_description 分段标题保持一致。 */
export const INCIDENT_SECTION_CAUSE = '【事件成因】';
export const INCIDENT_SECTION_EVIDENCE = '【证据详情】';
export const INCIDENT_SECTION_DETAIL = '【详细证据】';
export const INCIDENT_SECTION_TRACE = '【溯源信息】';

export interface ParsedIncidentDescription {
  cause: string;
  evidence: string;
  detail: string;
  trace: string;
  raw: string;
  hasSections: boolean;
}

function extractBetween(
  text: string,
  startMark: string,
  endMark?: string,
): string {
  const start = text.indexOf(startMark);
  if (start < 0) return '';
  let body = text.slice(start + startMark.length);
  if (endMark) {
    const end = body.indexOf(endMark);
    if (end >= 0) {
      body = body.slice(0, end);
    }
  }
  return body.trim();
}

export function parseIncidentDescription(text?: string): ParsedIncidentDescription {
  const raw = String(text ?? '').trim();
  if (!raw) {
    return { cause: '', evidence: '', detail: '', trace: '', raw: '', hasSections: false };
  }
  if (!raw.includes(INCIDENT_SECTION_CAUSE)) {
    return { cause: '', evidence: '', detail: '', trace: '', raw, hasSections: false };
  }
  const hasDetail = raw.includes(INCIDENT_SECTION_DETAIL);
  const evidenceEnd = hasDetail ? INCIDENT_SECTION_DETAIL : INCIDENT_SECTION_TRACE;
  return {
    cause: extractBetween(raw, INCIDENT_SECTION_CAUSE, INCIDENT_SECTION_EVIDENCE),
    evidence: extractBetween(raw, INCIDENT_SECTION_EVIDENCE, evidenceEnd),
    detail: hasDetail
      ? extractBetween(raw, INCIDENT_SECTION_DETAIL, INCIDENT_SECTION_TRACE)
      : '',
    trace: extractBetween(raw, INCIDENT_SECTION_TRACE),
    raw,
    hasSections: true,
  };
}

/** 将分段文本解析为「标签：值」行（用于详情页排版） */
export function parseDescriptionKvLines(text?: string): { key: string; value: string }[] {
  return String(text ?? '')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const sep = line.indexOf('：');
      if (sep > 0) {
        return { key: line.slice(0, sep), value: line.slice(sep + 1).trim() };
      }
      const sep2 = line.indexOf(':');
      if (sep2 > 0 && sep2 < 24) {
        return { key: line.slice(0, sep2), value: line.slice(sep2 + 1).trim() };
      }
      return { key: '', value: line };
    });
}

/** 解析证据块：首行为标题，后续以列表项展示 */
export function parseEvidenceBlock(text?: string): { title: string; items: string[] } {
  const lines = String(text ?? '')
    .split('\n')
    .map((l) => l.trimEnd())
    .filter((l) => l.trim());
  if (!lines.length) return { title: '', items: [] };
  const title = lines[0] || '';
  const items: string[] = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (/^[-\d]+[.)]\s/.test(line) || line.startsWith('- ')) {
      items.push(line.replace(/^[-\d]+[.)]\s*/, '').replace(/^-\s*/, '').trim());
    } else {
      items.push(line);
    }
  }
  if (!items.length && title && !title.endsWith('：')) {
    return { title: '', items: [title] };
  }
  return { title, items };
}

export function joinIncidentSections(parts: {
  cause: string;
  evidence: string;
  detail?: string;
  trace: string;
}): string {
  const blocks: string[] = [];
  if (parts.cause.trim()) {
    blocks.push(INCIDENT_SECTION_CAUSE, parts.cause.trim(), '');
  }
  if (parts.evidence.trim()) {
    blocks.push(INCIDENT_SECTION_EVIDENCE, parts.evidence.trim(), '');
  }
  if (parts.detail?.trim()) {
    blocks.push(INCIDENT_SECTION_DETAIL, parts.detail.trim(), '');
  }
  if (parts.trace.trim()) {
    blocks.push(INCIDENT_SECTION_TRACE, parts.trace.trim());
  }
  return blocks.join('\n').trim();
}
