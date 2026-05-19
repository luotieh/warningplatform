/** 篡改 diff 证据格式化（与 TamperDetail 字段含义一致） */

export const TAMPER_DIFF_LABELS: Record<string, string> = {
  content_hash: '内容 Hash 变化',
  title: '页面标题变化',
  status_code: 'HTTP 状态码变化',
  text_length: '可见文本长度异常',
  injected_elements: '异常注入元素',
};

function truncateHash(s: string): string {
  const v = String(s);
  if (v.length <= 20) return v;
  return `${v.slice(0, 10)}…${v.slice(-10)}`;
}

export function formatTamperDiffItem(diff: Record<string, any>): string {
  const type = String(diff?.type || '');
  const label = TAMPER_DIFF_LABELS[type] || type || '未知变更';

  if (type === 'injected_elements') {
    const els = (diff.elements as any[]) || [];
    if (!els.length) return `${label}：发现异常元素`;
    const preview = els
      .slice(0, 3)
      .map((e) => e?.tag || e?.src || e?.href || JSON.stringify(e))
      .join('；');
    return `${label}：${els.length} 处（${preview}${els.length > 3 ? '…' : ''}）`;
  }

  const base = diff.baseline;
  const cur = diff.current;
  if (base !== undefined && cur !== undefined) {
    const baseStr = String(base);
    const curStr = String(cur);
    if (type === 'text_length' && typeof diff.ratio === 'number') {
      return `${label}：基线 ${baseStr} 字 → 当前 ${curStr} 字（变化约 ${(diff.ratio * 100).toFixed(0)}%）`;
    }
    if (type === 'content_hash') {
      return `${label}：${truncateHash(baseStr)} → ${truncateHash(curStr)}`;
    }
    return `${label}：${baseStr} → ${curStr}`;
  }

  if (diff.severity) {
    return `[${diff.severity}] ${label}${diff.selector ? ` (${diff.selector})` : ''}`;
  }
  return label;
}

export function buildTamperEvidenceText(result: any): string {
  if (!result) return '';
  const diffs = result.diffs || [];
  if (!diffs.length) {
    const lines: string[] = [];
    if (result.tampered) lines.push('状态：检测到页面篡改');
    if (result.title) lines.push(`页面标题：${result.title}`);
    if (result.content_hash) lines.push(`当前内容 Hash：${truncateHash(result.content_hash)}`);
    return lines.join('\n') || '';
  }
  const lines = [`篡改变更（${diffs.length} 处）：`];
  for (const diff of diffs.slice(0, 12)) {
    lines.push(`  - ${formatTamperDiffItem(diff)}`);
  }
  if (diffs.length > 12) lines.push(`  … 共 ${diffs.length} 处`);
  return lines.join('\n');
}
