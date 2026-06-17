import type { IncidentReportData } from '#/api/incident';

function d(v?: string) {
  return v?.trim() ? escHtml(v) : '-';
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatEvidenceKV(text: string): string {
  const lines = text.split('\n');
  let html = '';
  let inGroup = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const secMatch = trimmed.match(/^(.+?)：$/);
    if (secMatch && !trimmed.includes('  ')) {
      if (inGroup) html += '</tbody></table>';
      html += `<div class="ev-group-title">${escHtml(secMatch[1]!)}</div>`;
      html += '<table class="ev-kv-table"><tbody>';
      inGroup = true;
      continue;
    }
    const kvMatch = trimmed.match(/^\s*(.+?)[:：]\s*(.+)$/);
    if (kvMatch) {
      if (!inGroup) {
        html += '<table class="ev-kv-table"><tbody>';
        inGroup = true;
      }
      let val = kvMatch[2]!;
      try {
        const parsed = JSON.parse(val);
        if (typeof parsed === 'object' && parsed !== null) {
          val = JSON.stringify(parsed, null, 2);
          html += `<tr><td class="ev-kv-k">${escHtml(kvMatch[1]!)}</td><td class="ev-kv-v"><pre class="ev-json">${escHtml(val)}</pre></td></tr>`;
          continue;
        }
      } catch { /* not JSON */ }
      html += `<tr><td class="ev-kv-k">${escHtml(kvMatch[1]!)}</td><td class="ev-kv-v">${escHtml(val)}</td></tr>`;
    } else if (inGroup) {
      html += `<tr><td colspan="2" class="ev-kv-v">${escHtml(trimmed)}</td></tr>`;
    }
  }
  if (inGroup) html += '</tbody></table>';
  return html || `<pre>${escHtml(text)}</pre>`;
}

function descSectionsHtml(r: IncidentReportData): string {
  const sec = r.description_sections;
  if (!sec?.has_sections) {
    return `<pre>${d(r.description)}</pre>`;
  }
  let html = '';
  const parts: [string, string | undefined, boolean][] = [
    ['一、事件成因', sec.cause, false],
    ['二、证据详情', sec.evidence, false],
    ['三、详细证据', sec.detail, true],
    ['四、溯源信息', sec.trace, false],
  ];
  for (const [title, body, isDetail] of parts) {
    if (!body?.trim()) continue;
    html += `<div class="desc-section"><div class="desc-section__title">${escHtml(title)}</div>`;
    html += isDetail ? formatEvidenceKV(body) : `<pre>${escHtml(body)}</pre>`;
    html += `</div>`;
  }
  return html;
}

function evidenceImagesHtml(r: IncidentReportData): string {
  if (!r.evidence_images?.length) return '';
  let html = '<div class="evidence-gallery">';
  for (const img of r.evidence_images) {
    if (!img.base64?.trim()) continue;
    html += `<div class="evidence-gallery__item">`;
    html += `<img src="data:${img.mime_type};base64,${img.base64}" alt="${escHtml(img.caption)}" />`;
    html += `<div class="evidence-gallery__caption">${escHtml(img.caption)}</div>`;
    html += `</div>`;
  }
  html += '</div>';
  return html;
}

function row4(k1: string, v1: string, k2: string, v2: string): string {
  return `<tr><th>${escHtml(k1)}</th><td>${v1}</td><th>${escHtml(k2)}</th><td>${v2}</td></tr>`;
}

function rowSpan(k: string, v: string, cssClass = ''): string {
  const cls = cssClass ? ` class="${cssClass}"` : '';
  return `<tr><th>${escHtml(k)}</th><td colspan="3"${cls}>${v}</td></tr>`;
}

export function buildIncidentReportHtml(r: IncidentReportData): string {
  const rows = [
    row4('隐患编号', d(r.incident_no), '数据编号', d(r.data_no)),
    rowSpan('隐患名称', d(r.name || r.title)),
    rowSpan('厂商上报归属地', d(r.vendor_region)),
    rowSpan('隐患URL', d(r.incident_url), 'break-all'),
    row4('网站名称', d(r.asset_name), '网站域名IP', d(r.domain_ip)),
    row4('网站IP', d(r.site_ip), '归属地', d(r.region)),
    row4('隐患类型', d(r.incident_type), '预警级别', d(r.warning_level)),
    row4('隐患级别', d(r.level), '发现时间', d(r.discovery_time)),
    row4('上报厂商', d(r.vendor_name), '厂商上报时间', d(r.vendor_time)),
    row4('涉及信息数量', d(r.affected_count), '涉及信息类型', d(r.affected_type)),
    row4('隶属单位', d(r.unit), '单位类型', d(r.unit_type)),
    row4('所属行业', d(r.industry), '工信部备案号', d(r.miit_record_no)),
    row4('等保级别', d(r.mlps_level), '等保备案号', d(r.mlps_record_no)),
  ];

  const descHtml = descSectionsHtml(r) + evidenceImagesHtml(r);
  if (descHtml.trim()) {
    rows.push(`<tr><th>隐患描述</th><td colspan="3" class="hazard-desc">${descHtml}</td></tr>`);
  }

  if (r.remediation_plan?.trim() || r.remediation_advice?.trim()) {
    let rem = '';
    if (r.remediation_plan?.trim()) rem += `<pre>${escHtml(r.remediation_plan)}</pre>`;
    if (r.remediation_advice?.trim() && r.remediation_advice !== r.remediation_plan)
      rem += `<pre>${escHtml(r.remediation_advice)}</pre>`;
    rows.push(`<tr><th>整改建议</th><td colspan="3" class="hazard-desc">${rem}</td></tr>`);
  }

  if (r.attachment?.trim()) {
    rows.push(rowSpan('证据附件', d(r.attachment), 'hazard-attach'));
  }

  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"/>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: "Microsoft YaHei", "SimHei", "PingFang SC", sans-serif; padding: 24px; background: #fff; color: #333; }
.hazard-doc__title { text-align: center; font-size: 20px; font-weight: 700; letter-spacing: 2px; margin: 0 0 16px; }
.hazard-table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: 13px; }
.hazard-table th, .hazard-table td { border: 1px solid #333; padding: 8px 10px; vertical-align: top; }
.hazard-table th { width: 14%; text-align: center; font-weight: 500; background: #fafafa; }
.hazard-desc { line-height: 1.5; }
.hazard-desc pre { margin: 0 0 8px; white-space: pre-wrap; word-break: break-word; font-family: inherit; font-size: 13px; }
.desc-section { margin-bottom: 12px; }
.desc-section__title { font-weight: 600; margin-bottom: 4px; }
.evidence-gallery { margin-top: 12px; }
.evidence-gallery__item { margin-bottom: 16px; text-align: center; }
.evidence-gallery__item img { max-width: 100%; border: 1px solid #ddd; }
.evidence-gallery__caption { font-size: 12px; color: #666; margin-top: 4px; }
.hazard-attach { color: #2080f0; }
.break-all { word-break: break-all; }
.ev-group-title { font-weight: 600; font-size: 13px; margin: 8px 0 4px; padding: 4px 8px; background: #f0f5ff; border-left: 3px solid #2080f0; }
.ev-kv-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 8px; }
.ev-kv-table td { padding: 4px 8px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
.ev-kv-k { width: 30%; color: #666; font-weight: 500; word-break: break-all; }
.ev-kv-v { color: #333; word-break: break-all; }
.ev-json { margin: 0; padding: 4px 6px; background: #f9f9f9; border: 1px solid #eee; border-radius: 3px; font-family: Consolas, Monaco, monospace; font-size: 11px; white-space: pre-wrap; word-break: break-all; }
</style>
</head>
<body>
<div class="hazard-doc">
  <h1 class="hazard-doc__title">网络安全隐患详情</h1>
  <table class="hazard-table"><tbody>${rows.join('\n')}</tbody></table>
</div>
</body>
</html>`.trim();
}
