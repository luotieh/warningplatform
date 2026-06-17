/** 监测转事件 / 通报 PDF 用的详细证据纯文本（与后端 incident_evidence_detail.go 对齐） */

const MAX_DETAIL_CHARS = 24000;

function truncateText(s: string, max = MAX_DETAIL_CHARS): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max)}\n…（内容已截断，完整证据见监测执行记录）`;
}

export function htmlEvidenceToPlain(html: string): string {
  if (!html) return '';
  let s = html;
  s = s.replaceAll('<del class="tp-del">', '\n[-');
  s = s.replaceAll('</del>', '-]\n');
  s = s.replaceAll('<ins class="tp-ins">', '\n[+');
  s = s.replaceAll('</ins>', '+]\n');
  s = s.replaceAll(/<mark[^>]*>/g, '\n【敏感词】');
  s = s.replaceAll('</mark>', '【/敏感词】\n');
  s = s.replaceAll(/<[^>]+>/g, '');
  s = s
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&amp;', '&')
    .replaceAll('&quot;', '"');
  return s
    .split('\n')
    .map((l) => l.trimEnd())
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

export function buildTamperEvidenceDetail(result: any): string {
  if (!result) return '';
  const lines: string[] = [];
  if (result.title) lines.push(`页面标题：${result.title}`);
  if (result.url) lines.push(`页面 URL：${result.url}`);
  if (result.status_code) lines.push(`HTTP 状态码：${result.status_code}`);

  const diffs = result.diffs || [];
  for (const diff of diffs) {
    if (diff?.type !== 'injected_elements' || !diff.elements?.length) continue;
    lines.push(`\n异常注入元素（${diff.elements.length} 个）：`);
    diff.elements.slice(0, 20).forEach((el: any, i: number) => {
      lines.push(
        `  ${i + 1}. 类型=${el.type || 'unknown'} 域名=${el.domain || '-'}`,
        `     地址=${el.src || el.href || '-'}`,
      );
    });
  }

  const ev = result.evidence;
  if (!ev?.baseline_html && !ev?.current_html) {
    return lines.join('\n').trim();
  }
  if (ev.truncated) {
    lines.push('\n（页面正文较长，以下内容为截断摘录）');
  }
  lines.push(
    '\n════════ 内容对比（文本摘录，[-] 为相对基线删除，[+] 为相对基线新增） ════════',
  );
  const base = ev.baseline_html || '';
  const cur = ev.current_html || '';
  if (base && cur && base === cur) {
    lines.push('\n【基线全文（首次建立）】', truncateText(htmlEvidenceToPlain(base), 12000));
  } else {
    if (base) {
      lines.push('\n【基线 / 相对删除】', truncateText(htmlEvidenceToPlain(base), 12000));
    }
    if (cur) {
      lines.push('\n【当前 / 相对新增】', truncateText(htmlEvidenceToPlain(cur), 12000));
    }
  }
  return truncateText(lines.join('\n'));
}

export function buildSensitiveWordEvidenceDetail(result: any): string {
  if (!result) return '';
  const lines: string[] = [];
  const matches = result.matches || [];
  if (matches.length) {
    lines.push(`敏感词命中明细（共 ${matches.length} 处）：`);
    matches.slice(0, 30).forEach((m: any, i: number) => {
      lines.push(
        `\n[${i + 1}] 词条="${m.keyword || m.word || ''}" 级别=${m.severity || '-'}`,
      );
      if (m.url) lines.push(`    页面：${m.url}`);
      if (m.context) lines.push(`    上下文：${m.context}`);
      (m.contexts || []).slice(0, 5).forEach((c: string, j: number) => {
        lines.push(`    片段${j + 1}：${c}`);
      });
    });
    if (matches.length > 30) lines.push(`… 另有 ${matches.length - 30} 处未列出`);
  }
  if (result.page_evidence_html) {
    lines.push('\n════════ 页面全文摘录（敏感词已标注） ════════');
    lines.push(truncateText(htmlEvidenceToPlain(result.page_evidence_html)));
  }
  return lines.join('\n').trim();
}

export function buildBlacklinkEvidenceDetail(result: any): string {
  if (!result) return '';
  const lines: string[] = [];
  if (result.total_links != null) lines.push(`页面链接总数：${result.total_links}`);
  if (result.external_links != null) lines.push(`外链数量：${result.external_links}`);
  const links = result.blacklink_matches || [];
  if (links.length) {
    lines.push(`\n暗链明细（${links.length} 个）：`);
    links.slice(0, 25).forEach((l: any, i: number) => {
      lines.push(
        `  ${i + 1}. ${l.url || l.domain || '未知'}${l.hidden ? ' [隐藏]' : ''}`,
      );
      if (l.pattern) lines.push(`     匹配规则：${l.pattern}`);
    });
  }
  const backs = result.backdoor_findings || [];
  if (backs.length) {
    lines.push(`\n后门特征（${backs.length} 个）：`);
    backs.slice(0, 15).forEach((b: any, i: number) => {
      lines.push(
        `  ${i + 1}. 特征路径=${b.path || '-'}`,
        `     脚本地址=${b.src || '-'}`,
        `     上下文=${b.context || '-'}`,
      );
    });
  }
  return lines.join('\n').trim();
}

export function buildAvailabilityEvidenceDetail(result: any): string {
  if (!result) return '';
  const lines: string[] = [];
  const formatValue = (v: unknown): string => {
    if (v == null) return '';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  };
  const appendObj = (title: string, obj: Record<string, any> | undefined) => {
    if (!obj || !Object.keys(obj).length) return;
    lines.push(`\n${title}：`);
    for (const [k, v] of Object.entries(obj)) {
      if (v != null && v !== '') lines.push(`  ${k}：${formatValue(v)}`);
    }
  };
  appendObj('耗时分解 (ms)', result.timing);
  appendObj('DNS', result.dns);
  appendObj('HTTP', result.http);
  appendObj('SSL/TLS', result.ssl);
  (result.errors || []).slice(0, 10).forEach((e: string) => lines.push(`  错误：${e}`));
  (result.warnings || []).slice(0, 10).forEach((w: string) => lines.push(`  告警：${w}`));
  (result.security_issues || []).slice(0, 15).forEach((s: any) => lines.push(`  安全问题：${JSON.stringify(s)}`));
  return lines.join('\n').trim();
}

export function buildMonitorEvidenceDetail(dim: string, result: any): string {
  if (!result) return '';
  switch (dim) {
    case 'tamper':
      return buildTamperEvidenceDetail(result);
    case 'sensitive_word':
      return buildSensitiveWordEvidenceDetail(result);
    case 'blacklink':
      return buildBlacklinkEvidenceDetail(result);
    case 'sensitive_file': {
      const files = result.files || result.matches || [];
      if (!files.length) return '';
      const lines = [`敏感文件明细（${files.length} 个）：`];
      files.slice(0, 30).forEach((f: any, i: number) => {
        lines.push(`  ${i + 1}. ${f.path || f.url || f.filename || '未知'}`);
        if (f.risk) lines.push(`     风险：${f.risk}`);
      });
      return lines.join('\n');
    }
    case 'domain_hijack': {
      const keys = ['hijacked', 'resolved_ip', 'expected_ip', 'dns_provider', 'error'];
      return keys
        .filter((k) => result[k] != null && result[k] !== '')
        .map((k) => `${k}：${result[k]}`)
        .join('\n');
    }
    case 'availability':
      return buildAvailabilityEvidenceDetail(result);
    default:
      return '';
  }
}
