import type { ScanFinding } from '#/api/task';

import {
  joinIncidentSections,
} from '../incident/incident-description';

const moduleToType: Record<string, string> = {
  sqli: 'SQL注入',
  sql: 'SQL注入',
  xss: 'XSS漏洞',
  cmdi: '命令注入',
  rce: '远程代码执行',
  command: '远程代码执行',
  lfi: '文件包含',
  ssti: '模板注入',
  xxe: 'XXE注入',
  ssrf: 'SSRF服务端请求伪造',
  nosqli: 'NoSQL注入',
  jwt_sec: 'JWT安全缺陷',
  jwt: 'JWT安全缺陷',
  weak_pass: '弱口令',
  brute: '爆破',
  cert_check: '证书安全',
  cert: '证书安全',
  info_leak: '信息泄露',
  dir_scan: '信息泄露',
  poc: '已知漏洞利用',
};

export function classifyScanIncidentType(finding: ScanFinding): string {
  const moduleId = finding.module_id || '';
  if (!moduleId) return moduleToType[finding.type] || '漏洞';
  for (const [key, label] of Object.entries(moduleToType)) {
    if (moduleId.includes(key)) return label;
  }
  return moduleToType[finding.type] || '漏洞';
}

export function buildScanIncidentDescription(finding: ScanFinding): string {
  const incidentType = classifyScanIncidentType(finding);
  const d = finding.data || {};

  const causeLines = [
    `漏洞扫描发现「${incidentType}」类安全问题，严重级别：${(finding.severity || '').toUpperCase() || '未知'}。`,
  ];
  if (finding.description) causeLines.push(finding.description);
  if (finding.confidence) {
    let line = `检测置信度：${finding.confidence}%`;
    if (finding.confidence_reason) line += `（${finding.confidence_reason}）`;
    causeLines.push(line);
  }

  const evidenceLines: string[] = [];
  if (finding.evidence) {
    evidenceLines.push('技术证据：', finding.evidence);
  }
  if (d.service) {
    evidenceLines.push(`识别服务：${d.service}${d.version ? ` ${d.version}` : ''}`);
  }
  if (d.banner) evidenceLines.push(`Banner：${String(d.banner).slice(0, 300)}`);
  if (finding.port) {
    evidenceLines.push(`端口：${finding.port}/${finding.protocol || 'tcp'}`);
  }
  if (finding.verification_level) {
    evidenceLines.push(
      `验证级别：${finding.verification_level === 'exploit' ? '实际利用验证' : '原理验证'}`,
    );
  }
  if (finding.verification_detail) {
    evidenceLines.push(`验证方式：${finding.verification_detail}`);
  }

  const traceLines = [
    '来源：漏洞扫描（手动转事件）',
    `扫描发现 ID：${finding.id}`,
    `扫描任务 ID：${finding.task_id}`,
  ];
  if (finding.module_id) traceLines.push(`检测模块：${finding.module_id}`);
  if (finding.asset_id) traceLines.push(`关联资产 ID：${finding.asset_id}`);

  return joinIncidentSections({
    cause: causeLines.join('\n'),
    evidence: evidenceLines.length ? evidenceLines.join('\n') : '详见扫描发现详情。',
    trace: traceLines.join('\n'),
  });
}
