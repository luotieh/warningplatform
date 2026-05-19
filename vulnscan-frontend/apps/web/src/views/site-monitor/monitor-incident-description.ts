import {
  INCIDENT_SECTION_CAUSE,
  INCIDENT_SECTION_EVIDENCE,
  INCIDENT_SECTION_TRACE,
  joinIncidentSections,
} from '../incident/incident-description';

import { buildMonitorEvidenceDetail } from './monitor-evidence-detail';
import { buildTamperEvidenceText } from './monitor-tamper-evidence';

const dimensionLabel: Record<string, string> = {
  tamper: '网站篡改',
  blacklink: '暗链检测',
  sensitive_word: '敏感词检测',
  sensitive_file: '敏感文件泄露',
  domain_hijack: '域名劫持',
  availability: '可用性异常',
};

function buildMonitorCause(d: {
  dimension: string;
  url: string;
  agent_id?: string;
  started_at?: string;
  id?: string;
}, dimLabel: string, formatTime?: (t?: string) => string): string {
  const lines = [
    `站点监测在「${dimLabel}」维度检测到异常。`,
    `监测目标 URL：${d.url}`,
  ];
  if (d.agent_id) lines.push(`Agent：${d.agent_id}`);
  if (d.started_at && formatTime) lines.push(`检测时间：${formatTime(d.started_at)}`);
  return lines.join('\n');
}

function buildMonitorEvidence(dim: string, result: any): string {
  if (!result) return '请在站点监测执行记录中查看完整探测结果。';

  if (dim === 'tamper') {
    const tamperText = buildTamperEvidenceText(result);
    if (tamperText) return tamperText;
  }
  if (dim === 'blacklink') {
    const links = result.blacklink_matches || [];
    const backdoors = result.backdoor_findings || [];
    const lines: string[] = [];
    if (links.length) {
      lines.push(`暗链（${links.length} 个）：`);
      for (const l of links.slice(0, 8)) {
        lines.push(`  - ${l.url || l.domain || '未知链接'}${l.hidden ? ' [隐藏]' : ''}`);
      }
    }
    if (backdoors.length) {
      lines.push(`后门（${backdoors.length} 个）：`);
      for (const b of backdoors.slice(0, 5)) {
        lines.push(`  - ${b.path || b.url || '未知路径'}`);
      }
    }
    if (lines.length) return lines.join('\n');
  }
  if (dim === 'sensitive_word' && result.matches?.length) {
    const lines = [`敏感词命中（${result.matches.length} 处）：`];
    for (const m of result.matches.slice(0, 8)) {
      const ctx = m.context ? ` 上下文: ${String(m.context).slice(0, 120)}` : '';
      lines.push(`  - [${m.severity || ''}] "${m.keyword || m.word || ''}"${ctx}`);
    }
    return lines.join('\n');
  }
  if (dim === 'sensitive_file') {
    const files = result.files || result.matches || [];
    if (files.length) {
      const lines = [`敏感文件（${files.length} 个）：`];
      for (const f of files.slice(0, 8)) {
        lines.push(`  - ${f.path || f.url || f.filename || '未知文件'}`);
      }
      return lines.join('\n');
    }
  }
  if (dim === 'domain_hijack') {
    const lines: string[] = [];
    if (result.hijacked) lines.push('状态：检测到域名劫持');
    if (result.resolved_ip) lines.push(`解析 IP：${result.resolved_ip}`);
    if (result.expected_ip) lines.push(`预期 IP：${result.expected_ip}`);
    if (result.dns_provider) lines.push(`DNS：${result.dns_provider}`);
    if (lines.length) return lines.join('\n');
  }
  if (dim === 'availability') {
    const lines: string[] = [];
    if (result.available === false) lines.push('状态：站点不可用');
    if (result.status_code) lines.push(`HTTP 状态码：${result.status_code}`);
    if (result.response_time_ms) lines.push(`响应时间：${result.response_time_ms}ms`);
    if (result.error) lines.push(`错误：${result.error}`);
    if (lines.length) return lines.join('\n');
  }
  return '详见站点监测执行记录中的结构化结果。';
}

function buildMonitorTrace(d: {
  id?: string;
  path_task_id?: string;
  target_id?: string;
  agent_id?: string;
}): string {
  const lines = ['来源：站点监测（手动转事件）'];
  if (d.id) lines.push(`监测执行 ID：${d.id}`);
  if (d.path_task_id) lines.push(`路径任务 ID：${d.path_task_id}`);
  if (d.target_id) lines.push(`监测目标 ID：${d.target_id}`);
  if (d.agent_id) lines.push(`执行 Agent：${d.agent_id}`);
  return lines.join('\n');
}

/** 构建带成因/证据/溯源分段的监测转事件描述。 */
export function buildMonitorIncidentDescription(
  d: {
    dimension: string;
    url: string;
    id?: string;
    path_task_id?: string;
    target_id?: string;
    agent_id?: string;
    started_at?: string;
  },
  result: any,
  formatTime?: (t?: string) => string,
): string {
  const dimLabel = dimensionLabel[d.dimension] || d.dimension;
  const detail = buildMonitorEvidenceDetail(d.dimension, result);
  return joinIncidentSections({
    cause: buildMonitorCause(d, dimLabel, formatTime),
    evidence: buildMonitorEvidence(d.dimension, result),
    detail: detail || undefined,
    trace: buildMonitorTrace(d),
  });
}
