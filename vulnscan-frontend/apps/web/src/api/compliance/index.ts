import { requestClient } from '#/api/request';

export interface FrameworkSummary {
  id: string;
  name: string;
  version: string;
  description: string;
  standard: string;
  rule_count: number;
}

export interface Rule {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: string;
  check_type: string;
  remediation: string;
}

export interface CheckResult {
  rule_id: string;
  target_id: string;
  status: string;
  actual: string;
  expected: string;
  evidence: string;
}

export interface ComplianceReport {
  framework_id: string;
  target_id: string;
  total_rules: number;
  passed_rules: number;
  failed_rules: number;
  skipped_rules: number;
  score: number;
  results: CheckResult[];
}

export function getFrameworks() {
  return requestClient.get('/compliance/frameworks');
}

export function getFramework(id: string) {
  return requestClient.get(`/compliance/frameworks/${id}`);
}

export function getRules(id: string, params?: { category?: string; severity?: string }) {
  return requestClient.get(`/compliance/frameworks/${id}/rules`, { params });
}

export function runCheck(data: { framework_id: string; target_ip: string; username?: string; password?: string; port?: number }) {
  return requestClient.post('/compliance/check', data);
}
