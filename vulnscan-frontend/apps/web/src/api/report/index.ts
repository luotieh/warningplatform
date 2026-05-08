import { baseRequestClient, requestClient } from '#/api/request';

export interface ReportRequest {
  title: string;
  task_ids: string[];
  format: 'json' | 'markdown' | 'csv' | 'sarif';
  severity?: string[];
}

export interface ReportSummary {
  total_assets: number;
  total_vulns: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  risk_score: number;
}

export interface VulnItem {
  id: string;
  title: string;
  severity: string;
  cve_id: string;
  asset: string;
  status: string;
  description: string;
  evidence: string;
  remediation: string;
}

export interface ReportData {
  title: string;
  generated_at: string;
  summary: ReportSummary;
  vulnerabilities: VulnItem[];
}

export function generateReport(data: ReportRequest) {
  return requestClient.post<ReportData>('/report/generate', data);
}

export function getTaskReportURL(taskId: string, format: string) {
  return `/api/report/task/${taskId}?format=${format}`;
}

export async function getTaskReportJSON(taskId: string) {
  const res = await baseRequestClient.get<ReportData>(`/report/task/${taskId}?format=json`);
  return res as unknown as ReportData;
}

export interface VulnDiff {
  id: string;
  title: string;
  severity: string;
  target: string;
  status: string;
  old_severity?: string;
  diff_type: string;
}

export interface CompareResult {
  base_task_id: string;
  compare_task_id: string;
  new_vulns: VulnDiff[];
  fixed_vulns: VulnDiff[];
  changed_vulns: VulnDiff[];
  unchanged_count: number;
  summary: {
    base_total: number;
    compare_total: number;
    new_count: number;
    fixed_count: number;
    changed_count: number;
    delta: number;
  };
}

export function compareTasks(baseId: string, compareId: string) {
  return requestClient.get<CompareResult>('/report/compare', { params: { base: baseId, compare: compareId } });
}
