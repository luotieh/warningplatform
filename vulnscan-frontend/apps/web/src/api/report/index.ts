import { requestClient } from '#/api/request';

export interface ReportRequest {
  title: string;
  task_id: string;
  type?: string;
  format: 'json' | 'word' | 'pdf' | 'markdown' | 'csv' | 'sarif';
  severity?: string[];
}

export interface ReportTaskMeta {
  id: string;
  name: string;
  status: string;
  targets?: string[];
  started_at?: string;
  finished_at?: string;
}

export interface ReportSummary {
  total_assets: number;
  total_findings: number;
  total_vulns: number;
  discovery_count: number;
  total_discovery_types: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  risk_score: number;
  compliance_score: number;
  scan_duration: string;
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

export interface DiscoveryItem {
  id: string;
  category: string;
  type: string;
  type_label: string;
  title: string;
  target: string;
  port: number;
  protocol: string;
  severity: string;
  confidence: number;
  module_id: string;
  description: string;
  evidence: string;
  summary: string;
  created_at: string;
}

export interface DiscoveryGroup {
  type: string;
  label: string;
  count: number;
}

export interface AssetItem {
  host: string;
  ip: string;
  open_ports: number[];
  services: string[];
  fingerprints: string[];
  vuln_count: number;
  finding_count: number;
}

export interface ReportData {
  title: string;
  generated_at: string;
  generated_by: string;
  task?: ReportTaskMeta | null;
  summary: ReportSummary;
  vulnerabilities: VulnItem[];
  discovery_findings: DiscoveryItem[];
  discovery_groups: DiscoveryGroup[];
  assets: AssetItem[];
}

export interface ReportTask {
  id: string;
  name: string;
  status?: string;
  finished_at?: string;
  created_at?: string;
  total_targets?: number;
  targets?: string[];
}

export function previewReport(data: Pick<ReportRequest, 'task_id' | 'title' | 'type'>) {
  return requestClient.post<ReportData>('/report/preview', data);
}

export function listReportTasks() {
  return requestClient.get<ReportTask[]>('/report/tasks');
}

export function getTaskReportURL(taskId: string, format: string) {
  return `/api/report/task/${taskId}?format=${format}`;
}

export function getTaskReportJSON(taskId: string) {
  return requestClient.get<ReportData>(`/report/task/${taskId}?format=json`);
}

export function downloadTaskReport(taskId: string, format: 'word' | 'pdf') {
  return requestClient.download<Blob>(`/report/task/${taskId}`, {
    params: { format },
  });
}
