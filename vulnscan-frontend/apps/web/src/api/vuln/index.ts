import { normalizePagedResponse } from '#/api/helpers';
import { baseRequestClient, requestClient } from '#/api/request';

export interface Vulnerability {
  id: string;
  title: string;
  type: string;
  severity: string;
  target: string;
  port?: number;
  url?: string;
  description: string;
  solution?: string;
  evidence?: string;
  cve_ids?: string[];
  cwe_ids?: string[];
  module_id: string;
  task_id: string;
  asset_id?: string;
  status: string;
  confidence?: number;
  first_seen_at?: string;
  last_seen_at?: string;
  created_at: string;
}

export async function getVulnList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/vuln/list', { params });
  return normalizePagedResponse<Vulnerability>(res);
}

export function getVulnDetail(id: string) {
  return requestClient.get<Vulnerability>(`/vuln/${id}`);
}

export function markFixed(id: string) {
  return requestClient.post(`/vuln/${id}/fix`);
}

export function markIgnored(id: string) {
  return requestClient.post(`/vuln/${id}/ignore`);
}

export function reopenVuln(id: string) {
  return requestClient.post(`/vuln/${id}/reopen`);
}

export function deleteVuln(id: string) {
  return requestClient.delete(`/vuln/${id}`);
}

export function getVulnStats() {
  return requestClient.get('/vuln/stats');
}

export interface VulnStatusHistory {
  id: string;
  vuln_id: string;
  old_status: string;
  new_status: string;
  comment: string;
  operator: string;
  created_at: string;
}

export function getVulnStatusHistory(id: string) {
  return requestClient.get<VulnStatusHistory[]>(`/vuln/${id}/history`);
}
