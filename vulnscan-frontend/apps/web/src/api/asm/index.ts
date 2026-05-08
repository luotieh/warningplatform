import { baseRequestClient, requestClient } from '#/api/request';

export interface ASMProject {
  id: string;
  name: string;
  description: string;
  schedule: string;
  enabled: boolean;
  created_at: string;
}

export interface ASMSeed {
  id: string;
  project_id: string;
  type: string;
  value: string;
  enabled: boolean;
  last_run_at: string | null;
}

export interface ASMDiscoveredAsset {
  id: string;
  project_id: string;
  type: string;
  value: string;
  source: string;
  attributes: Record<string, string>;
  risk_score: number;
  status: string;
  first_seen: string;
  last_seen: string;
}

export interface ASMChange {
  id: string;
  project_id: string;
  asset_id: string;
  field: string;
  old_value: string;
  new_value: string;
  severity: string;
  change_at: string;
}

export function getProjects() {
  return baseRequestClient.get<any>('/asm/projects');
}

export function getProject(id: string) {
  return requestClient.get(`/asm/projects/${id}`);
}

export function createProject(data: { name: string; description?: string; schedule?: string; seeds?: { type: string; value: string }[] }) {
  return requestClient.post('/asm/projects', data);
}

export function updateProject(id: string, data: Partial<ASMProject>) {
  return requestClient.put(`/asm/projects/${id}`, data);
}

export function deleteProject(id: string) {
  return requestClient.delete(`/asm/projects/${id}`);
}

export function addSeed(projectId: string, data: { type: string; value: string }) {
  return requestClient.post(`/asm/projects/${projectId}/seeds`, data);
}

export function deleteSeed(projectId: string, seedId: string) {
  return requestClient.delete(`/asm/projects/${projectId}/seeds/${seedId}`);
}

export function runDiscovery(projectId: string) {
  return requestClient.post(`/asm/projects/${projectId}/discover`);
}

export function getDiscoveredAssets(projectId: string) {
  return baseRequestClient.get<any>(`/asm/projects/${projectId}/assets`);
}

export function getChanges(projectId: string) {
  return baseRequestClient.get<any>(`/asm/projects/${projectId}/changes`);
}

export function getAlertRules(projectId: string) {
  return requestClient.get(`/asm/projects/${projectId}/alert-rules`);
}

export function createAlertRule(projectId: string, data: { name: string; type: string; condition?: Record<string, any>; actions?: Record<string, any>; enabled?: boolean }) {
  return requestClient.post(`/asm/projects/${projectId}/alert-rules`, data);
}

export function deleteAlertRule(projectId: string, ruleId: string) {
  return requestClient.delete(`/asm/projects/${projectId}/alert-rules/${ruleId}`);
}

export function getExposureReport(projectId: string) {
  return requestClient.get(`/asm/projects/${projectId}/report`);
}
