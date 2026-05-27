import { baseRequestClient, requestClient } from '#/api/request';
import { normalizePagedResponse } from '#/api/helpers';

export interface PocTemplate {
  id: string;
  poc_id: string;
  name: string;
  author: string;
  severity: string;
  description?: string;
  tags: string[];
  content: string;
  enabled: boolean;
  category?: string;
  cve?: string;
  cwe?: string;
  cvss?: string;
  hit_count?: number;
  source?: string;
  source_type?: string;
  source_url?: string;
  sync_version?: number;
  created_at: string;
  updated_at: string;
}

export async function getPocList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/poc/list', { params });
  return normalizePagedResponse<PocTemplate>(res);
}

export function getPocDetail(id: string) {
  return requestClient.get<PocTemplate>(`/poc/${id}`);
}

export function createPoc(data: Partial<PocTemplate>) {
  return requestClient.post('/poc', data);
}

export function updatePoc(id: string, data: Partial<PocTemplate>) {
  return requestClient.put(`/poc/${id}`, data);
}

export function deletePoc(id: string) {
  return requestClient.delete(`/poc/${id}`);
}

export function togglePoc(id: string, enabled: boolean) {
  return requestClient.post(`/poc/${id}/toggle`, { enabled });
}

export function importPocYaml(yaml: string) {
  return requestClient.post('/poc/import', { yaml });
}

export function importPocsFromDir(dir: string) {
  return requestClient.post('/poc/import-dir', { dir });
}

export function importPocUpload(file: File) {
  const formData = new FormData();
  formData.append('file', file);
  return requestClient.post<{ imported: number; skipped: number; errors: number }>('/poc/import-upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
}

export interface ValidateResult {
  valid: boolean;
  error?: string;
  id?: string;
  name?: string;
  author?: string;
  severity?: string;
  description?: string;
  tags?: string[];
  reference?: string[];
}

export function validatePocYaml(yaml: string) {
  return requestClient.post<ValidateResult>('/poc/validate', { yaml });
}

export interface TestPocMatch {
  template_id: string;
  name: string;
  severity: string;
  matched_at: string;
  matcher_name?: string;
  evidence?: string;
  curl_command?: string;
}

export interface TestPocResult {
  success: boolean;
  error?: string;
  duration: string;
  findings: TestPocMatch[];
}

export function testPoc(yaml: string, targetUrl: string) {
  return requestClient.post<TestPocResult>('/poc/test', {
    yaml,
    target_url: targetUrl,
  });
}

/** 与扫描任务相同的 Nuclei 引擎，不落库；parameters 需含 nuclei_template_dir 等或依赖库内已启用 PoC */
export interface QuickNucleiScanParams {
  targets?: string[];
  urls?: string[];
  parameters?: Record<string, any>;
  timeout_seconds?: number;
}

export interface QuickNucleiScanResult {
  findings: Record<string, any>[];
  duration_ms: number;
}

export function quickNucleiScan(body: QuickNucleiScanParams) {
  return requestClient.post<QuickNucleiScanResult>('/poc/quick-scan', body);
}
