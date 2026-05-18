import { normalizePagedResponse } from '#/api/helpers';
import { baseRequestClient, requestClient } from '#/api/request';

export interface TemplateParam {
  name: string;
  type: string;
  default: any;
  required: boolean;
  description: string;
  options?: string[];
}

export interface TemplateStage {
  name: string;
  module?: string;
  modules?: string[];
  parallel: boolean;
  condition?: { prev_stage_has_findings?: boolean; prev_stage_min_targets?: number; expression?: string };
  config?: Record<string, any>;
  depends_on?: string[];
  timeout?: string;
}

export interface ScanTemplate {
  id: string;
  name: string;
  code: string;
  category: string;
  description: string;
  icon: string;
  tags: string[];
  content: string;
  version: string;
  builtin: boolean;
  enabled: boolean;
  usage_count: number;
  params: TemplateParam[];
  stages: TemplateStage[];
  created_at: string;
  updated_at: string;
}

export async function getTemplateList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/template/list', { params });
  return normalizePagedResponse<ScanTemplate>(res);
}

export function getTemplateDetail(id: string) {
  return requestClient.get<ScanTemplate>(`/template/${id}`);
}

export function createTemplate(data: Partial<ScanTemplate>) {
  return requestClient.post('/template', data);
}

export function updateTemplate(id: string, data: Partial<ScanTemplate>) {
  return requestClient.put(`/template/${id}`, data);
}

export function deleteTemplate(id: string) {
  return requestClient.delete(`/template/${id}`);
}

export function toggleTemplate(id: string, enabled: boolean) {
  return requestClient.post(`/template/${id}/toggle`, { enabled });
}

export function seedBuiltins() {
  return requestClient.post('/template/seed-builtins');
}

export function getBuiltinTemplates() {
  return requestClient.get<ScanTemplate[]>('/template/builtins');
}
