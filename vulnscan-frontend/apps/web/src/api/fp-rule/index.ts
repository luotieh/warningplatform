import { baseRequestClient, requestClient } from '#/api/request';
import { normalizePagedResponse } from '#/api/helpers';

export interface FPRule {
  id: string;
  name: string;
  match_type: string;
  match_field: string;
  match_value: string;
  reason: string;
  source_id: string;
  scope: string;
  enabled: boolean;
  hit_count: number;
  created_by: string;
  organize_id: string;
  created_at: string;
  updated_at: string;
}

export async function getFPRuleList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/fp-rules', { params });
  return normalizePagedResponse<FPRule>(res);
}

export function getFPRuleDetail(id: string) {
  return requestClient.get<FPRule>(`/fp-rules/${id}`);
}

export function createFPRule(data: Partial<FPRule>) {
  return requestClient.post('/fp-rules', data);
}

export function updateFPRule(id: string, data: Partial<FPRule>) {
  return requestClient.put(`/fp-rules/${id}`, data);
}

export function deleteFPRule(id: string) {
  return requestClient.delete(`/fp-rules/${id}`);
}

export function toggleFPRule(id: string) {
  return requestClient.post(`/fp-rules/${id}/toggle`);
}

export function markAsFP(data: { finding_id: string; match_type?: string; reason?: string }) {
  return requestClient.post('/fp-rules/mark', data);
}
