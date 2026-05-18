import { baseRequestClient, requestClient } from '#/api/request';
import { normalizePagedResponse } from '#/api/helpers';

export interface ScanExclusion {
  id: string;
  name: string;
  rule_type: string;
  match_value: string;
  description: string;
  scope: string;
  enabled: boolean;
  hit_count: number;
  created_by: string;
  organize_id: string;
  created_at: string;
  updated_at: string;
}

export async function getExclusionList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/scan-exclusions', { params });
  return normalizePagedResponse<ScanExclusion>(res);
}

export function getExclusionDetail(id: string) {
  return requestClient.get<ScanExclusion>(`/scan-exclusions/${id}`);
}

export function createExclusion(data: Partial<ScanExclusion>) {
  return requestClient.post('/scan-exclusions', data);
}

export function updateExclusion(id: string, data: Partial<ScanExclusion>) {
  return requestClient.put(`/scan-exclusions/${id}`, data);
}

export function deleteExclusion(id: string) {
  return requestClient.delete(`/scan-exclusions/${id}`);
}

export function toggleExclusion(id: string) {
  return requestClient.post(`/scan-exclusions/${id}/toggle`);
}
