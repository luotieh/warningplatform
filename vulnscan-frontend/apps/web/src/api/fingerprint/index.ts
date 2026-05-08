import { baseRequestClient, requestClient } from '#/api/request';

export interface ServiceFingerprint {
  id: string;
  name: string;
  service: string;
  protocol: string;
  probe_type: string;
  pattern: string;
  version_regex?: string;
  confidence: number;
  source_type?: string;
  sync_version?: number;
  created_at: string;
  updated_at: string;
}

export async function getFingerprintList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/fingerprint/list', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: ServiceFingerprint[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}

export function createFingerprint(data: Partial<ServiceFingerprint>) {
  return requestClient.post('/fingerprint', data);
}

export function updateFingerprint(id: string, data: Partial<ServiceFingerprint>) {
  return requestClient.put(`/fingerprint/${id}`, data);
}

export function deleteFingerprint(id: string) {
  return requestClient.delete(`/fingerprint/${id}`);
}
