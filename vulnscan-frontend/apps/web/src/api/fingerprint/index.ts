import { baseRequestClient, requestClient } from '#/api/request';

export interface ServiceFingerprint {
  id: string;
  name: string;
  service: string;
  protocol: string;
  probe_type: string;
  probe_data: string;
  match_type: string;
  match_rule: string;
  version_expr: string;
  priority: number;
  ports: string;
  status: string;
  source: string;
  description: string;
  sync_version: number;
  source_type: string;

  // HTTP 深度识别相关字段
  http_paths: string;
  http_headers: string;
  http_method: string;
  http_match_body: boolean;

  // TLS 证书分析相关字段
  tls_match_cn: boolean;
  tls_match_san: boolean;
  tls_match_org: boolean;
  tls_match_issuer: boolean;
  tls_match_expiry: boolean;
  tls_match_self_sign: boolean;

  // 探测链相关字段
  probe_chain: string;
  probe_chain_next: string;

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
