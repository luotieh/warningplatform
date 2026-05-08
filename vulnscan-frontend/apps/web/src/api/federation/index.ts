import { baseRequestClient, requestClient } from '#/api/request';

export interface SubMaster {
  id: string;
  sub_master_code: string;
  hostname: string;
  ip_address: string;
  version: string;
  status: string;
  cpu_percent: number;
  mem_percent: number;
  worker_count: number;
  active_tasks: number;
  scans_today: number;
  poc_version: number;
  fingerprint_version: number;
  rule_version: number;
  last_heartbeat_at?: string;
}

export interface FederationStats {
  total_sub_masters: number;
  online_sub_masters: number;
  current_versions: Record<string, number>;
}

export async function getSubMasterList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/federation/sub-masters', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: SubMaster[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}

export function getFederationStats() {
  return requestClient.get<FederationStats>('/federation/stats');
}
