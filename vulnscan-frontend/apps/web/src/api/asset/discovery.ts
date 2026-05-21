import { normalizePagedResponse } from '#/api/helpers';
import { baseRequestClient, requestClient } from '#/api/request';

export interface AssetDiscoveryProbe {
  id: string;
  name: string;
  task_id?: string;
  targets_raw?: string;
  target_count: number;
  ports_preset: string;
  status: string;
  candidate_total: number;
  pending_count: number;
  verified_count: number;
  imported_count: number;
  error_msg?: string;
  created_at: string;
  updated_at: string;
  started_at?: string;
  finished_at?: string;
  /** 关联扫描任务状态（列表接口附加） */
  task_status?: string;
  alive_hosts?: number;
  open_ports?: number;
}

export interface AssetDiscoveryCandidate {
  id: string;
  probe_id: string;
  address: string;
  port: number;
  protocol?: string;
  service?: string;
  version?: string;
  asset_type?: string;
  alive: boolean;
  title?: string;
  evidence?: string;
  status: string;
  target_organize_id?: string;
  target_organize_name?: string;
  in_asset_library?: boolean;
  existing_asset_id?: string;
  existing_organize_id?: string;
  existing_organize_name?: string;
  imported_asset_id?: string;
  verify_remark?: string;
  verified_at?: string;
}

export interface CreateDiscoveryProbeParams {
  name?: string;
  targets?: string[];
  targets_text?: string;
  ports_preset?: string;
  /** 自定义端口列表（与 ports_preset 二选一，优先使用此项） */
  ports_custom?: string;
  timeout_ms?: number;
}

export async function createDiscoveryProbe(data: CreateDiscoveryProbeParams) {
  return requestClient.post<{
    probe: AssetDiscoveryProbe;
    task_id: string;
    expanded: number;
    split_mode?: boolean;
    sub_count?: number;
  }>('/asset/discovery/probes', data);
}

export async function getDiscoveryProbeList(params: {
  page?: number;
  page_size?: number;
  keyword?: string;
  status?: string;
}) {
  const res = await baseRequestClient.get('/asset/discovery/probes', { params });
  return normalizePagedResponse<AssetDiscoveryProbe>(res);
}

export async function getDiscoveryProbe(id: string) {
  return requestClient.get<AssetDiscoveryProbe>(`/asset/discovery/probes/${id}`);
}

export async function getDiscoveryCandidates(
  probeId: string,
  params: { page?: number; page_size?: number; status?: string; keyword?: string },
) {
  const res = await baseRequestClient.get(`/asset/discovery/probes/${probeId}/candidates`, {
    params,
  });
  return normalizePagedResponse<AssetDiscoveryCandidate>(res);
}

export async function syncDiscoveryCandidates(probeId: string) {
  return requestClient.post<{ synced: number }>(`/asset/discovery/probes/${probeId}/sync`);
}

export async function verifyDiscoveryCandidates(
  probeId: string,
  data: { ids: string[]; target_organize_id: string; remark?: string },
) {
  return requestClient.post<{
    updated: number;
    target_organize_id?: string;
    target_organize_name?: string;
  }>(`/asset/discovery/probes/${probeId}/candidates/verify`, data);
}

export async function rejectDiscoveryCandidates(probeId: string, ids: string[], remark?: string) {
  return requestClient.post<{ updated: number }>(
    `/asset/discovery/probes/${probeId}/candidates/reject`,
    { ids, remark },
  );
}

export async function importDiscoveryCandidates(probeId: string, ids: string[], remark?: string) {
  return requestClient.post<{ imported: number; skipped: number }>(
    `/asset/discovery/probes/${probeId}/candidates/import`,
    { ids, remark },
  );
}
