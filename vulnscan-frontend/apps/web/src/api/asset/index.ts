import { baseRequestClient, requestClient } from '#/api/request';

export interface Asset {
  id: string;
  name: string;
  type: string;
  address: string;
  port?: number;
  group_id?: string;
  tags?: string[];
  status: number;
  created_by?: string;
  organize_id?: string;
  created_at: string;
  updated_at: string;
  domain?: string;
  ipv4?: string;
  ipv6?: string;
  url?: string;
  protocol?: string;
  service?: string;
  version?: string;
  os?: string;
  data_number?: string;
  system_name?: string;
  system_type?: string;
  is_online?: boolean;
  is_key?: boolean;
  security_protection_level?: string;
  filing_cert_number?: string;
  icp_filing_number?: string;
  construction_org_id?: string;
  operation_org_id?: string;
  lifecycle_state?: string;
  review_status?: string;
  data_source?: string;
  responsible_user_id?: string;
  responsible_user_name?: string;
  risk_score?: number;
  vuln_count?: number;
  last_scan_at?: string;
  ssl_expires_at?: string;
  domain_expires_at?: string;
  remark?: string;
}

export interface AssetGroup {
  id: string;
  name: string;
  description?: string;
  asset_count?: number;
  created_at: string;
}

export async function getAssetList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/asset/list', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: Asset[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}

export function getAssetDetail(id: string) {
  return requestClient.get<Asset>(`/asset/${id}`);
}

export function createAsset(data: Partial<Asset>) {
  return requestClient.post('/asset', data);
}

export function updateAsset(id: string, data: Partial<Asset>) {
  return requestClient.put(`/asset/${id}`, data);
}

export function deleteAsset(id: string) {
  return requestClient.delete(`/asset/${id}`);
}

export function getAssetGroups(params?: Record<string, any>) {
  return requestClient.get('/asset/group/list', { params });
}

export function createAssetGroup(data: Partial<AssetGroup>) {
  return requestClient.post('/asset/group', data);
}

export function updateAssetGroup(id: string, data: Partial<AssetGroup>) {
  return requestClient.put(`/asset/group/${id}`, data);
}

export function deleteAssetGroup(id: string) {
  return requestClient.delete(`/asset/group/${id}`);
}

export interface AssetEnrichDetail {
  asset: Asset;
  ports: { port: number; protocol: string; service: string; version: string }[];
  vulns: { id: string; title: string; severity: string; status: string; target: string; created_at: string }[];
  scan_history: { id: string; name: string; status: string; created_at: string; finished_at?: string }[];
  services: { service_name: string; version: string; port: string; count: number }[];
  summary: { port_count: number; vuln_count: number; scan_count: number; risk_score: number; last_scan?: string };
}

export async function getAssetEnrich(id: string) {
  const res = await baseRequestClient.get<any>(`/asset/${id}/enrich`);
  const body = (res as Record<string, unknown>).data ?? res;
  return (body as { data?: AssetEnrichDetail }).data;
}

export interface AssetStats {
  total: number;
  active: number;
  inactive: number;
  with_vulns: number;
  by_type: { type: string; count: number }[];
  by_group: { group_id: string; count: number }[];
}

export async function getAssetStats() {
  const res = await baseRequestClient.get<any>('/asset/stats');
  const body = (res as Record<string, unknown>).data ?? res;
  return (body as { data?: AssetStats }).data;
}

export function aggregateAssets() {
  return requestClient.post('/asset/aggregate');
}

export function batchAssignGroup(assetIds: string[], groupId: string) {
  return requestClient.post('/asset/batch-assign', { asset_ids: assetIds, group_id: groupId });
}

export function importAssets(file: File) {
  const formData = new FormData();
  formData.append('file', file);
  return requestClient.post('/asset/import', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
}

export function getImportTemplateUrl() {
  return '/api/asset/import/template';
}
