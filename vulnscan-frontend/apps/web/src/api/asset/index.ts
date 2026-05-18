import { normalizePagedResponse } from '#/api/helpers';
import { baseRequestClient, requestClient } from '#/api/request';

export interface Asset {
  id: string;
  name: string;
  asset_family?: string;
  address: string;
  region_code?: string;
  region_name?: string;
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
  protocol?: string;
  service?: string;
  version?: string;
  os?: string;
  data_number?: string;
  is_online?: boolean;
  /** 实时探测是否可达（与登记字段 is_online/是否联网 无关） */
  reachable?: boolean | null;
  reachable_checked_at?: string | null;
  is_key?: boolean;
  security_protection_level?: string;
  filing_cert_number?: string;
  icp_filing_number?: string;
  public_security_filing?: string;
  construction_org_id?: string;
  operation_org_id?: string;
  review_status?: string;
  data_source?: string;
  responsible_user_id?: string;
  responsible_user_name?: string;
  risk_score?: number;
  vuln_count?: number;
  events_count?: number;
  circular_count?: number;
  last_scan_at?: string;
  ssl_expires_at?: string;
  domain_expires_at?: string;
  extra?: Record<string, any>;
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
  return normalizePagedResponse<Asset>(res);
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

/** 轻量可用性探测并刷新 reachable（仅当前页 assetIds 时最快）。 */
export function syncAssetOnlineStatus(
  params?: Record<string, unknown>,
  assetIds?: string[],
) {
  const body = assetIds?.length ? { asset_ids: assetIds } : undefined;
  return requestClient.post<{
    checked: number;
    offline: number;
    online: number;
    skipped: number;
    duration_ms?: number;
  }>('/asset/sync-online-status', body, { params });
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
  asset_vulns: { id: string; title: string; severity: string; status: string; target: string; created_at: string }[];
  scan_history: { id: string; name: string; status: string; created_at: string; finished_at?: string }[];
  services: { service_name: string; version: string; port: string; protocol?: string; count: number }[];
  monitor_tasks: { id: string; task_name: string; target_homepage: string; enabled: boolean; next_run_at?: string }[];
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
  key_assets: number;
  risk_high: number;
  with_vulns: number;
  by_type: { type: string; count: number }[];
  by_group: { group_id: string; count: number }[];
}

export async function getAssetStats(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/asset/stats', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  return (body as { data?: AssetStats }).data;
}

export function aggregateAssets() {
  return requestClient.post('/asset/aggregate');
}

export function batchAssignGroup(assetIds: string[], groupId: string) {
  return requestClient.post('/asset/batch-assign', { asset_ids: assetIds, group_id: groupId });
}

export function batchUpdateAssets(ids: string[], updates: Record<string, any>) {
  return requestClient.post('/asset/batch-update', { ids, updates });
}

export function batchDeleteAssets(ids: string[]) {
  return requestClient.post<{ affected: number }>('/asset/batch-delete', { ids });
}

export function importAssets(file: File) {
  const formData = new FormData();
  formData.append('file', file);
  return requestClient.post('/asset/import', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
}

function blobFromAxiosResponse(res: { data?: unknown }): Blob {
  const raw = res?.data;
  if (raw instanceof Blob) {
    return raw;
  }
  if (typeof raw === 'string' || raw instanceof ArrayBuffer) {
    return new Blob([raw]);
  }
  throw new Error('文件下载响应格式异常');
}

/** 下载资产导入模板（需携带鉴权头，勿用直链） */
export async function downloadImportTemplate(): Promise<Blob> {
  const res = await baseRequestClient.get('/asset/import/template', {
    responseType: 'blob',
  });
  return blobFromAxiosResponse(res);
}

export async function exportAssets(
  params?: Record<string, any>,
  format: 'csv' | 'xlsx' = 'xlsx',
): Promise<Blob> {
  const res = await baseRequestClient.get('/asset/export', {
    params: { ...params, format },
    responseType: 'blob',
  });
  return blobFromAxiosResponse(res);
}

export interface RiskTrendItem {
  recorded_at: string;
  score: number;
  vuln_score: number;
  exposure_score: number;
  alert_score: number;
  ssl_score: number;
}

export function getAssetRiskTrend(assetId: string) {
  return requestClient.get<RiskTrendItem[]>(`/asset/${assetId}/risk-trend`);
}

export interface RiskRankingItem {
  id: string;
  name: string;
  risk_score: number;
  vuln_count: number;
  asset_family: string;
}

export function getRiskRanking(params?: Record<string, any>) {
  return requestClient.get<RiskRankingItem[]>('/asset/risk-ranking', { params });
}

export interface AssetEnrichRunResult {
  asset_id?: string;
  task_id: string;
  status: string;
  template: string;
  split_mode?: boolean;
  sub_count?: number;
  target_count?: number;
  skipped?: number;
  engine_enrich?: boolean;
}

export function enrichAsset(assetId: string) {
  return requestClient.post<AssetEnrichRunResult>(`/asset/${assetId}/enrich-run`);
}

export function batchEnrichAssets(assetIds: string[]) {
  return requestClient.post<AssetEnrichRunResult>('/asset/batch-enrich', { ids: assetIds });
}

export function recalcAssetRisk(assetId: string) {
  return requestClient.post(`/asset/${assetId}/risk-calc`);
}

export function recalcAllRisk() {
  return requestClient.post('/asset/risk-recalc-all');
}

export function dedupAssets() {
  return requestClient.post('/asset/dedup');
}

export function importFromCyberspace(data: Record<string, any>) {
  return requestClient.post('/asset/import-cyberspace', data);
}

export function getComplianceReport(params?: Record<string, any>) {
  return requestClient.get('/asset/compliance-report', { params });
}
