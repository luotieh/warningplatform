import { requestClient } from '#/api/request';

export interface CVEEntry {
  id: string;
  description: string;
  severity: string;
  cvss_score: number;
  cvss_vector: string;
  cwe: string[];
  cpe: string[];
  references: string[];
  published: string;
  modified: string;
  has_exploit: boolean;
  in_kev: boolean;
  exploit_type: string;
  exploit_urls: string[];
  difficulty: string;
  impact: string;
  epss_score: number;
  epss_percentile: number;
}

export interface IntelSource {
  name: string;
  type: string;
  url: string;
  last_sync: string;
  entry_count: number;
  enabled: boolean;
  sync_interval: string;
  api_key?: string;
  custom: boolean;
}

export interface VulnMatch {
  cve: CVEEntry;
  matched_cpe: string;
  match_type: string;
  confidence: number;
}

export function searchCVE(params: { q?: string; severity?: string; has_exploit?: string; in_kev?: string; page?: number; page_size?: number }) {
  return requestClient.get('/intel/cve', { params });
}

export function getCVEDetail(id: string) {
  return requestClient.get(`/intel/cve/${id}`);
}

export function matchFingerprint(product: string, version?: string) {
  return requestClient.get('/intel/match', { params: { product, version } });
}

export function getSources() {
  return requestClient.get('/intel/sources');
}

export function addSource(data: { name: string; type: string; url: string; sync_interval?: string; api_key?: string; enabled?: boolean }) {
  return requestClient.post('/intel/sources', data);
}

export function updateSource(name: string, data: Partial<{ url: string; sync_interval: string; api_key: string; enabled: boolean }>) {
  return requestClient.put(`/intel/sources/${encodeURIComponent(name)}`, data);
}

export function deleteSource(name: string) {
  return requestClient.delete(`/intel/sources/${encodeURIComponent(name)}`);
}

export function syncNow() {
  return requestClient.post('/intel/sync');
}

export function getIntelStats() {
  return requestClient.get('/intel/stats');
}

export function getTopEPSS(limit = 20) {
  return requestClient.get('/intel/epss/top', { params: { limit } });
}

export function getTrend(dimension: 'time' | 'severity' | 'product' | 'exploit') {
  return requestClient.get('/intel/trend', { params: { dimension } });
}

export interface IOCIndicator {
  id: string;
  type: string;
  value: string;
  threat_type: string;
  severity: string;
  source: string;
  description: string;
  tags: string[];
  expires_at: string | null;
  enabled: boolean;
  hit_count: number;
  last_hit_at: string | null;
  created_at: string;
}

export function listIOC(params?: { type?: string; severity?: string; q?: string }) {
  return requestClient.get('/intel/ioc', { params });
}

export function createIOC(data: { type: string; value: string; threat_type?: string; severity?: string; source?: string; description?: string; tags?: string[]; expires_at?: string }) {
  return requestClient.post('/intel/ioc', data);
}

export function deleteIOC(id: string) {
  return requestClient.delete(`/intel/ioc/${id}`);
}

export function toggleIOC(id: string) {
  return requestClient.post(`/intel/ioc/${id}/toggle`);
}

export function scanAssetsIOC() {
  return requestClient.post('/intel/ioc/scan-assets');
}

export function getIOCStats() {
  return requestClient.get('/intel/ioc/stats');
}

export interface CPEMapping {
  product: string;
  version: string;
  cpe_matches: string[];
}

export function listCPEMappings(q?: string) {
  return requestClient.get('/intel/cpe-mappings', { params: q ? { q } : {} });
}

export function addCPEMapping(data: { product: string; version?: string; cpe_matches: string[] }) {
  return requestClient.post('/intel/cpe-mappings', data);
}

export function updateCPEMapping(product: string, data: { version?: string; cpe_matches?: string[] }) {
  return requestClient.put(`/intel/cpe-mappings/${encodeURIComponent(product)}`, data);
}

export function deleteCPEMapping(product: string) {
  return requestClient.delete(`/intel/cpe-mappings/${encodeURIComponent(product)}`);
}

export function fetchExploit(url: string) {
  return requestClient.get('/intel/exploit/fetch', { params: { url } });
}

export function searchExploits(q: string) {
  return requestClient.get('/intel/exploit/search', { params: { q } });
}

export function analyzeAsset(assetId: string) {
  return requestClient.get(`/intel/analyze/${assetId}`);
}

export function batchAnalyze(assetIds: string[]) {
  return requestClient.post('/intel/analyze/batch', { asset_ids: assetIds });
}

export interface IntelSubscription {
  id: string;
  user_id: string;
  name: string;
  products: string[];
  keywords: string[];
  severities: string[];
  only_exploit: boolean;
  only_kev: boolean;
  enabled: boolean;
  last_match_at: string | null;
  match_count: number;
  created_at: string;
}

export function listSubscriptions() {
  return requestClient.get('/intel/subscriptions');
}

export function createSubscription(data: { name: string; products?: string[]; keywords?: string[]; severities?: string[]; only_exploit?: boolean; only_kev?: boolean }) {
  return requestClient.post('/intel/subscriptions', data);
}

export function updateSubscription(id: string, data: Partial<{ name: string; products: string[]; keywords: string[]; severities: string[]; only_exploit: boolean; only_kev: boolean; enabled: boolean }>) {
  return requestClient.put(`/intel/subscriptions/${id}`, data);
}

export function deleteSubscription(id: string) {
  return requestClient.delete(`/intel/subscriptions/${id}`);
}

export function testSubscription(id: string) {
  return requestClient.get(`/intel/subscriptions/${id}/test`);
}
