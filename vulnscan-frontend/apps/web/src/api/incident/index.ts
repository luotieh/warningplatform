import { baseRequestClient, requestClient } from '#/api/request';

// ─── Interfaces ───────────────────────────────────────────────

export interface SecurityIncident {
  id: string;
  incident_no: string;
  name: string;
  description?: string;
  status: number; // 1=待审核 2=AI预审中 3=待人工审核 4=审核通过 5=审核不通过 6=整改中 7=已关闭
  level: number; // 1=低 2=中 3=高 4=紧急
  source_system?: string;
  source_ip?: string;
  target_ip?: string;
  target_port?: number;
  attack_type?: string;
  event_time?: string;
  ai_pre_status?: number;
  ai_opinion?: string;
  ai_confidence?: number;
  risk_score?: number;
  ai_tags?: string[];
  ai_category?: string;
  sla_level?: string;
  sla_deadline?: string;
  remediation_plan?: string;
  remediation_result?: string;
  remediation_status?: number;
  remediation_deadline?: string;
  remediation_submitted_at?: string;
  verified_at?: string;
  closed_at?: string;
  asset_id?: string;
  reporter?: string;
  assignee?: string;
  created_at: string;
  updated_at?: string;
}

export interface IncidentComment {
  id: string;
  incident_id: string;
  content: string;
  author: string;
  parent_id?: string;
  created_at: string;
}

export interface KnowledgeArticle {
  id: string;
  title: string;
  category: string;
  content: string;
  tags?: string[];
  author?: string;
  status?: number;
  view_count?: number;
  created_at: string;
  updated_at?: string;
}

export interface OpLog {
  id: string;
  incident_id: string;
  action: string;
  operator: string;
  detail?: string;
  created_at: string;
}

export interface DashboardStats {
  total: number;
  pending_audit: number;
  in_remediation: number;
  closed: number;
  overdue: number;
  ai_auditing?: number;
  passed?: number;
  failed?: number;
}

export interface SLAOverview {
  total: number;
  within_sla: number;
  breached: number;
  breach_rate?: number;
  avg_resolve_time?: number;
  items?: any[];
}

export interface IncidentAssetReq {
  asset_name?: string;
  system_name?: string;
  domain_ip?: string;
  site_ip?: string;
  unit?: string;
  unit_type?: string;
  industry?: string;
  mlps_record_no?: string;
  mlps_level?: string;
  miit_record_no?: string;
  region?: string;
}

export interface IncidentMetaReq {
  data_no?: string;
  incident_type?: string;
  incident_url?: string;
  discovery_time?: string;
  vendor_region?: string;
  incident_description?: string;
  vendor_name?: string;
  vendor_time?: string;
  affected_count?: string;
  affected_type?: string;
  cvss_score?: number;
  cve_id?: string;
  owasp_category?: string;
  exploit_difficulty?: string;
  affect_scope?: string;
}

export interface CreateIncidentReq {
  name: string;
  level: number;
  source: number;
  report_time?: string;
  asset?: IncidentAssetReq;
  metadata?: IncidentMetaReq;
}

// ─── Core CRUD ────────────────────────────────────────────────

export async function getIncidentList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/incident/incidents', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: SecurityIncident[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}

export function createIncident(data: CreateIncidentReq) {
  return requestClient.post('/incident/incidents', data);
}

export function getIncidentDetail(id: string) {
  return requestClient.get<SecurityIncident>(`/incident/incidents/${id}`);
}

export function updateIncident(id: string, data: Partial<SecurityIncident>) {
  return requestClient.put(`/incident/incidents/${id}`, data);
}

export function deleteIncident(id: string) {
  return requestClient.delete(`/incident/incidents/${id}`);
}

// ─── AI / Audit ───────────────────────────────────────────────

export function aiPreAudit(id: string) {
  return requestClient.post(`/incident/incidents/${id}/ai-pre-audit`);
}

export function manualAudit(id: string, data: { passed: boolean; opinion?: string }) {
  return requestClient.post(`/incident/incidents/${id}/manual-audit`, data);
}

export function aiClassify(id: string) {
  return requestClient.post(`/incident/incidents/${id}/ai-classify`);
}

// ─── Remediation ──────────────────────────────────────────────

export function submitRemediation(id: string, data: { plan?: string; result?: string }) {
  return requestClient.post(`/incident/incidents/${id}/remediation`, data);
}

export function verifyRemediation(id: string, data?: { passed?: boolean; comment?: string }) {
  return requestClient.post(`/incident/incidents/${id}/verify-remediation`, data);
}

export function closeIncident(id: string, data?: { comment?: string }) {
  return requestClient.post(`/incident/incidents/${id}/close`, data);
}

// ─── Import / Export ──────────────────────────────────────────

export function importIncidents(file: File) {
  const formData = new FormData();
  formData.append('file', file);
  return requestClient.post('/incident/incidents/import', formData);
}

export function downloadImportTemplate() {
  return baseRequestClient.get('/incident/incidents/import-template', {
    responseType: 'blob',
  });
}

export function exportBatch(params?: { ids?: string[]; status?: number; level?: number }) {
  return baseRequestClient.post('/incident/incidents/export-batch', params, {
    responseType: 'blob',
  });
}

export function exportSingle(id: string) {
  return baseRequestClient.get(`/incident/incidents/export-single`, {
    params: { id },
    responseType: 'blob',
  });
}

// ─── Dashboard ────────────────────────────────────────────────

export function getDashboardStats() {
  return requestClient.get<DashboardStats>('/incident/dashboard/stats');
}

export function getChartByType(params?: Record<string, any>) {
  return requestClient.get('/incident/dashboard/chart/type', { params });
}

export function getChartByTrend(params?: Record<string, any>) {
  return requestClient.get('/incident/dashboard/chart/trend', { params });
}

// ─── Stats ────────────────────────────────────────────────────

export function getRemediationStats(params?: Record<string, any>) {
  return requestClient.get('/incident/stats/remediation', { params });
}

export function getOverdueList(params?: Record<string, any>) {
  return requestClient.get('/incident/stats/overdue', { params });
}

export function getMultiDimAnalysis(params?: Record<string, any>) {
  return requestClient.get('/incident/stats/analysis', { params });
}

export function generateReport(params?: Record<string, any>) {
  return requestClient.get('/incident/stats/report', { params });
}

export function getTrendPrediction(params?: Record<string, any>) {
  return requestClient.get('/incident/stats/trend-prediction', { params });
}

export function getAIAnalysis(params?: Record<string, any>) {
  return requestClient.get('/incident/stats/ai-analysis', { params });
}

// ─── Comments ─────────────────────────────────────────────────

export function createComment(data: { incident_id: string; content: string; parent_id?: string }) {
  return requestClient.post('/incident/comments', data);
}

export async function getCommentList(params: { incident_id: string } & Record<string, any>) {
  const res = await baseRequestClient.get<any>('/incident/comments', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: IncidentComment[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}

export function deleteComment(id: string) {
  return requestClient.delete(`/incident/comments/${id}`);
}

// ─── SLA ──────────────────────────────────────────────────────

export function getSLAOverview(params?: Record<string, any>) {
  return requestClient.get<SLAOverview>('/incident/sla/overview', { params });
}

export function setSLA(data: { incident_id?: string; level?: string; deadline?: string }) {
  return requestClient.post('/incident/sla/set', data);
}

export function checkSLA(params?: Record<string, any>) {
  return requestClient.post('/incident/sla/check', params);
}

// ─── Assets ───────────────────────────────────────────────────

export function getAssetProfile(params: { asset_id: string } & Record<string, any>) {
  return requestClient.get('/incident/assets/profile', { params });
}

export function getAssetSummary(params?: Record<string, any>) {
  return requestClient.get('/incident/assets/summary', { params });
}

// ─── Knowledge ────────────────────────────────────────────────

export async function getKnowledgeList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/incident/knowledge', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: KnowledgeArticle[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}

export function createKnowledge(data: Partial<KnowledgeArticle>) {
  return requestClient.post('/incident/knowledge', data);
}

export function getKnowledgeDetail(id: string) {
  return requestClient.get<KnowledgeArticle>(`/incident/knowledge/${id}`);
}

export function updateKnowledge(id: string, data: Partial<KnowledgeArticle>) {
  return requestClient.put(`/incident/knowledge/${id}`, data);
}

export function deleteKnowledge(id: string) {
  return requestClient.delete(`/incident/knowledge/${id}`);
}

export function getKnowledgeRecommend(params?: Record<string, any>) {
  return requestClient.get('/incident/knowledge/recommend', { params });
}

export function archiveKnowledge(id: string) {
  return requestClient.post(`/incident/knowledge/archive`, { id });
}

// ─── Oplogs ───────────────────────────────────────────────────

export async function getOplogList(params: { incident_id: string } & Record<string, any>) {
  const res = await baseRequestClient.get<any>('/incident/oplogs', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: OpLog[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}
