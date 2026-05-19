import { baseRequestClient, requestClient } from '#/api/request';
import { normalizePagedResponse } from '#/api/helpers';

// ─── Interfaces ───────────────────────────────────────────────

export interface IncidentAsset {
  id: string;
  asset_name: string;
  system_name: string;
  domain_ip: string;
  site_ip: string;
  unit: string;
  unit_type: string;
  industry: string;
  mlps_record_no: string;
  mlps_level: string;
  miit_record_no: string;
  region: string;
}

export interface IncidentMetadata {
  id: string;
  data_no: string;
  incident_type: string;
  incident_url: string;
  discovery_time: string;
  vendor_region: string;
  vendor_name: string;
  incident_description: string;
  vendor_time: string;
  affected_count: string;
  affected_type: string;
  cvss_score: number;
  cve_id: string;
  owasp_category: string;
  exploit_difficulty: string;
  affect_scope: string;
}

export interface SecurityIncident {
  id: string;
  incident_no: string;
  name: string;
  description?: string;
  level: number;
  source: number;
  status: number;
  status_text?: string;
  report_time?: string;
  ai_pre_status?: number;
  ai_opinion?: string;
  ai_confidence?: number;
  risk_score?: number;
  ai_tags?: string | string[];
  ai_category?: string;
  asset_detail_id?: string;
  event_metadata_id?: string;
  asset_detail?: IncidentAsset;
  event_metadata?: IncidentMetadata;
  remediation_plan?: string;
  remediation_result?: string;
  remediation_deadline?: string;
  remediation_assignee?: string;
  asset_name?: string;
  unit?: string;
  is_overdue?: boolean;
  remediation_submit_at?: string;
  verified_at?: string;
  close_reason?: string;
  closed_at?: string;
  sla_level?: number;
  sla_deadline?: string;
  sla_status?: number;
  sla_escalated_at?: string;
  sla_escalated_to?: string;
  sla_reminder_count?: number;
  sla_last_reminder?: string;
  current_step?: number;
  operation_logs?: OpLog[];
  created_at: string;
  updated_at?: string;
}

export interface IncidentComment {
  id: string;
  incident_id: string;
  content: string;
  author_id: string;
  author_name: string;
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
  incident_no: string;
  operation_type: string;
  operation_type_zh: string;
  operator_id: string;
  operator_name: string;
  operation_time: string;
  result: string;
  detail: string;
  source_system: string;
  source_system_zh: string;
}

export interface DashboardStats {
  total: number;
  pending_audit: number;
  in_remediation: number;
  closed: number;
  overdue: number;
  today_total?: number;
  urgent_count?: number;
  remediation_rate?: number;
  ai_auditing?: number;
  passed?: number;
  failed?: number;
}

export interface ChartTypeItem {
  type: string;
  count: number;
  percentage: string;
}

export interface ChartLevelItem {
  level: number;
  label: string;
  count: number;
  percentage: string;
}

export interface ChartTrendItem {
  period: string;
  date: string;
  created: number;
  closed: number;
  pending: number;
  count?: number;
}

export interface SLAOverview {
  total: number;
  within_sla: number;
  breached: number;
  breach_rate?: number;
  avg_resolve_time?: number;
  items?: any[];
}

export interface RemediationStats {
  total_count: number;
  remediated_count: number;
  overdue_count: number;
  remediation_rate: number;
  overdue_rate: number;
  avg_remediation_day: number;
  closed_count: number;
  verifying_count: number;
}

export interface MultiDimItem {
  dimension: string;
  value: string;
  count: number;
}

export interface TrendPoint {
  date: string;
  count: number;
}

export interface TrendPrediction {
  historical: TrendPoint[];
  predicted: TrendPoint[];
  algorithm: string;
  confidence: number;
}

export interface HotCategory {
  name: string;
  count: number;
  ratio: number;
}

export interface AIAnalysisSummary {
  overall_risk: string;
  risk_score: number;
  summary: string;
  top_risk_areas: string[];
  trend_direction: string;
  recommendations: string[];
  hot_categories: HotCategory[];
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
  return normalizePagedResponse<SecurityIncident>(res);
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
  return requestClient.get<ChartTypeItem[]>('/incident/dashboard/chart/type', { params });
}

export function getChartByLevel(params?: Record<string, any>) {
  return requestClient.get<ChartLevelItem[]>('/incident/dashboard/chart/level', { params });
}

export function getChartByTrend(params?: Record<string, any>) {
  return requestClient.get<ChartTrendItem[]>('/incident/dashboard/chart/trend', { params });
}

// ─── Stats ────────────────────────────────────────────────────

export function getRemediationStats(params?: Record<string, any>) {
  return requestClient.get<RemediationStats>('/incident/stats/remediation', { params });
}

export async function getOverdueList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/incident/stats/overdue', { params });
  return normalizePagedResponse<SecurityIncident>(res);
}

export function getMultiDimAnalysis(params?: Record<string, any>) {
  return requestClient.get<MultiDimItem[]>('/incident/stats/analysis', { params });
}

export function downloadIncidentReport(params?: Record<string, any>) {
  return requestClient.download<Blob>('/incident/stats/report', { params });
}

export function getTrendPrediction(params?: Record<string, any>) {
  return requestClient.get<TrendPrediction>('/incident/stats/trend-prediction', { params });
}

export function getAIAnalysis(params?: Record<string, any>) {
  return requestClient.get<AIAnalysisSummary>('/incident/stats/ai-analysis', { params });
}

// ─── Comments ─────────────────────────────────────────────────

export function createComment(data: { incident_id: string; content: string; parent_id?: string }) {
  return requestClient.post('/incident/comments', data);
}

export async function getCommentList(params: { incident_id: string } & Record<string, any>) {
  const res = await baseRequestClient.get<any>('/incident/comments', { params });
  return normalizePagedResponse<IncidentComment>(res);
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
  return normalizePagedResponse<KnowledgeArticle>(res);
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
  return normalizePagedResponse<OpLog>(res);
}

// ─── 流转到通报 ───

export interface TransferToCircularReq {
  incident_no: string;
  name: string;
  level?: number;
  ai_opinion?: string;
  ai_confidence?: number;
  asset_info?: {
    asset_name?: string;
    system_name?: string;
    domain_ip?: string;
    site_ip?: string;
    unit?: string;
    unit_type?: string;
    industry?: string;
    mlps_record_no?: string;
    mlps_level?: string;
    region?: string;
  };
  metadata_info?: {
    data_no?: string;
    incident_type?: string;
    incident_url?: string;
    incident_description?: string;
    cvss_score?: number;
    cve_id?: string;
  };
  source_system?: string;
}

export function transferToCircular(data: TransferToCircularReq) {
  return requestClient.post<{ circular_code: string }>('/circular/transfers', data);
}
