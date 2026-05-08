import { requestClient, baseRequestClient } from '#/api/request';

// ── 标签 ──

export interface Tag {
  id: number;
  name: string;
  color: string;
  category: string;
  is_auto: boolean;
}

export function getTagList(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/tagging/tags/list', { params });
}

export function createTag(data: Partial<Tag>) {
  return requestClient.post('/tagging/tags', data);
}

export function updateTag(id: number, data: Partial<Tag>) {
  return requestClient.put(`/tagging/tags/${id}`, data);
}

export function deleteTag(id: number) {
  return requestClient.delete(`/tagging/tags/${id}`);
}

export function getAssetTags(assetId: string) {
  return requestClient.get(`/tagging/asset-tags/${assetId}`);
}

export function setAssetTags(assetId: string, tagIds: number[]) {
  return requestClient.post('/tagging/asset-tags', { asset_id: assetId, tag_ids: tagIds });
}

// ── 变更日志 ──

export function getChangeLogs(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/tagging/changelogs/list', { params });
}

export function getAssetChangeLogs(assetId: string) {
  return requestClient.get(`/tagging/changelogs/${assetId}`);
}

// ── 组织管理 ──

export interface Organize {
  id: string;
  parent_id: string;
  name: string;
  unified_social_credit_code: string;
  industry_category: string;
  unit_type: string;
  address: string;
  contact_name: string;
  contact_phone: string;
  asset_count: number;
}

export function getOrganizeList(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/organize/list', { params });
}

export function getOrganizeTree() {
  return requestClient.get('/organize/tree');
}

export function createOrganize(data: Partial<Organize>) {
  return requestClient.post('/organize', data);
}

export function updateOrganize(id: string, data: Partial<Organize>) {
  return requestClient.put(`/organize/${id}`, data);
}

export function deleteOrganize(id: string) {
  return requestClient.delete(`/organize/${id}`);
}

// ── 建设运维单位 ──

export interface ConstructionOrg {
  id: string;
  name: string;
  location: string;
  address: string;
  charge_person: string;
  charge_phone: string;
  security_filing: string;
  used: number;
}

export function getConstructionList(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/organize/construction/list', { params });
}

export function createConstruction(data: Partial<ConstructionOrg>) {
  return requestClient.post('/organize/construction', data);
}

export function updateConstruction(id: string, data: Partial<ConstructionOrg>) {
  return requestClient.put(`/organize/construction/${id}`, data);
}

export function deleteConstruction(id: string) {
  return requestClient.delete(`/organize/construction/${id}`);
}

// ── 生命周期 ──

export function getLifecycleList(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/assetmgr/lifecycle/list', { params });
}

export function lifecycleTransition(data: { asset_id: string; to_state: string; remark?: string }) {
  return requestClient.post('/assetmgr/lifecycle/transition', data);
}

// ── 风险评估 ──

export interface RiskScore {
  id: number;
  asset_id: string;
  total_score: number;
  exposure_score: number;
  vuln_score: number;
  compliance_score: number;
  open_ports: number;
  vuln_count: number;
  critical_vulns: number;
}

export function getRiskList(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/assetmgr/risk/list', { params });
}

export function getAssetRisk(assetId: string) {
  return requestClient.get(`/assetmgr/risk/${assetId}`);
}

export function recalculateRisk(assetId: string) {
  return requestClient.post(`/assetmgr/risk/${assetId}/recalculate`);
}

export function recalculateAllRisk() {
  return requestClient.post('/assetmgr/risk/recalculate-all');
}

// ── 安全告警 ──

export interface Alert {
  id: string;
  asset_id: string;
  alert_type: string;
  severity: string;
  title: string;
  description: string;
  source: string;
  status: string;
  acked_by: string;
  acked_at: string;
  resolved_at: string;
}

export function getAlertList(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/assetmgr/alert/list', { params });
}

export function createAlert(data: Partial<Alert>) {
  return requestClient.post('/assetmgr/alert', data);
}

export function ackAlert(id: string) {
  return requestClient.put(`/assetmgr/alert/${id}/ack`);
}

export function resolveAlert(id: string) {
  return requestClient.put(`/assetmgr/alert/${id}/resolve`);
}

// ── 审核 ──

export function getVerifyList(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/assetmgr/verify/list', { params });
}

export function submitVerify(data: { asset_id: string }) {
  return requestClient.post('/assetmgr/verify', data);
}

export function reviewVerify(id: string, data: { review_status: string; review_remark?: string }) {
  return requestClient.put(`/assetmgr/verify/${id}/review`, data);
}

// ── 合规 ──

export function getComplianceList(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/assetmgr/compliance/items/list', { params });
}

export function createComplianceItem(data: Record<string, any>) {
  return requestClient.post('/assetmgr/compliance/items', data);
}

export function getComplianceTemplates(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/assetmgr/compliance/templates/list', { params });
}

export function getComplianceTemplateDetail(id: number) {
  return requestClient.get(`/assetmgr/compliance/templates/${id}`);
}

export function createComplianceTemplate(data: Record<string, any>) {
  return requestClient.post('/assetmgr/compliance/templates', data);
}

export function getCheckResults(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/assetmgr/compliance/results/list', { params });
}

export function submitCheckResult(data: Record<string, any>) {
  return requestClient.post('/assetmgr/compliance/results', data);
}

// ── 责任人 ──

export function getResponsibleList(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/assetmgr/responsible/list', { params });
}

export function createResponsible(data: Record<string, any>) {
  return requestClient.post('/assetmgr/responsible', data);
}

export function updateResponsible(id: number, data: Record<string, any>) {
  return requestClient.put(`/assetmgr/responsible/${id}`, data);
}

export function deleteResponsible(id: number) {
  return requestClient.delete(`/assetmgr/responsible/${id}`);
}

// ── 集成 ──

export function getIntegrationSources(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/assetmgr/integration/sources/list', { params });
}

export function createIntegrationSource(data: Record<string, any>) {
  return requestClient.post('/assetmgr/integration/sources', data);
}

export function updateIntegrationSource(id: number, data: Record<string, any>) {
  return requestClient.put(`/assetmgr/integration/sources/${id}`, data);
}

export function deleteIntegrationSource(id: number) {
  return requestClient.delete(`/assetmgr/integration/sources/${id}`);
}

// ── 工作流 ──

export function getWorkflowList(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/assetmgr/workflow/list', { params });
}

export function createWorkflow(data: Record<string, any>) {
  return requestClient.post('/assetmgr/workflow', data);
}

export function updateWorkflow(id: string, data: Record<string, any>) {
  return requestClient.put(`/assetmgr/workflow/${id}`, data);
}

export function deleteWorkflow(id: string) {
  return requestClient.delete(`/assetmgr/workflow/${id}`);
}

export function getWorkflowExecutions(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/assetmgr/workflow/executions', { params });
}
