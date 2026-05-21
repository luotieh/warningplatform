import { baseRequestClient, requestClient } from '#/api/request';
import { normalizePagedResponse } from '#/api/helpers';

// ─── 通报状态枚举 ───

export type CircularStatus =
  | 'to_be_submit'
  | 'to_be_verified'
  | 'to_be_distributed'
  | 'to_be_processed'
  | 'to_be_reviewed'
  | 'rejected'
  | 'completed'
  | 'time_out'
  | 'in_progress'
  | 'redistributed'
  | 'disposed'
  | 'reviewed';

export const CircularStatusLabels: Record<CircularStatus, string> = {
  to_be_submit: '待提交',
  to_be_verified: '待核验',
  to_be_distributed: '待派发',
  to_be_processed: '待处置',
  to_be_reviewed: '待审核',
  rejected: '已驳回',
  completed: '已归档',
  time_out: '已超时',
  in_progress: '处置中',
  redistributed: '已转派',
  disposed: '已处置',
  reviewed: '已审核',
};

export const CircularStatusTypes: Record<CircularStatus, string> = {
  to_be_submit: 'default',
  to_be_verified: 'warning',
  to_be_distributed: 'info',
  to_be_processed: 'warning',
  to_be_reviewed: 'info',
  rejected: 'error',
  completed: 'success',
  time_out: 'error',
  in_progress: 'warning',
  redistributed: 'info',
  disposed: 'success',
  reviewed: 'success',
};

// ─── 危害等级枚举 ───

export type HazardLevel = 'low' | 'medium' | 'high' | 'critical';

export const HazardLevelLabels: Record<HazardLevel, string> = {
  low: '低危',
  medium: '中危',
  high: '高危',
  critical: '危急',
};

export const HazardLevelColors: Record<HazardLevel, { bg: string; fg: string }> = {
  low: { bg: '#f6ffed', fg: '#389e0d' },
  medium: { bg: '#fffbe6', fg: '#d4b106' },
  high: { bg: '#fff7e6', fg: '#d46b08' },
  critical: { bg: '#fff1f0', fg: '#cf1322' },
};

// ─── 模板类型枚举 ───

export type CircularDataSource =
  | 'manual_input'
  | 'third_party_import'
  | 'template_import'
  | 'superior_transfer';

export const DataSourceLabels: Record<CircularDataSource, string> = {
  manual_input: '手动录入',
  third_party_import: '第三方导入',
  template_import: '模板导入',
  superior_transfer: '上级流转',
};

// ─── 操作类型枚举 ───

export type CircularOperationType =
  | 'input'
  | 'import'
  | 'submit'
  | 'third_party_import'
  | 'verify_pass'
  | 'verify_reject'
  | 'distribute'
  | 'redistribute'
  | 'disposal'
  | 'review_approve'
  | 'review_reject'
  | 'completed';

export const OperationTypeLabels: Record<CircularOperationType, string> = {
  input: '录入',
  import: '导入',
  submit: '提交核验',
  third_party_import: '第三方导入',
  verify_pass: '核验通过',
  verify_reject: '核验驳回',
  distribute: '派发',
  redistribute: '转派',
  disposal: '处置',
  review_approve: '审核通过',
  review_reject: '审核驳回',
  completed: '归档',
};

// ─── 接口类型定义 ───

export interface CircularItem {
  id: string;
  code: string;
  title: string;
  custom_code?: string;
  source: CircularDataSource;
  organize: string;
  disposal_organize?: string;
  distribution_time?: string;
  processing_deadline?: string;
  circular_template: string;
  circular_data?: Record<string, any>[];
  disposal_template?: string;
  disposal_data?: Record<string, any>[];
  status: CircularStatus;
  created_at: string;
  updated_at: string;
  created_by?: string;
  updated_by?: string;
  organize_status_list?: CircularOrganizeStatus[];
}

export interface CircularOrganizeStatus {
  id: number;
  circular_id: string;
  distribution_id?: string;
  organize: string;
  status: CircularStatus;
}

export interface CircularDistribution {
  id: string;
  circular_id: string;
  current_organize: string;
  target_organize: string;
  processing_deadline?: string;
  requirements?: string;
  depth: number;
  parent_distribution_id?: string;
  disposal_data?: string;
  created_at: string;
  created_by?: string;
}

export interface CircularDisposal {
  id: string;
  circular: string;
  current_organize: string;
  target_organize: string;
  disposal_result?: string;
  disposal_time?: string;
  disposal_question?: string;
  created_at: string;
  created_by?: string;
}

export interface CircularReview {
  id: string;
  circular_id: string;
  distribution_id?: string;
  organize: string;
  depth: number;
  review: string;
  instructions?: string;
  annex?: string;
  created_at: string;
  created_by?: string;
}

export interface CircularOplog {
  id: string;
  circular_id: string;
  operation_type: CircularOperationType;
  operator: string;
  operator_name?: string;
  operation_time: string;
  operation_result: string;
  target_organize?: string;
  detail?: string;
  created_at: string;
}

export interface CircularDetailResp {
  id: string;
  code: string;
  title: string;
  custom_code?: string;
  source: CircularDataSource;
  organize: string;
  disposal_organize?: string;
  distribution_time?: string;
  processing_deadline?: string;
  circular_template: string;
  circular_data?: Record<string, any>[];
  disposal_template?: string;
  disposal_data?: Record<string, any>[];
  status: CircularStatus;
  created_at: string;
  updated_at: string;
  created_by?: string;
  organize_status_list?: CircularOrganizeStatus[];
  distributions?: CircularDistribution[];
  disposals?: CircularDisposal[];
  reviews?: CircularReview[];
}

export interface TransferStatusResp {
  incident_no: string;
  circular_id: string;
  circular_code: string;
  status: string;
  transfer_time: string;
}

// ─── 录入 API ───

export async function getInputList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/circular/inputs', { params });
  return normalizePagedResponse<CircularItem>(res);
}

export function createInput(data: Record<string, any>) {
  return requestClient.post('/circular/inputs', data);
}

export function getInputDetail(id: string) {
  return requestClient.get<CircularDetailResp>(`/circular/inputs/${id}`);
}

export function updateInput(id: string, data: Record<string, any>) {
  return requestClient.put(`/circular/inputs/${id}`, data);
}

export function deleteInput(id: string) {
  return requestClient.delete(`/circular/inputs/${id}`);
}

export function submitForVerify(id: string) {
  return requestClient.post(`/circular/inputs/${id}/submit`);
}

export function exportCirculars(data: { codes?: string[] }) {
  return requestClient.post('/circular/inputs/export', data);
}

export function importCirculars(file: File) {
  const formData = new FormData();
  formData.append('file', file);
  return requestClient.post('/circular/inputs/import', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
}

export function getImportTemplateDownloadUrl() {
  return '/api/circular/inputs/template/download';
}

export function thirdPartyImport(data: Record<string, any>) {
  return requestClient.post('/circular/inputs/third-party', data);
}

// ─── 核验 API ───

export async function getVerifyList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/circular/verifications', { params });
  return normalizePagedResponse<CircularItem>(res);
}

export function verifyCircular(data: { circular_ids: string[]; result: string }) {
  return requestClient.post('/circular/verifications', data);
}

// ─── 派发 API ───

export async function getDistributeList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/circular/distributions', { params });
  return normalizePagedResponse<CircularItem>(res);
}

export function distributeCircular(data: {
  circular_id: string;
  target_organize: string;
  processing_deadline?: string;
  requirements?: string;
  disposal_template?: string;
  disposal_data?: Record<string, any>[];
}) {
  return requestClient.post('/circular/distributions', data);
}

// ─── 处置 API ───

export async function getDisposalList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/circular/disposals', { params });
  return normalizePagedResponse<CircularItem>(res);
}

export function disposeCircular(id: string, data: {
  disposal_result?: string;
  disposal_question?: string;
  disposal_data?: Record<string, any>[];
}) {
  return requestClient.post(`/circular/disposals/${id}`, data);
}

export function redistributeCircular(data: {
  circular_id: string;
  distribution_id: string;
  target_organize: string;
  processing_deadline?: string;
  requirements?: string;
}) {
  return requestClient.post('/circular/disposals/redistribute', data);
}

// ─── 审核 API ───

export async function getReviewList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/circular/reviews', { params });
  return normalizePagedResponse<CircularItem>(res);
}

export function reviewCircular(id: string, data: {
  review: string;
  instructions?: string;
  annex?: string;
}) {
  return requestClient.post(`/circular/reviews/${id}`, data);
}

// ─── 台账 API ───

export async function getLedgerList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/circular/ledgers', { params });
  return normalizePagedResponse<CircularItem>(res);
}

export function getLedgerDetail(id: string) {
  return requestClient.get<CircularDetailResp>(`/circular/ledgers/${id}`);
}

// ─── 操作日志 API ───

export function getCircularOplogs(circularId: string) {
  return requestClient.get<CircularOplog[]>(`/circular/oplogs/${circularId}`);
}

// ─── 流转 API ───

export function getTransferStatus(params?: Record<string, any>) {
  return requestClient.get<TransferStatusResp>('/circular/transfers/status', { params });
}

/** 下载由安全事件流转时附带的 Word/PDF 报告（circularId 为通报主键） */
export async function downloadCircularIncidentReport(
  circularId: string,
  format: 'docx' | 'pdf',
) {
  return baseRequestClient.get<Blob>(`/circular/transfers/reports/${circularId}/${format}`, {
    responseType: 'blob',
  });
}
