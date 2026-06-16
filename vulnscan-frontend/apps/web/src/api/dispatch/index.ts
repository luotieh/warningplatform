import { baseRequestClient, requestClient } from '#/api/request';
import { normalizePagedResponse } from '#/api/helpers';

// ─── 状态枚举 ───

export type DispatchStatus =
  | 'draft'
  | 'pending'
  | 'rejected'
  | 'in_progress'
  | 'submitted'
  | 'reviewing'
  | 'completed'
  | 'cancelled'
  | 'overdue';

export const DispatchStatusLabels: Record<DispatchStatus, string> = {
  draft: '草稿',
  pending: '待接收',
  rejected: '已拒绝',
  in_progress: '处理中',
  submitted: '已提交',
  reviewing: '审核中',
  completed: '已完成',
  cancelled: '已取消',
  overdue: '已逾期',
};

export const DispatchStatusTypes: Record<DispatchStatus, string> = {
  draft: 'default',
  pending: 'warning',
  rejected: 'error',
  in_progress: 'info',
  submitted: 'success',
  reviewing: 'warning',
  completed: 'success',
  cancelled: 'default',
  overdue: 'error',
};

// ─── 类型枚举 ───

export type DispatchType =
  | 'vuln_retest'
  | 'security_fix'
  | 'pentest'
  | 'audit'
  | 'custom';

export const DispatchTypeLabels: Record<DispatchType, string> = {
  vuln_retest: '漏洞复测',
  security_fix: '安全整改',
  pentest: '渗透测试',
  audit: '安全审计',
  custom: '自定义',
};

// ─── 优先级 ───

export const PriorityLabels: Record<number, string> = {
  1: '最低',
  2: '低',
  3: '中',
  4: '高',
  5: '紧急',
};

export const PriorityColors: Record<number, string> = {
  1: '#8c8c8c',
  2: '#52c41a',
  3: '#1890ff',
  4: '#fa8c16',
  5: '#f5222d',
};

// ─── 来源类型 ───

export type DispatchSourceType =
  | 'vuln'
  | 'finding'
  | 'incident'
  | 'task'
  | 'manual';

export const SourceTypeLabels: Record<DispatchSourceType, string> = {
  vuln: '漏洞',
  finding: '扫描发现',
  incident: '安全事件',
  task: '扫描任务',
  manual: '手动创建',
};

// ─── 接口类型定义 ───

export interface DispatchOrder {
  id: string;
  code: string;
  title: string;
  description: string;
  type: DispatchType;
  priority: number;
  status: DispatchStatus;
  source_type: DispatchSourceType;
  source_id: string;
  source_title: string;
  assignee_type: 'internal' | 'external';
  assignee_id: string;
  assignee_name: string;
  assignee_contact: string;
  deadline: string | null;
  accepted_at: string | null;
  submitted_at: string | null;
  completed_at: string | null;
  result: string;
  result_data: Record<string, any> | null;
  attachments: Record<string, any> | null;
  reviewer_id: string;
  review_comment: string;
  reviewed_at: string | null;
  reject_reason: string;
  created_by: string;
  organize_id: string;
  created_at: string;
  updated_at: string;
}

export interface DispatchContact {
  id: string;
  name: string;
  company: string;
  role: string;
  email: string;
  phone: string;
  tags: string[];
  note: string;
  created_by: string;
  organize_id: string;
  created_at: string;
  updated_at: string;
}

export interface DispatchOplog {
  id: number;
  order_id: string;
  action: string;
  operator: string;
  content: string;
  data: Record<string, any> | null;
  created_at: string;
}

export interface StatsOverview {
  total: number;
  by_status: Record<string, number>;
  by_type: Record<string, number>;
  by_priority: Record<string, number>;
  overdue: number;
  avg_days_to_complete: number;
}

// ─── 派发单 API ───

export async function getOrderList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/dispatch/orders', { params });
  return normalizePagedResponse<DispatchOrder>(res);
}

export function getOrderDetail(id: string) {
  return requestClient.get<DispatchOrder>(`/dispatch/orders/${id}`);
}

export function createOrder(data: Record<string, any>) {
  return requestClient.post<DispatchOrder>('/dispatch/orders', data);
}

export function cancelOrder(id: string) {
  return requestClient.post(`/dispatch/orders/${id}/cancel`);
}

export function assignOrder(id: string, data: Record<string, any>) {
  return requestClient.post(`/dispatch/orders/${id}/assign`, data);
}

export function acceptOrder(id: string) {
  return requestClient.post(`/dispatch/orders/${id}/accept`);
}

export function rejectOrder(id: string, reason: string) {
  return requestClient.post(`/dispatch/orders/${id}/reject`, { reason });
}

export function submitResult(id: string, data: Record<string, any>) {
  return requestClient.post(`/dispatch/orders/${id}/submit`, data);
}

export function reviewOrder(id: string, data: { approved: boolean; comment: string }) {
  return requestClient.post(`/dispatch/orders/${id}/review`, data);
}

export function getOrderOplogs(id: string) {
  return requestClient.get<DispatchOplog[]>(`/dispatch/orders/${id}/oplogs`);
}

// ─── 统计 API ───

export function getDispatchStats() {
  return requestClient.get<StatsOverview>('/dispatch/stats');
}

// ─── IAM 用户选择 ───

export interface IAMUser {
  user_id: string;
  account: string;
  name?: string;
  email?: string;
  phone?: string;
  organize_id?: string;
}

export async function getIAMUserList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/system/users', { params });
  const body = res?.data ?? res;
  const items: IAMUser[] = body?.data ?? body?.items ?? body?.list ?? [];
  const total = Number(body?.total ?? body?.count ?? items.length);
  return { items, total };
}

// ─── 联系人 API ───

export async function getContactList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/dispatch/contacts', { params });
  return normalizePagedResponse<DispatchContact>(res);
}

export function getContactDetail(id: string) {
  return requestClient.get<DispatchContact>(`/dispatch/contacts/${id}`);
}

export function createContact(data: Record<string, any>) {
  return requestClient.post<DispatchContact>('/dispatch/contacts', data);
}

export function updateContact(id: string, data: Record<string, any>) {
  return requestClient.put(`/dispatch/contacts/${id}`, data);
}

export function deleteContact(id: string) {
  return requestClient.delete(`/dispatch/contacts/${id}`);
}
