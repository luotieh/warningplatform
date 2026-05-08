import { baseRequestClient, requestClient } from '#/api/request';

// ========== 公告 ==========
export interface AnnouncementItem {
  id: string;
  title: string;
  content: string;
  priority: number | string;
  status: string;
  require_ack: boolean;
  channels: string;
  category?: string;
  target?: string;
  pinned?: boolean;
  publish_at: string | null;
  published_at: string;
  expire_at: string | null;
  created_at: string;
  updated_at: string;
  read_count?: number;
  ack_count?: number;
  is_read?: boolean;
  is_acked?: boolean;
}

export interface AnnouncementQuery {
  status?: string;
  priority?: string;
  keyword?: string;
  index?: number;
  size?: number;
}

export interface AnnouncementCreateReq {
  title: string;
  content: string;
  priority?: number | string;
  pinned?: boolean;
  category?: string;
  require_ack?: boolean;
  target?: string;
  target_ids?: string;
  channels?: string[];
  expire_at?: string;
}

export async function getAnnouncementList(params?: AnnouncementQuery) {
  const res = await baseRequestClient.get<{ data: AnnouncementItem[]; count: number }>('/messages/announcements', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: AnnouncementItem[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}
export function getAnnouncementDetail(id: string) { return requestClient.get<AnnouncementItem>(`/messages/announcements/${id}`); }
export function createAnnouncement(data: AnnouncementCreateReq) { return requestClient.post('/messages/announcements', data); }
export function updateAnnouncement(id: string, data: Partial<AnnouncementCreateReq>) { return requestClient.put(`/messages/announcements/${id}`, data); }
export function deleteAnnouncement(id: string) { return requestClient.delete(`/messages/announcements/${id}`); }
export function publishAnnouncement(id: string) { return requestClient.post(`/messages/announcements/${id}/publish`); }
export function revokeAnnouncement(id: string) { return requestClient.post(`/messages/announcements/${id}/revoke`); }
export function markAnnouncementRead(id: string) { return requestClient.post(`/messages/announcements/${id}/read`); }
export function ackAnnouncement(id: string) { return requestClient.post(`/messages/announcements/${id}/ack`); }
export async function getPublishedAnnouncements(params?: AnnouncementQuery) {
  const res = await baseRequestClient.get<{ data: AnnouncementItem[]; count: number }>('/messages/announcements/published', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: AnnouncementItem[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}

// ========== 渠道 ==========
/**
 * 渠道限流配置（与后端 RateLimitConfig 对齐）
 */
export interface ChannelRateLimit {
  max_per_second?: number;
  max_per_minute?: number;
  max_per_hour?: number;
  max_per_day?: number;
}

/**
 * 渠道（与后端 MessageChannel 对齐）
 *
 * 注意：name 既是唯一标识也是渠道类型（如 email/sms/inapp/wecom 等）
 * 真实的连接配置（SMTP/AccessKey/CorpID）请到「平台 → 提供商」配置
 */
export interface ChannelItem {
  id?: number;
  name: string;
  enabled: boolean;
  config?: Record<string, unknown>;
  rate_limit?: ChannelRateLimit;
  created_at?: string;
  updated_at?: string;
}

export interface ChannelCreateReq {
  name: string;
  enabled?: boolean;
  config?: Record<string, unknown>;
  rate_limit?: ChannelRateLimit;
}

export interface ChannelUpdateReq {
  enabled?: boolean;
  config?: Record<string, unknown>;
  rate_limit?: ChannelRateLimit;
}

export async function getChannelList(_params?: any) {
  const res = await baseRequestClient.get<any>('/messages/channels');
  const body = res.data ?? res;
  // 后端 List 返回直接是数组（不分页）
  const list: ChannelItem[] = Array.isArray(body?.data)
    ? body.data
    : Array.isArray(body)
      ? body
      : [];
  return { items: list, total: list.length };
}

export function getChannelDetail(name: string) {
  return requestClient.get<ChannelItem>(`/messages/channels/${name}`);
}

export function createChannel(data: ChannelCreateReq) {
  return requestClient.post<ChannelItem>('/messages/channels', data);
}

export function updateChannel(name: string, data: ChannelUpdateReq) {
  return requestClient.put<ChannelItem>(`/messages/channels/${name}`, data);
}

export function deleteChannel(name: string) {
  return requestClient.delete(`/messages/channels/${name}`);
}

/**
 * 触发渠道连通性测试（调用对应 Provider.HealthCheck）
 * 后端只返回成功/失败，失败时 message 为错误描述
 */
export function testChannel(name: string, data?: any) {
  return requestClient.post(`/messages/channels/${name}/test`, data);
}

export function getChannelHealth() {
  return requestClient.get<any>('/messages/channels/health');
}

// ========== 模板 ==========
export async function getTemplateList(params?: any) {
  const res = await baseRequestClient.get<any>('/messages/templates', { params });
  const body = res.data ?? res;
  return { items: body.data ?? [], total: body.count ?? 0 };
}
export function getTemplateDetail(id: string) { return requestClient.get<any>(`/messages/templates/${id}`); }
export function createTemplate(data: any) { return requestClient.post('/messages/templates', data); }
export function updateTemplate(id: string, data: any) { return requestClient.put(`/messages/templates/${id}`, data); }
export function deleteTemplate(id: string) { return requestClient.delete(`/messages/templates/${id}`); }
export function validateTemplate(data: { channel: string; content: string; variables?: Record<string, any> }) {
  return requestClient.post<any>('/messages/templates/validate', data);
}
export function previewTemplate(id: string, data?: { variables?: Record<string, any> }) {
  return requestClient.post<any>(`/messages/templates/${id}/preview`, data);
}

// ========== 通知（SDK /me/* + /notifications/* 路由） ==========
export async function getNotificationList(params?: any) {
  const res = await baseRequestClient.get<any>('/me/notifications', { params });
  const body = res.data ?? res;
  const data = body.data;
  const list = Array.isArray(data) ? data : (data?.items ?? data?.list ?? []);
  const unread = data?.unread_count ?? data?.total ?? body.count ?? 0;
  return { items: list, total: list.length, unread_count: unread };
}
export function getNotificationDetail(id: string) { return requestClient.get<any>(`/me/notifications/${id}`); }
export function deleteNotification(id: string) { return requestClient.delete(`/notifications/${id}`).catch(() => {}); }
export function markNotificationRead(id: string) { return requestClient.post(`/notifications/${id}/read`); }
export function markAllNotificationsRead() { return requestClient.post('/notifications/read-all'); }
export async function getUnreadCount(): Promise<{ count: number }> {
  const data = await requestClient.get<any>('/me/unread-count');
  return { count: data?.total ?? data?.count ?? 0 };
}

// ========== 订阅 ==========
export async function getSubscriptionList(params?: any) {
  return requestClient.get<any[]>('/messages/subscriptions', { params });
}
export function createSubscription(data: any) { return requestClient.post('/messages/subscriptions', data); }
export function updateSubscription(id: string, data: any) { return requestClient.put(`/messages/subscriptions/${id}`, data); }
export function deleteSubscription(id: string) { return requestClient.delete(`/messages/subscriptions/${id}`); }
export function presetSubscriptions() { return requestClient.post('/messages/subscriptions/preset'); }
export function getSubscriptionCategories() { return requestClient.get<any[]>('/messages/subscriptions/categories'); }

// ========== 统计 ==========
export interface MessageStats {
  total_sent: number;
  total_failed: number;
  total_pending: number;
  by_channel: Record<string, number>;
  by_status: Record<string, number>;
}

export interface DailyStatsItem {
  date: string;
  sent: number;
  failed: number;
}

export interface ChannelStatsItem {
  channel: string;
  total: number;
  success: number;
  failed: number;
  success_rate: number;
}

export function getMessageStats() { return requestClient.get<MessageStats>('/messages/stats'); }
export function getDailyStats(params?: { start_date?: string; end_date?: string; days?: number }) { return requestClient.get<DailyStatsItem[]>('/messages/stats/daily', { params }); }
export function getChannelStats() { return requestClient.get<ChannelStatsItem[]>('/messages/stats/channel'); }

// ========== 消息发送 ==========
/**
 * 发送一条消息
 *
 * 入参支持两种模式：
 * 1. 单收件人：传入 recipient（手机号/邮箱/user_id 等）
 * 2. 扇出模式：传入 recipient_type + recipient_ids，由后端解析为目标用户列表并扇出
 *    - recipient_type: user/organize/department/role/all
 *    - 当 recipient_type=user 时，recipient_ids 为用户 id 列表；其它类型为对应组织/部门/角色 id
 */
export interface SendMessageReq {
  channel: string;
  category?: string;
  template_id?: string;
  variables?: Record<string, unknown>;
  recipient?: string;
  recipient_type?: 'all' | 'department' | 'organize' | 'role' | 'user';
  recipient_ids?: string[];
  subject?: string;
  content?: string;
  priority?: number;
  scheduled_at?: string;
  biz_id?: string;

  /**
   * 备选渠道列表，按顺序尝试。
   * 当主渠道在 MaxRetry 内全部失败后，自动按列表顺序切换重试。
   * 例如 ['email', 'sms'] 表示主渠道失败后先用 email，email 也失败再用 sms。
   */
  fallback_channels?: string[];

  /**
   * 终态回调 URL（HTTP POST），消息成功 / 彻底失败时异步推送结果。
   * 业务侧可基于此实现幂等的业务流转。
   */
  webhook?: string;
}
export function sendMessage(data: SendMessageReq) {
  return requestClient.post<any>('/messages/send', data);
}

export function batchSendMessage(data: SendMessageReq[]) {
  return requestClient.post<any>('/messages/send/batch', data);
}

// ========== 发送记录 ==========
export async function getRecordList(params?: any) {
  const res = await baseRequestClient.get<any>('/messages/records', { params });
  const body = res.data ?? res;
  return { items: body.data ?? [], total: body.count ?? 0 };
}
export function getRecordDetail(id: string) { return requestClient.get<any>(`/messages/records/${id}`); }
export function retryRecord(id: string) { return requestClient.post(`/messages/records/${id}/retry`); }
export function cancelRecord(id: string) { return requestClient.delete(`/messages/records/${id}`); }

// ========== 死信队列 ==========
/**
 * 死信队列条目（与后端 storage.DLQItem 对齐）
 */
export interface DLQItem {
  event_id: number;
  record_id: number;
  channel: string;
  category: string;
  recipient: string;
  subject: string;
  retry_count: number;
  error_msg: string;
  created_at: string;
  updated_at: string;
}

export interface DLQQueryParams {
  channel?: string;
  category?: string;
  start_time?: string;
  end_time?: string;
  index?: number;
  size?: number;
}

export async function getDLQList(params?: DLQQueryParams) {
  const res = await baseRequestClient.get<any>('/messages/dlq', { params });
  const body = res.data ?? res;
  return { items: (body.data ?? []) as DLQItem[], total: body.count ?? 0 };
}

export function getDLQDetail(id: number) {
  return requestClient.get<DLQItem>(`/messages/dlq/${id}`);
}

/** 重投：把死信事件重置为 pending 重新进入处理流程 */
export function retryDLQ(id: number) {
  return requestClient.post(`/messages/dlq/${id}/retry`);
}

/** 放弃：删除死信事件并把 record 标记为 cancelled */
export function discardDLQ(id: number) {
  return requestClient.delete(`/messages/dlq/${id}`);
}

// ========== 待办事项 ==========
export interface TodoItem {
  id: number;
  title: string;
  description: string;
  type: string;
  priority: number;
  status: string;
  assignee_id: string;
  creator_id: string;
  creator_name: string;
  source: string;
  source_id: string;
  source_url: string;
  due_date: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface TodoQuery {
  status?: string;
  type?: string;
  source?: string;
  priority?: number;
  keyword?: string;
  overdue?: string;
  index?: number;
  size?: number;
}

export interface TodoStats {
  pending: number;
  in_progress: number;
  completed: number;
  cancelled: number;
  expired: number;
  overdue: number;
}

export async function getTodoList(params?: TodoQuery) {
  const res = await baseRequestClient.get<any>('/messages/todos', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: TodoItem[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}

export function getTodoDetail(id: number) {
  return requestClient.get<TodoItem>(`/messages/todos/${id}`);
}

export function createTodo(data: Partial<TodoItem>) {
  return requestClient.post<TodoItem>('/messages/todos', data);
}

export function updateTodo(id: number, data: Partial<TodoItem>) {
  return requestClient.put<TodoItem>(`/messages/todos/${id}`, data);
}

export function updateTodoStatus(id: number, status: string) {
  return requestClient.put(`/messages/todos/${id}/status`, { status });
}

export function deleteTodo(id: number) {
  return requestClient.delete(`/messages/todos/${id}`);
}

export function getTodoStats() {
  return requestClient.get<TodoStats>('/messages/todos/stats');
}
