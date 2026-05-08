import { baseRequestClient, requestClient } from '#/api/request';

export interface Notification {
  id: string;
  user_id: string;
  type: string;
  title: string;
  content: string;
  link: string;
  severity: string;
  read: boolean;
  read_at: string | null;
  created_at: string;
}

export function getNotifications(params?: { read?: string; type?: string }) {
  return baseRequestClient.get<any>('/notify/list', { params });
}

export function getUnreadCount() {
  return requestClient.get('/notify/unread-count');
}

export function markRead(id: string) {
  return requestClient.post(`/notify/${id}/read`);
}

export function markAllRead() {
  return requestClient.post('/notify/read-all');
}
