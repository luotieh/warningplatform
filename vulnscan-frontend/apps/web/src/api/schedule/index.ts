import { baseRequestClient, requestClient } from '#/api/request';

export interface ScanSchedule {
  id: string;
  name: string;
  description: string;
  template_id: string;
  template_name: string;
  targets: string[];
  config: Record<string, any>;
  schedule_type: string;
  cron_expr: string;
  interval_min: number;
  enabled: boolean;
  status: string;
  last_run_at: string | null;
  next_run_at: string | null;
  last_task_id: string;
  run_count: number;
  created_at: string;
}

export async function getScheduleList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/schedule/list', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: ScanSchedule[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}

export function getScheduleDetail(id: string) {
  return requestClient.get<ScanSchedule>(`/schedule/${id}`);
}

export function createSchedule(data: Partial<ScanSchedule>) {
  return requestClient.post('/schedule', data);
}

export function updateSchedule(id: string, data: Partial<ScanSchedule>) {
  return requestClient.put(`/schedule/${id}`, data);
}

export function deleteSchedule(id: string) {
  return requestClient.delete(`/schedule/${id}`);
}

export function toggleSchedule(id: string, enabled: boolean) {
  return requestClient.post(`/schedule/${id}/toggle`, { enabled });
}

export function runScheduleNow(id: string) {
  return requestClient.post(`/schedule/${id}/run`);
}
