import { baseRequestClient } from '#/api/request';

export interface SystemSetting {
  key: string;
  value: string;
  group: string;
  label: string;
  description: string;
  value_type: string;
  is_secret: boolean;
  updated_at: string;
  updated_by: string;
}

export async function getSettings(group?: string) {
  const params: Record<string, string> = {};
  if (group) params.group = group;
  const res = await baseRequestClient.get<any>('/setting/list', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  return ((body as any).data ?? []) as SystemSetting[];
}

export async function batchUpdateSettings(
  items: Array<{ key: string; value: string }>,
) {
  return baseRequestClient.put('/setting/batch', { items });
}

export async function resetGroup(group: string) {
  return baseRequestClient.post(`/setting/reset/${group}`);
}
