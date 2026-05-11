import { baseRequestClient, requestClient } from '#/api/request';

export interface SystemDict {
  id: string;
  name: string;
  category: string;
  description: string;
  item_count: number;
  created_at: string;
  updated_at: string;
}

export interface SystemDictItem {
  id: string;
  dict_id: string;
  label: string;
  value: string;
  sort: number;
  enabled: boolean;
  remark: string;
}

export interface SystemDictInput {
  id?: string;
  name: string;
  category?: string;
  description?: string;
  items?: SystemDictItemInput[];
}

export interface SystemDictItemInput {
  id?: string;
  label: string;
  value: string;
  sort?: number;
  enabled?: boolean;
  remark?: string;
}

export async function getSystemDictList(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/system/dict', { params });
}

export async function getSystemDictDetail(id: string) {
  return requestClient.get<{ dict: SystemDict; items: SystemDictItem[] }>(`/system/dict/detail/${id}`);
}

export async function createSystemDict(data: SystemDictInput) {
  return requestClient.post<{ id: string }>('/system/dict', data);
}

export async function updateSystemDict(id: string, data: Partial<SystemDictInput>) {
  return requestClient.put(`/system/dict/detail/${id}`, data);
}

export async function deleteSystemDict(id: string) {
  return requestClient.delete(`/system/dict/detail/${id}`);
}

export async function getSystemDictItems(dictId: string, enabled = true) {
  return requestClient.get<SystemDictItem[]>(`/system/dict/item/all/${dictId}`, {
    params: { enabled },
  });
}

export async function addSystemDictItems(dictId: string, items: SystemDictItemInput[]) {
  return requestClient.post(`/system/dict/item/${dictId}`, items);
}

export async function updateSystemDictItem(dictId: string, item: SystemDictItemInput) {
  return requestClient.put(`/system/dict/item/${dictId}`, item);
}

export async function deleteSystemDictItems(dictId: string, ids: string[]) {
  return requestClient.delete(`/system/dict/item/${dictId}`, { data: { ids } });
}

export function dictItemsToOptions(items: SystemDictItem[]) {
  return items
    .filter(item => item.enabled)
    .sort((a, b) => (a.sort || 0) - (b.sort || 0))
    .map(item => ({ label: item.label, value: item.value }));
}
