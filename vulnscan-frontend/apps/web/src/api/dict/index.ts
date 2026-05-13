import { normalizePagedResponse } from '#/api/helpers';
import { baseRequestClient, requestClient } from '#/api/request';

export interface Dictionary {
  id: string;
  name: string;
  type: string;
  description: string;
  entry_count: number;
  source: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface DictionaryEntry {
  id: string;
  dictionary_id: string;
  value: string;
  tags: string;
  priority: number;
}

export async function getDictList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/dict/list', { params });
  return normalizePagedResponse<Dictionary>(res);
}

export function getDictDetail(id: string) {
  return requestClient.get<Dictionary>(`/dict/${id}`);
}

export function createDict(data: Partial<Dictionary>) {
  return requestClient.post('/dict', data);
}

export function updateDict(id: string, data: Partial<Dictionary>) {
  return requestClient.put(`/dict/${id}`, data);
}

export function deleteDict(id: string) {
  return requestClient.delete(`/dict/${id}`);
}

export async function getDictEntries(id: string, params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>(`/dict/${id}/entries`, { params });
  return normalizePagedResponse<DictionaryEntry>(res);
}

export function addDictEntry(id: string, data: Partial<DictionaryEntry>) {
  return requestClient.post(`/dict/${id}/entries`, data);
}

export function deleteDictEntry(id: string, entryId: string) {
  return requestClient.delete(`/dict/${id}/entries/${entryId}`);
}

export function importDict(id: string, text: string) {
  return requestClient.post(`/dict/${id}/import`, { text });
}

export function exportDict(id: string) {
  return `/api/dict/${id}/export`;
}

export function clearDict(id: string) {
  return requestClient.post(`/dict/${id}/clear`);
}
