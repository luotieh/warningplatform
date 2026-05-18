import { normalizePagedResponse } from '#/api/helpers';
import { baseRequestClient, requestClient } from '#/api/request';

export interface DataLibrary {
  id: string;
  name: string;
  type: string;
  category: string;
  description: string;
  entry_count: number;
  source: string;
  status: string;
  organize_id: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface DataLibraryEntry {
  id: string;
  library_id: string;
  name: string;
  value: string;
  type: string;
  tags: string;
  metadata: Record<string, any> | null;
  priority: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

// ── Library CRUD ──

export async function getDataLibList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/data-libraries', { params });
  return normalizePagedResponse<DataLibrary>(res);
}

export function getDataLibDetail(id: string) {
  return requestClient.get<DataLibrary>(`/data-libraries/${id}`);
}

export function createDataLib(data: Partial<DataLibrary>) {
  return requestClient.post('/data-libraries', data);
}

export function updateDataLib(id: string, data: Partial<DataLibrary>) {
  return requestClient.put(`/data-libraries/${id}`, data);
}

export function deleteDataLib(id: string) {
  return requestClient.delete(`/data-libraries/${id}`);
}

// ── Entry CRUD ──

export async function getDataLibEntries(
  libId: string,
  params?: Record<string, any>,
) {
  const res = await baseRequestClient.get<any>(
    `/data-libraries/${libId}/entries`,
    { params },
  );
  return normalizePagedResponse<DataLibraryEntry>(res);
}

export function getDataLibEntry(libId: string, entryId: string) {
  return requestClient.get<DataLibraryEntry>(
    `/data-libraries/${libId}/entries/${entryId}`,
  );
}

export function addDataLibEntry(
  libId: string,
  data: Partial<DataLibraryEntry>,
) {
  return requestClient.post(`/data-libraries/${libId}/entries`, data);
}

export function updateDataLibEntry(
  libId: string,
  entryId: string,
  data: Record<string, any>,
) {
  return requestClient.put(`/data-libraries/${libId}/entries/${entryId}`, data);
}

export function deleteDataLibEntry(libId: string, entryId: string) {
  return requestClient.delete(`/data-libraries/${libId}/entries/${entryId}`);
}

export function batchAddEntries(
  libId: string,
  entries: Partial<DataLibraryEntry>[],
) {
  return requestClient.post(`/data-libraries/${libId}/entries/batch`, {
    entries,
  });
}

// ── Bulk Operations ──

export function importDataLib(libId: string, text: string) {
  return requestClient.post(`/data-libraries/${libId}/import`, { text });
}

export function exportDataLibUrl(libId: string) {
  return `/api/data-libraries/${libId}/export`;
}

export function clearDataLib(libId: string) {
  return requestClient.post(`/data-libraries/${libId}/clear`);
}

export function getDataLibCategories(type?: string) {
  return requestClient.get<string[]>('/data-libraries/categories', {
    params: type ? { type } : undefined,
  });
}

export function reloadDataLib() {
  return requestClient.post('/data-libraries/reload');
}
