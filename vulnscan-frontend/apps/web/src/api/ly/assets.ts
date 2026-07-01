import { preferences } from '@vben/preferences';
import { useAccessStore } from '@vben/stores';

const PREFIX = '/api/traffic/assets';

function headers(json = true) {
  const accessStore = useAccessStore();
  const h = new Headers();
  if (json) h.set('Content-Type', 'application/json');
  h.set('Accept-Language', preferences.app.locale);
  if (accessStore.accessToken) h.set('Authorization', `Bearer ${accessStore.accessToken}`);
  return h;
}

async function parse(res: Response) {
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  if (data?.code !== undefined && ![0, 200, 2000].includes(data.code)) {
    throw new Error(data.msg || data.message || '请求失败');
  }
  return data?.data !== undefined ? data.data : data;
}

export interface LyAsset extends Record<string, any> {
  id?: string;
  name: string;
  asset_type: 'domain_site' | 'ip';
  address: string;
  unit?: string;
  owner?: string;
  status?: number;
  remark?: string;
}

export function lyAssetList(params?: Record<string, any>) {
  const q = new URLSearchParams();
  Object.entries(params ?? {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') q.set(k, String(v));
  });
  const qs = q.toString();
  return fetch(`${PREFIX}/list${qs ? `?${qs}` : ''}`, { headers: headers(false) }).then(parse) as Promise<LyAsset[]>;
}

export function lyAssetCreate(data: LyAsset) {
  return fetch(PREFIX, { method: 'POST', headers: headers(), body: JSON.stringify(data) }).then(parse);
}

export function lyAssetUpdate(id: string, data: Partial<LyAsset>) {
  return fetch(`${PREFIX}/${id}`, { method: 'PUT', headers: headers(), body: JSON.stringify(data) }).then(parse);
}

export function lyAssetDelete(id: string) {
  return fetch(`${PREFIX}/${id}`, { method: 'DELETE', headers: headers() }).then(parse);
}

export function lyAssetImport(file: File) {
  const fd = new FormData();
  fd.append('file', file);
  return fetch(`${PREFIX}/import`, { method: 'POST', headers: headers(false), body: fd }).then(parse) as Promise<{
    imported: number;
    errors: Array<{ row: number; message: string }>;
  }>;
}

export function lyAssetTemplateUrl() {
  return `${PREFIX}/import/template`;
}
