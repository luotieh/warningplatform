const DEEPFLOW_BASE_URL = '/api/traffic';

interface DeepflowRequestOptions extends RequestInit {
  params?: Record<string, any>;
}

function buildUrl(url: string, params?: Record<string, any>) {
  const full = `${DEEPFLOW_BASE_URL}${url}`;
  if (!params || Object.keys(params).length === 0) return full;
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === null || value === undefined || value === '') return;
    search.set(key, String(value));
  });
  const query = search.toString();
  return query ? `${full}?${query}` : full;
}

async function parseResponse(response: Response) {
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  const data = await response.json();

  if (data?.code !== undefined) {
    if (![200, 2000].includes(data.code)) throw new Error(data.message || 'Request failed');
    if (data.access_token !== undefined) return data;
    return data.data;
  }

  if (data?.status !== undefined) {
    if (data.status !== 'success') {
      throw new Error(data.message || 'Request failed');
    }
    if (data.access_token !== undefined) return data;
    return data.data !== undefined ? data.data : data;
  }

  return data;
}

function unwrapListResponse(data: any) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.list)) return data.list;
  if (Array.isArray(data?.data)) return data.data;
  if (Array.isArray(data?.messages)) return data.messages;
  return [];
}

async function request<T = any>(url: string, options: DeepflowRequestOptions = {}) {
  const token = localStorage.getItem('deepflow_token');
  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json');
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(buildUrl(url, options.params), {
    ...options,
    headers,
  });

  return parseResponse(response) as Promise<T>;
}

export function deepflowGet<T = any>(url: string, params?: Record<string, any>) {
  return request<T>(url, { method: 'GET', params });
}

export function deepflowPost<T = any>(url: string, data?: Record<string, any>) {
  return request<T>(url, {
    body: JSON.stringify(data ?? {}),
    method: 'POST',
  });
}

export function deepflowPut<T = any>(url: string, data?: Record<string, any>) {
  return request<T>(url, {
    body: JSON.stringify(data ?? {}),
    method: 'PUT',
  });
}

export function deepflowLogin(data: { password: string; username: string }) {
  return deepflowPost<{
    access_token?: string;
    data?: Record<string, any>;
    user?: Record<string, any>;
  }>(
    '/deepsoc/auth/login',
    data,
  );
}

export function deepflowGetEvents() {
  return deepflowGet('/events/list').then(unwrapListResponse);
}

export function deepflowGetEventDetail(eventId: string) {
  return deepflowGet(`/events/detail/${eventId}`);
}

export function deepflowGetEventStats(eventId: string) {
  return deepflowGet(`/events/detail/${eventId}/stats`);
}

export function deepflowGetEventSummary(eventId: string) {
  return deepflowGet(`/events/detail/${eventId}/summaries`);
}

export function deepflowRefreshEventReport(eventId: string) {
  return deepflowPost<{ analysis_version: number; status: string }>(
    `/events/detail/${eventId}/report/refresh`,
  );
}

export function deepflowEventEvidenceUrl(eventId: string, idx: number) {
  return `/api/traffic/events/detail/${eventId}/evidence/${idx}`;
}

export function deepflowEventArchiveUrl(eventId: string) {
  return `/api/traffic/events/detail/${eventId}/evidence/archive`;
}

export function deepflowGetChatRecords(
  eventId: string,
  params: Record<string, any> = { last_message_db_id: 0 },
) {
  return deepflowGet(`/events/detail/${eventId}/messages`, params).then(unwrapListResponse);
}

export function deepflowAskAI(data: Record<string, any>) {
  return deepflowPost('/engineer-chat/send', data);
}
