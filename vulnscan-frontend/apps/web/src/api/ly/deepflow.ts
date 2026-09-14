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

export class DeepflowRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly errorCode = '',
    readonly stage = 'backend',
    readonly hint = '',
    readonly detail = '',
    readonly upstreamStatus = 0,
    readonly requestId = '',
  ) {
    super(message);
    this.name = 'DeepflowRequestError';
  }
}

async function parseResponse(response: Response) {
  let data: any;
  try {
    data = await response.json();
  } catch {
    throw new DeepflowRequestError('平台接口返回了非 JSON 响应', response.status, 'invalid_response');
  }

  const fail = () => {
    const providerMessage = typeof data?.error === 'string' ? data.error : data?.error?.message;
    throw new DeepflowRequestError(
      String(data?.message || data?.msg || providerMessage || '请求失败'),
      response.status,
      String(data?.error_code || ''),
      String(data?.stage || 'backend'),
      String(data?.hint || ''),
      String(data?.detail || ''),
      Number(data?.upstream_status || 0),
      String(data?.request_id || response.headers.get('X-Request-Id') || ''),
    );
  };
  if (!response.ok) fail();

  if (data?.code !== undefined) {
    if (![200, 2000].includes(data.code)) fail();
    if (data.access_token !== undefined) return data;
    return data.data;
  }

  if (data?.status !== undefined) {
    if (data.status !== 'success') {
      fail();
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

export function deepflowGetChatRecords(
  eventId: string,
  params: Record<string, any> = { last_message_db_id: 0 },
) {
  return deepflowGet(`/events/detail/${eventId}/messages`, params).then(unwrapListResponse);
}

export function deepflowAskAI(data: Record<string, any>) {
  return deepflowPost('/engineer-chat/send', data);
}
