import { preferences } from '@vben/preferences';
import { useAccessStore } from '@vben/stores';

export interface LyEventItem extends Record<string, any> {
  id: number | string;
  obj?: string;
  peer?: string;
  type?: string;
  desc?: string;
  level?: number | string;
  proc_status?: string;
  starttime?: number | string;
  duration?: number | string;
  is_alive?: boolean | string | number;
  attackDevice?: string;
  victimDevice?: string;
}

export interface LyConfigItem extends Record<string, any> {
  id?: number | string;
}

const LOCAL_CONFIG_KEY = 'traffic-analysis-demo-configs';

async function parseResponse(response: Response) {
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  const data = await response.json();

  if (data?.code !== undefined) {
    if (![0, 200, 2000].includes(data.code)) {
      throw new Error(data.msg || data.message || 'Request failed');
    }
    return data.data !== undefined ? data.data : data;
  }

  if (data?.status !== undefined) {
    if (data.status !== 'success') {
      throw new Error(data.msg || data.message || 'Request failed');
    }
    return data.data !== undefined ? data.data : data;
  }

  return data;
}

function createHeaders() {
  const accessStore = useAccessStore();
  const headers = new Headers();
  headers.set('Content-Type', 'application/json');
  headers.set('Accept-Language', preferences.app.locale);

  if (accessStore.accessToken) {
    headers.set('Authorization', `Bearer ${accessStore.accessToken}`);
  }

  return headers;
}

async function post<T = any>(
  url: string,
  data?: Record<string, any>,
  prefix = '/api/traffic/ly',
) {
  const response = await fetch(`${prefix}${url}`, {
    body: JSON.stringify(data ?? {}),
    headers: createHeaders(),
    method: 'POST',
  });

  return parseResponse(response) as Promise<T>;
}

async function get<T = any>(
  url: string,
  params?: Record<string, any>,
  prefix = '/api/traffic/ly',
) {
  const search = new URLSearchParams();
  Object.entries(params ?? {}).forEach(([key, value]) => {
    if (value === null || value === undefined || value === '') return;
    search.set(key, String(value));
  });
  const query = search.toString();
  const response = await fetch(`${prefix}${url}${query ? `?${query}` : ''}`, {
    headers: createHeaders(),
    method: 'GET',
  });

  return parseResponse(response) as Promise<T>;
}

async function postInternal<T = any>(url: string, data?: Record<string, any>) {
  const headers = new Headers();
  headers.set('Content-Type', 'application/json');
  headers.set('X-API-Key', 'change-me-internal-key');

  const response = await fetch(`/api/traffic/internal${url}`, {
    body: JSON.stringify(data ?? {}),
    headers,
    method: 'POST',
  });

  return parseResponse(response) as Promise<T>;
}

export function lyEventGet(params?: Record<string, any>) {
  return get<LyEventItem[]>('/event', {
    req_type: 'aggre',
    ...(params ?? {}),
  });
}

export function lyEventStatusMod(params: Record<string, any>) {
  return post('/event', {
    req_type: 'set_proc_status',
    ...params,
  });
}

export function lyFeatureMo(params?: Record<string, any>) {
  return get<any[]>('/feature', {
    ...(params ?? {}),
    type: 'mo',
    limit: 0,
  });
}

export function lyEventPushToAi(data: Record<string, any>) {
  return postInternal('/event/push', data);
}

export function lyEventReview(params: {
  eventId: number | string;
  action: 'approve' | 'reject';
  comment?: string;
  reviewedBy?: string;
}) {
  const { eventId, action, comment, reviewedBy } = params;
  return post(
    `/events/detail/${eventId}/review`,
    { action, comment: comment ?? '', reviewed_by: reviewedBy ?? '' },
    '/api/traffic',
  );
}

export function lyEventSearch(params?: Record<string, any>) {
  return lyEventGet(params);
}

export function lyConfigGet(params?: Record<string, any>) {
  return get<any[]>('/config', {
    op: 'get',
    ...(params ?? {}),
  });
}

export function lyConfigSave(params: Record<string, any>) {
  saveLocalConfig(params);
  return post('/config', params).catch(() => ({
    data: params,
    local: true,
    result: 'ok',
    status: 'success',
  }));
}

export function lyLLMConfigGet() {
  return get<Record<string, any>>('/config', undefined, '/api/traffic/llm');
}

export function lyLLMConfigSave(params: Record<string, any>) {
  return post<Record<string, any>>('/config', params, '/api/traffic/llm');
}

/** LLM 健康检查：用表单当前值（可未保存）测连通性并发送一条测试对话 */
export function lyLLMHealthCheck(params: Record<string, any>) {
  return post<Record<string, any>>('/llm', params, '/api/traffic/health');
}

export function lyNodeTestConnection(params: Record<string, any>) {
  return post<Record<string, any>>('/config', {
    ...(params ?? {}),
    op: 'test',
    type: 'agent',
  }).catch((error) => ({
    message: error?.message || '连接测试失败',
    reachable: false,
    status: 'offline',
  }));
}

export function lyInternalApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'internalip', ...(params ?? {}) });
}

export function lyBlacklistApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'bwlist', target: 'blacklist', ...(params ?? {}) });
}

export function lyWhitelistApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'bwlist', target: 'whitelist', ...(params ?? {}) });
}

export function lyDeviceApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'agent', target: 'device', ...(params ?? {}) });
}

export function lyProxyApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'agent', ...(params ?? {}) });
}

export function lyUserApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'user', ...(params ?? {}) });
}

export function lyMoApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'mo', ...(params ?? {}) });
}

export function lyMoGroupApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'mo_group', op: 'gget', ...(params ?? {}) });
}

export function lyEventRulesApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'event', ...(params ?? {}) });
}

export function lyEventIgnoreApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'event_ignore', ...(params ?? {}) });
}

export function lyEventTypeApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'event_type', ...(params ?? {}) });
}

export function lyEventLevelApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'event_level', ...(params ?? {}) });
}

export function lyEventActionApi(params?: Record<string, any>) {
  return lyConfigGet({ type: 'event_action', ...(params ?? {}) });
}

// 只读获取来自 ta_node 的规则（intel.*.yaml），支持类型/关键字过滤与分页。
export function lyRuleList(params?: Record<string, any>) {
  return get<Record<string, any>>('/rules', params);
}

// 获取当前规则读取路径配置（路径、模式、解析到的文件与规则数）。
export function lyRuleConfigGet() {
  return get<Record<string, any>>('/rules/config');
}

// 设置规则读取路径（单个 yaml 文件，或包含 yaml 的文件夹；留空恢复默认探测）。
export function lyRuleConfigSave(path: string) {
  return post<Record<string, any>>('/rules/config', { path });
}

export function lyLocalConfigList(category: string) {
  return readLocalConfigs()[category] ?? [];
}

function saveLocalConfig(params: Record<string, any>) {
  const category = categoryForParams(params);
  if (!category) return;
  const all = readLocalConfigs();
  const list = [...(all[category] ?? [])];
  const op = String(params.op ?? 'add').toLowerCase();
  const id = String(
    params.id ??
      params.event_id ??
      params.config_id ??
      params.group_id ??
      params.user_id ??
      '',
  );

  if (['del', 'delete', 'remove'].includes(op)) {
    all[category] = list.filter((item) => !sameLocalItem(item, params, id));
    all[category].unshift(normalizeDeletedLocalConfigItem(params, id));
    writeLocalConfigs(all);
    return;
  }

  const next = normalizeLocalConfigItem(category, params);
  const index = list.findIndex((item) =>
    sameLocalItem(item, next, String(next.id ?? '')),
  );
  if (index >= 0) {
    list[index] = { ...list[index], ...next };
  } else {
    list.unshift(next);
  }
  all[category] = list;
  writeLocalConfigs(all);
}

function sameLocalItem(
  item: Record<string, any>,
  params: Record<string, any>,
  id: string,
) {
  if (
    id &&
    String(item.id ?? item.config_id ?? item.group_id ?? item.user_id ?? '') ===
      id
  ) {
    return true;
  }
  const value = params.value ?? params.ip ?? params.name ?? params.moip;
  if (value === undefined || value === '') return false;
  return (
    String(item.value ?? item.ip ?? item.name ?? item.moip ?? '') ===
    String(value)
  );
}

function normalizeLocalConfigItem(category: string, params: Record<string, any>) {
  const id =
    params.id ??
    params.event_id ??
    params.config_id ??
    params.group_id ??
    params.user_id ??
    `local-${Date.now()}`;
  const base = { ...params, id, config_id: params.config_id ?? id, local: true };
  switch (category) {
    case 'internalip':
      return {
        ...base,
        desc: params.desc ?? params.description,
        ip: params.ip ?? params.value,
        value: params.value ?? params.ip,
      };
    case 'blacklist':
    case 'whitelist':
      return {
        ...base,
        desc: params.desc ?? params.description,
        ip: params.ip ?? params.value,
        value: params.value ?? params.ip,
      };
    case 'device':
    case 'proxy':
      return {
        ...base,
        comment: params.comment ?? params.desc ?? params.description,
        devid: params.devid ?? params.device_code,
        ip: params.ip ?? params.value,
        name: params.name ?? params.desc ?? params.description,
        port: params.port,
        protocol: params.protocol ?? 'http',
        status: params.status ?? 'unknown',
      };
    case 'user':
      return {
        ...base,
        name: params.name ?? params.username,
        username: params.username ?? params.name,
      };
    case 'mo':
      return {
        ...base,
        desc: params.desc ?? params.modesc ?? params.description,
        groupid: params.groupid ?? params.mogroupid,
      };
    case 'mo_group':
      return { ...base, desc: params.desc ?? params.description, name: params.name };
    case 'event':
      return { ...base, desc: params.desc ?? params.description, event_id: id };
    case 'event_ignore':
      return { ...base, desc: params.desc ?? params.description };
    default:
      return base;
  }
}

function normalizeDeletedLocalConfigItem(params: Record<string, any>, id: string) {
  const value = params.value ?? params.ip ?? params.name ?? params.moip;
  const fallbackID = value ? `deleted-${value}` : `deleted-${Date.now()}`;
  const deleteKey = id || String(value ?? fallbackID);
  return {
    ...params,
    id: id || fallbackID,
    config_id: (params.config_id ?? id) || fallbackID,
    __delete_key: deleteKey,
    __deleted: true,
    local: true,
  };
}

function categoryForParams(params?: Record<string, any>) {
  const type = String(params?.type ?? '').toLowerCase();
  const target = String(params?.target ?? params?.list_type ?? '').toLowerCase();
  if (type === 'bwlist') {
    return target.includes('white') ? 'whitelist' : 'blacklist';
  }
  if (type === 'agent') {
    return target === 'device' ? 'device' : 'proxy';
  }
  return type;
}

function readLocalConfigs(): Record<string, Record<string, any>[]> {
  if (typeof localStorage === 'undefined') return {};
  try {
    return JSON.parse(localStorage.getItem(LOCAL_CONFIG_KEY) || '{}');
  } catch {
    return {};
  }
}

function writeLocalConfigs(value: Record<string, Record<string, any>[]>) {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(LOCAL_CONFIG_KEY, JSON.stringify(value));
}
