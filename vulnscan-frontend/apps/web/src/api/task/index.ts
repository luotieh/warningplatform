import { useAppConfig } from '@vben/hooks';
import { useAccessStore } from '@vben/stores';

import { normalizePagedResponse } from '#/api/helpers';
import { baseRequestClient, probeAuthentication, requestClient } from '#/api/request';

export interface ScanTask {
  id: string;
  name: string;
  type: string;
  status: string;
  priority: number;
  targets: string[];
  total_targets: number;
  scanned_targets: number;
  config?: Record<string, any>;
  parameters?: Record<string, any>;
  progress: number;
  current_stage?: string;
  current_module?: string;
  worker_id?: string;
  schedule_id?: string;
  vuln_critical: number;
  vuln_high: number;
  vuln_medium: number;
  vuln_low: number;
  vuln_info: number;
  alive_hosts: number;
  open_ports: number;
  started_at?: string;
  finished_at?: string;
  error?: string;
  error_msg?: string;
  created_at: string;
  updated_at: string;
}

export async function getTaskList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/task/list', { params });
  return normalizePagedResponse<ScanTask>(res);
}

export function getTaskDetail(id: string) {
  return requestClient.get<ScanTask>(`/task/${id}`);
}

export function createTask(data: {
  name: string;
  targets: string[];
  template_id?: string;
  parameters?: Record<string, any>;
  asset_ids?: string[];
  executor_node_ids?: string[];
  priority?: number;
}) {
  return requestClient.post('/scan/launch', {
    ...data,
    template_id: data.template_id || 'full',
  });
}

export function cancelTask(id: string) {
  return requestClient.post(`/scan/cancel/${id}`);
}

/** 基于原任务配置重新入队（新任务 ID） */
export function rerunTask(id: string) {
  return requestClient.post<{
    task_id: string;
    name: string;
    template: string;
    status: string;
    split_mode?: boolean;
    sub_count?: number;
  }>(`/scan/rerun/${id}`);
}

export function deleteTask(id: string) {
  return requestClient.delete(`/task/${id}`);
}

export function pauseTask(id: string) {
  return requestClient.post(`/task/${id}/pause`);
}

export function resumeTask(id: string) {
  return requestClient.post(`/task/${id}/resume`);
}

export async function exportTaskReport(id: string, format: 'json' | 'markdown' | 'csv' | 'sarif' = 'json') {
  const res = await baseRequestClient.get(`/report/task/${id}`, {
    params: { format },
    responseType: 'blob',
  });
  return res;
}

export function getSchedulerStatus() {
  return requestClient.get('/scan/status');
}

export function getScanProfiles() {
  return requestClient.get('/scan/templates');
}

export interface ScanEnginePreset {
  name: string;
  description: string;
  parameters: Record<string, any>;
}

export function getScanEnginePresets() {
  return requestClient.get<ScanEnginePreset[]>('/scan/engine-presets');
}

export interface SuggestScanParameters {
  target_count: number;
  module_count?: number;
  template_version?: string;
  template_outdated?: boolean;
  derived: Record<string, any>;
  module_ids?: string[];
}

export function suggestScanParameters(data: { template_id?: string; targets: string[] }) {
  return requestClient.post<SuggestScanParameters>('/scan/suggest-parameters', data);
}

export interface EngineRuleInfo {
  id: string;
  name: string;
  source: string;
  default: string;
  config_key?: string;
  configurable: boolean;
  description: string;
}

export function getScanEngineRules() {
  return requestClient.get<{
    rules: EngineRuleInfo[];
    module_exposure: Record<string, string[]>;
    primary_module_ids: string[];
  }>('/scan/engine-rules');
}

export interface TaskLevelParamSchema {
  key: string;
  name: string;
  type: string;
  default_value?: unknown;
  description?: string;
  options?: { value: unknown; label: string }[];
}

export function getTaskParameterSchema() {
  return requestClient.get<{
    task_level_params: TaskLevelParamSchema[];
    module_create_params: TaskLevelParamSchema[];
    engine_presets: ScanEnginePreset[];
  }>('/scan/task-parameter-schema');
}

export interface ScanFinding {
  id: string;
  task_id: string;
  asset_id: string;
  module_id: string;
  type: string;
  category: string;
  target: string;
  port: number;
  protocol: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  confidence_reason: string;
  evidence: string;
  verification_level: string;
  verification_detail: string;
  data: Record<string, any>;
  tags: string[];
  created_at: string;
}

export interface FindingSummary {
  total_findings: number;
  by_category: Record<string, number>;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  by_module: Record<string, number>;
}

export async function getTaskFindings(
  taskId: string,
  params?: Record<string, any>,
) {
  const res = await baseRequestClient.get<any>(`/task/${taskId}/findings`, {
    params,
  });
  return normalizePagedResponse<ScanFinding>(res);
}

export function getTaskFindingSummary(taskId: string) {
  return requestClient.get<FindingSummary>(`/task/${taskId}/findings/summary`);
}

export interface AssetPort {
  port: number;
  protocol: string;
  service: string;
  version: string;
  banner: string;
}

export interface AssetSummary {
  target: string;
  ip: string;
  ports: AssetPort[];
  services: string[];
  techs: string[];
  banner: string;
  title: string;
  status_code: number;
  waf: string;
  os: string;
  vuln_count: Record<string, number>;
  finding_ids: string[];
  first_seen: string;
}

export function getTaskAssets(taskId: string) {
  return requestClient.get<AssetSummary[]>(`/task/${taskId}/assets`);
}

export interface ScanLogEntry {
  id: number;
  task_id: string;
  level: string;
  message: string;
  stage: string;
  module: string;
  created_at: string;
}

export function getTaskLogs(taskId: string) {
  return requestClient.get<ScanLogEntry[]>(`/task/${taskId}/logs`);
}

export interface ScanSSEEvent {
  type: 'finding' | 'progress' | 'stage' | 'done' | 'log' | 'ping';
  task_id: string;
  payload: any;
  time: string;
}

export interface LogPayload {
  level: string;
  message: string;
  stage?: string;
  module?: string;
}

export function subscribeScanEvents(
  taskId: string,
  callbacks: {
    onFinding?: (payload: { findings: ScanFinding[]; stage: string; module: string }) => void;
    onProgress?: (payload: any) => void;
    onStage?: (payload: { stage: string; status: string }) => void;
    onDone?: (payload: { status: string; error_msg?: string }) => void;
    onLog?: (payload: LogPayload, eventTime?: string) => void;
    onError?: (error: Event) => void;
  },
): { close: () => void } {
  const { apiURL } = useAppConfig(import.meta.env, import.meta.env.PROD);
  const accessStore = useAccessStore();
  const token = accessStore.accessToken ?? '';
  const sep = apiURL.includes('?') ? '&' : '?';
  const url = `${apiURL}/scan/events/${taskId}${sep}token=${encodeURIComponent(token)}`;

  const es = new EventSource(url);

  es.addEventListener('finding', (e: MessageEvent) => {
    try {
      const data = JSON.parse(e.data);
      const payload = typeof data.payload === 'string' ? JSON.parse(data.payload) : data.payload;
      callbacks.onFinding?.(payload);
    } catch { /* parse error */ }
  });

  es.addEventListener('progress', (e: MessageEvent) => {
    try {
      const data = JSON.parse(e.data);
      const payload = typeof data.payload === 'string' ? JSON.parse(data.payload) : data.payload;
      callbacks.onProgress?.(payload);
    } catch { /* parse error */ }
  });

  es.addEventListener('stage', (e: MessageEvent) => {
    try {
      const data = JSON.parse(e.data);
      const payload = typeof data.payload === 'string' ? JSON.parse(data.payload) : data.payload;
      callbacks.onStage?.(payload);
    } catch { /* parse error */ }
  });

  es.addEventListener('done', (e: MessageEvent) => {
    try {
      const data = JSON.parse(e.data);
      const payload = typeof data.payload === 'string' ? JSON.parse(data.payload) : data.payload;
      callbacks.onDone?.(payload);
    } catch { /* parse error */ }
    es.close();
  });

  es.addEventListener('log', (e: MessageEvent) => {
    try {
      const data = JSON.parse(e.data);
      const payload = typeof data.payload === 'string' ? JSON.parse(data.payload) : data.payload;
      callbacks.onLog?.(payload, data.time);
    } catch { /* parse error */ }
  });

  es.addEventListener('ping', () => {});

  es.onerror = (e) => {
    void probeAuthentication();
    callbacks.onError?.(e);
    es.close();
  };

  return {
    close: () => es.close(),
  };
}
