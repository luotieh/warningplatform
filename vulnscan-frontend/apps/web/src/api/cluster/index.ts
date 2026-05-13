import { normalizePagedResponse } from '#/api/helpers';
import { baseRequestClient, requestClient } from '#/api/request';

export interface WorkerNode {
  id: string;
  name: string;
  hostname: string;
  ip: string;
  port: number;
  status: string;
  capacity: number;
  active_tasks: number;
  cpu_usage: number;
  mem_usage: number;
  health_score: number;
  version: string;
  last_heartbeat?: string;
  registered_at: string;
}

export async function getWorkerList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/cluster/workers', { params });
  return normalizePagedResponse<WorkerNode>(res);
}

export function getWorkerDetail(id: string) {
  return requestClient.get<WorkerNode>(`/cluster/workers/${id}`);
}

export function unregisterWorker(id: string) {
  return requestClient.post(`/cluster/workers/${id}/unregister`);
}

export function checkStaleWorkers() {
  return requestClient.post('/cluster/workers/check-stale');
}

export function getClusterStats() {
  return requestClient.get('/scan/status');
}

export interface UnifiedNode {
  id: string;
  name: string;
  type: 'worker' | 'agent';
  ip: string;
  status: string;
  version: string;
  cpu_usage: number;
  mem_usage: number;
  active_tasks: number;
  capacity: number;
  health_score: number;
  region?: string;
  label?: string;
  last_heartbeat?: string;
  registered_at?: string;
  hostname?: string;
  bandwidth_mbps?: number;
  avg_latency_ms?: number;
  success_tasks?: number;
  failed_tasks?: number;
  queued_tasks?: number;
  tasks_completed?: number;
}

export interface NodeSummary {
  total_nodes: number;
  online_nodes: number;
  offline_nodes: number;
  worker_count: number;
  agent_count: number;
  total_tasks: number;
  total_capacity: number;
}

export function getUnifiedNodes(params?: { type?: string; status?: string }) {
  return requestClient.get<{ nodes: UnifiedNode[]; summary: NodeSummary }>('/nodes', { params });
}
