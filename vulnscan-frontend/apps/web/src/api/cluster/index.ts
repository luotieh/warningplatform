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

export interface ScanNodeCredentials {
  version: number;
  master_url: string;
  node_uuid: string;
  secret: string;
  issued_at: string;
  label?: string;
}

export interface CredentialEnvelope {
  v: number;
  ek: string;
  nonce: string;
  ct: string;
  algo: string;
}

export interface IssueScanNodeResponse {
  encrypted: boolean;
  credentials?: ScanNodeCredentials;
  envelope?: CredentialEnvelope;
}

export function issueScanNodeCredentials(body: {
  enrollment: Record<string, unknown>;
  master_url?: string;
  label?: string;
}) {
  return requestClient.post<IssueScanNodeResponse>('/cluster/scan-nodes/enroll', body);
}

export function getClusterStats() {
  return requestClient.get('/scan/status');
}

export interface UnifiedNode {
  id: string;
  name: string;
  type: 'worker' | 'agent' | 'local';
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

/** 主控知识库同步游标（与节点 node-api/knowledge/manifest 数值一致） */
export interface NodeKnowledgeManifest {
  versions: Record<string, number>;
  server_time: string;
}

export function getNodeKnowledgeManifest() {
  return requestClient.get<NodeKnowledgeManifest>('/cluster/node-knowledge/manifest');
}
