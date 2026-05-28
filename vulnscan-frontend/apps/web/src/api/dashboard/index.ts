import { normalizePagedResponse } from '#/api/helpers';
import { baseRequestClient, requestClient } from '#/api/request';

export interface SecurityPosture {
  total_assets: number;
  total_vulns: number;
  risk_score: number;
  compliance_score: number;
  severity_distribution: Record<string, number>;
  vuln_trend: { timestamp: string; value: number }[];
  top_vuln_assets: { host: string; vuln_count: number; risk_score: number }[];
  active_scans: number;
  worker_status: Record<string, number>;
  monitor_stats?: {
    enabled_tasks?: number;
    open_alerts?: number;
    total_alerts?: number;
    total_tasks?: number;
  };
  top_risk_assets?: {
    address?: string;
    asset_id?: string;
    id?: string;
    alert_count?: number;
    name?: string;
    risk_score?: number;
    vuln_count?: number;
  }[];
}

export interface RecentActivity {
  id?: string;
  type: string;
  title: string;
  detail: string;
  created_at: string;
}

export function getDashboardOverview() {
  return requestClient.get<SecurityPosture>('/dashboard/overview');
}

export function getVulnTrend() {
  return requestClient.get<{ timestamp: string; value: number }[]>('/dashboard/vuln-trend');
}

export function getTaskTrend() {
  return requestClient.get<{ timestamp: string; value: number }[]>('/dashboard/task-trend');
}

export function getTopVulnAssets() {
  return requestClient.get<{ host: string; vuln_count: number; risk_score: number }[]>('/dashboard/top-vuln-assets');
}

export function getTaskStatusDist() {
  return requestClient.get<Record<string, number>>('/dashboard/task-status');
}

export function getRecentActivity() {
  return requestClient.get<RecentActivity[]>('/dashboard/recent-activity');
}

export async function getRecentTasks(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/task/list', { params });
  return normalizePagedResponse(res);
}
