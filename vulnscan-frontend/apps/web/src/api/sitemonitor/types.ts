/**
 * 网站监测模块 - 类型定义
 * 与后端 monitor 模块保持一致
 */

export interface PageParams {
  index?: number;
  size?: number;
}

export interface PageResult<T> {
  list: T[];
  total: number;
  index?: number;
  size?: number;
}

// ════════════════════════════════════════
// 词库
// ════════════════════════════════════════

export interface WordLibrary {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface WordCategory {
  id: string;
  library_id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface WordEntry {
  id: number;
  category_id: string;
  word: string;
  severity: string;
  created_at: string;
}

// ════════════════════════════════════════
// 文件库
// ════════════════════════════════════════

export interface FileLibrary {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface FileEntry {
  id: number;
  library_id: string;
  path: string;
  mark: string;
  risk: string;
  created_at: string;
}

// ════════════════════════════════════════
// 6 大维度配置
// ════════════════════════════════════════

export type CycleType =
  | 'daily'
  | 'monthly'
  | 'quarterly'
  | 'semi_annual'
  | 'weekly';

export interface DimensionConfig {
  alert_enabled?: boolean;
  cycle_day_of_month?: number;
  cycle_day_of_week?: number;
  cycle_minutes?: number;
  cycle_time?: string;
  cycle_type?: CycleType;
  enabled?: boolean;
  exclude_status_codes?: string;
  exclude_time_enabled?: boolean;
  exclude_time_end?: string;
  exclude_time_start?: string;
  file_library_ids?: string[];
  run_once?: boolean;
  search_engine_ua?: boolean;
  timeout_seconds?: number;
  word_library_ids?: string[];
  [key: string]: any;
}

// ════════════════════════════════════════
// 监测任务
// ════════════════════════════════════════

export interface MonitorTask {
  id: string;
  task_name: string;
  asset_id?: string;
  enabled: boolean;
  notes: string;
  target_homepage: string;
  target_domain: string;
  target_subdomains: string;
  target_ips: string;
  schedule_enabled: boolean;
  schedule_cron: string;
  schedule_group: string;
  schedule_jitter: number;
  next_run_at: null | string;
  config_availability: DimensionConfig;
  config_domain_hijack: DimensionConfig;
  config_tamper: DimensionConfig;
  config_sensitive_file: DimensionConfig;
  config_sensitive_word: DimensionConfig;
  config_blacklink: DimensionConfig;
  last_run_availability: null | string;
  last_run_domain_hijack: null | string;
  last_run_tamper: null | string;
  last_run_sensitive_file: null | string;
  last_run_sensitive_word: null | string;
  last_run_blacklink: null | string;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface TaskCreateDTO {
  task_name: string;
  target_homepage: string;
  target_domain?: string;
  target_ips?: string;
  schedule_enabled?: boolean;
  schedule_cron?: string;
  enable_availability?: boolean;
  enable_domain_hijack?: boolean;
  enable_tamper?: boolean;
  enable_sensitive_file?: boolean;
  enable_sensitive_word?: boolean;
  enable_blacklink?: boolean;
  config_availability?: DimensionConfig;
  config_domain_hijack?: DimensionConfig;
  config_tamper?: DimensionConfig;
  config_sensitive_file?: DimensionConfig;
  config_sensitive_word?: DimensionConfig;
  config_blacklink?: DimensionConfig;
}

export interface MonitorDefaultConfig {
  id: string;
  dimension: string;
  config_json: DimensionConfig;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

// ════════════════════════════════════════
// 执行记录
// ════════════════════════════════════════

export interface MonitorExecution {
  id: string;
  task_id: string;
  agent_id: string;
  dimension: string;
  url: string;
  status: string;
  has_issue: boolean;
  error: string;
  result_json: string;
  started_at: string;
  finished_at: string;
  created_at: string;
  disposition?: string;
  disposition_remark?: string;
}

// ════════════════════════════════════════
// Agent 节点
// ════════════════════════════════════════

export interface MonitorAgent {
  id: string;
  uuid: string;
  version: string;
  status: string;
  mac_address: string;
  ip_address: string;
  region: string;
  label: string;
  running_tasks: number;
  queued_tasks: number;
  max_concurrent: number;
  max_queue: number;
  cpu_usage: number;
  memory_usage: number;
  tasks_completed: number;
  last_heartbeat: null | string;
  updated_at: string;
  created_at: string;
}

// ════════════════════════════════════════
// 仪表盘
// ════════════════════════════════════════

export interface DashboardStats {
  total_tasks: number;
  enabled_tasks: number;
  total_executions: number;
  issue_executions: number;
  online_agents: number;
  total_agents: number;
}

// ════════════════════════════════════════
// 规则数据
// ════════════════════════════════════════

export interface RuleDataSummary {
  module_key: string;
  name: string;
  description: string;
  type: string;
  has_data: boolean;
  updated_at: string;
}

export interface RuleDataDetail {
  module_key: string;
  data: string;
  updated_at: string;
}

export interface FieldDef {
  key: string;
  label: string;
  required: boolean;
  type: string;
}

export interface SectionDef {
  key: string;
  label: string;
  fields: FieldDef[];
}

export interface ModuleDef {
  key: string;
  name: string;
  description: string;
  type: string;
  kv_key: string;
  sections: SectionDef[];
}

// ════════════════════════════════════════
// 告警配置
// ════════════════════════════════════════

export interface AlertConfig {
  id?: string;
  silence_duration_minutes: number;
  max_alerts_per_hour: number;
  webhook_url: string;
  webhook_secret: string;
  email_enabled: boolean;
  email_receivers: string;
  dingtalk_enabled: boolean;
  dingtalk_webhook: string;
  dingtalk_secret: string;
  wechat_enabled: boolean;
  wechat_webhook: string;
  alert_enabled: boolean;
}

// ════════════════════════════════════════
// 批量导入
// ════════════════════════════════════════

export interface ImportRowResult {
  row: number;
  name: string;
  url: string;
  success: boolean;
  task_id?: string;
  error?: string;
}

export interface ImportResult {
  id: string;
  total: number;
  success: number;
  failed: number;
  results: ImportRowResult[];
  created_at: string;
}

export interface TaskExecutionStat {
  total: number;
  issue_count: number;
  pending_count?: number;
  valid_count?: number;
}

export interface MonitorReportRequest {
  start_date: string;
  end_date: string;
  task_ids: string[];
  format?: 'html' | 'json';
}

export interface MonitorReportDimensionStat {
  Total?: number;
  Issues?: number;
  IssueRate?: number;
}

export interface MonitorTaskReportItem {
  TaskName?: string;
  URL?: string;
  Executions?: number;
  Issues?: number;
  IssueRate?: number;
  LastRun?: string;
  DimResults?: Record<string, string>;
}

export interface MonitorReportSLAStats {
  AvailabilityRate?: number;
  AvgResponseMS?: number;
  P95ResponseMS?: number;
  UptimeHours?: number;
  DowntimeMinutes?: number;
  MeetsSLA?: boolean;
  SLATarget?: number;
}

export interface MonitorReportComplianceItem {
  Category?: string;
  Name?: string;
  Status?: string;
  Description?: string;
  Suggestion?: string;
}

export interface MonitorReportComplianceResult {
  Level?: string;
  Score?: number;
  Items?: MonitorReportComplianceItem[];
  PassCount?: number;
  WarnCount?: number;
  FailCount?: number;
}

export interface MonitorReportData {
  Title?: string;
  GeneratedAt?: string;
  Period?: string;
  StartDate?: string;
  EndDate?: string;
  Summary?: {
    TotalTasks?: number;
    EnabledTasks?: number;
    TotalExecutions?: number;
    IssueCount?: number;
    IssueRate?: number;
    OnlineAgents?: number;
    DimStats?: Record<string, MonitorReportDimensionStat>;
  };
  TaskReports?: MonitorTaskReportItem[];
  SLAStats?: MonitorReportSLAStats;
  Compliance?: MonitorReportComplianceResult;
}
