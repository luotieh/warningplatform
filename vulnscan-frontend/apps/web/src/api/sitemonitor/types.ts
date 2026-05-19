/**
 * 网站监测模块 - 类型定义（目标 + 路径任务模型）
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
// 词库 / 文件库
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
// 维度配置
// ════════════════════════════════════════

export type CycleType =
  | 'daily'
  | 'monthly'
  | 'quarterly'
  | 'semi_annual'
  | 'weekly';

export interface DimensionConfig {
  alert_enabled?: boolean;
  cron?: string;
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
  /** 监测发现问题后是否自动转为安全事件 */
  incident_auto_enabled?: boolean;
  /** 可用性：站点不可用时转事件 */
  incident_on_unavailable?: boolean;
  /** 可用性：响应时间超过该值(ms)时转事件，0 表示不启用 */
  incident_max_response_time_ms?: number;
  /** 敏感词：至少命中条数 */
  incident_min_match_count?: number;
  /** 敏感文件：至少发现文件数 */
  incident_min_file_count?: number;
  /** 篡改：至少差异处数 */
  incident_min_diff_count?: number;
  /** 暗链：至少发现条数（含后门） */
  incident_min_blacklink_count?: number;
  /** 域名劫持：检测到劫持时转事件 */
  incident_on_hijack?: boolean;
  [key: string]: any;
}

// ════════════════════════════════════════
// 监测目标 & 路径任务
// ════════════════════════════════════════

export type MonitorTargetType = 'domain' | 'ip';

export interface MonitorTarget {
  id: string;
  name: string;
  target_type: MonitorTargetType;
  target_value: string;
  default_scheme: string;
  virtual_host: string;
  expected_ips: string;
  asset_id?: string;
  enabled: boolean;
  notes: string;
  schedule_enabled: boolean;
  schedule_cron: string;
  schedule_jitter: number;
  next_run_at: null | string;
  config_domain_hijack: DimensionConfig;
  config_sensitive_file: DimensionConfig;
  last_run_domain_hijack: null | string;
  last_run_sensitive_file: null | string;
  created_by?: string;
  organize_id?: string;
  created_at: string;
  updated_at: string;
}

export interface MonitorPathTask {
  id: string;
  target_id: string;
  name: string;
  path: string;
  url_override: string;
  asset_id?: string;
  enabled: boolean;
  notes: string;
  schedule_enabled: boolean;
  schedule_cron: string;
  schedule_jitter: number;
  next_run_at: null | string;
  config_availability: DimensionConfig;
  config_tamper: DimensionConfig;
  config_sensitive_word: DimensionConfig;
  config_blacklink: DimensionConfig;
  last_run_availability: null | string;
  last_run_tamper: null | string;
  last_run_sensitive_word: null | string;
  last_run_blacklink: null | string;
  created_at: string;
  updated_at: string;
}

export interface MonitorCrawlJob {
  id: string;
  target_id: string;
  status: string;
  use_headless: boolean;
  max_depth: number;
  max_pages: number;
  same_host: boolean;
  error: string;
  result_json: string;
  started_at: null | string;
  finished_at: null | string;
  created_at: string;
}

export interface CrawlPageResult {
  url: string;
  title: string;
  status_code: number;
  depth: number;
  source: string;
}

export interface CrawlResult {
  pages: CrawlPageResult[];
  errors: number;
  duration_ms: number;
}

export interface TargetUpdateDTO {
  name?: string;
  notes?: string;
  enabled?: boolean;
  target_type?: MonitorTargetType;
  target_value?: string;
  default_scheme?: string;
  virtual_host?: string;
  expected_ips?: string;
  schedule_enabled?: boolean;
  schedule_cron?: string;
  config_domain_hijack?: DimensionConfig;
  config_sensitive_file?: DimensionConfig;
}

export interface PathTaskUpdateDTO {
  name?: string;
  notes?: string;
  enabled?: boolean;
  path?: string;
  url_override?: string;
  schedule_enabled?: boolean;
  schedule_cron?: string;
  config_availability?: DimensionConfig;
  config_tamper?: DimensionConfig;
  config_sensitive_word?: DimensionConfig;
  config_blacklink?: DimensionConfig;
}

/** @deprecated 使用 MonitorPathTask */
export type MonitorTask = MonitorPathTask & {
  task_name?: string;
  target_homepage?: string;
  target_domain?: string;
  target_ips?: string;
  config_domain_hijack?: DimensionConfig;
};

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
  target_id: string;
  path_task_id: string;
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
// Agent / 仪表盘
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

export interface DashboardStats {
  total_targets: number;
  enabled_targets: number;
  total_path_tasks: number;
  enabled_path_tasks: number;
  total_executions: number;
  issue_executions: number;
  online_agents: number;
  total_agents: number;
}

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

export interface RunTaskOutcome {
  execution_ids: string[];
  skipped?: Array<{ dimension: string; reason: string }>;
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

export interface TaskTrendResp {
  task_id: string;
  task_name: string;
  url: string;
  points: Array<{
    time: string;
    dimension?: string;
    status?: string;
    disposition?: string;
    available: boolean;
    status_code: number;
    total_ms: number;
    dns_ms: number;
    tcp_connect_ms: number;
    tls_handshake_ms: number;
    ttfb_ms: number;
    has_issue: boolean;
  }>;
  summary: Record<string, number>;
  dimensions: Array<{
    dimension: string;
    total: number;
    success_count: number;
    failed_count: number;
    issue_count: number;
    last_status: string;
    last_time: string;
  }>;
}
