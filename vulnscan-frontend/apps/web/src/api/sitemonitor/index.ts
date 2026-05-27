/**
 * 网站监测模块 - API（目标 + 路径任务）
 */
import type {
  AlertConfig,
  CrawlResult,
  DashboardStats,
  DimensionConfig,
  FileEntry,
  FileLibrary,
  ImportResult,
  MonitorAgent,
  MonitorCrawlJob,
  MonitorDefaultConfig,
  MonitorExecution,
  MonitorPathTask,
  MonitorReportData,
  MonitorReportRequest,
  MonitorTarget,
  PageParams,
  PathTaskUpdateDTO,
  RunTaskOutcome,
  TargetUpdateDTO,
  TaskExecutionStat,
  TaskTrendResp,
  WordCategory,
  WordEntry,
  WordLibrary,
} from './types';

function resolvePathTaskFetchUrl(
  task: MonitorPathTask,
  target?: MonitorTarget | null,
): string {
  const override = task.url_override?.trim();
  if (override) return override;
  if (!target?.target_value) return '';
  const scheme = target.default_scheme || 'https';
  const path = task.path?.startsWith('/') ? task.path : `/${task.path || ''}`;
  return `${scheme}://${target.target_value}${path}`;
}

import { requestClient } from '#/api/request';

const base = (url: string) => `/sitemonitor${url}`;

// ════════════════════════════════════════
// 词库 / 文件库 / 默认配置（保持不变）
// ════════════════════════════════════════

export const getWordLibraryList = (params?: PageParams & { name?: string }) =>
  requestClient.get<{ count: number; data: WordLibrary[] }>(
    base('/word-libraries'),
    { params, responseReturn: 'body' } as any,
  );

export const createWordLibrary = (data: Partial<WordLibrary>) =>
  requestClient.post<{ id: string }>(base('/word-libraries'), data);

export const getWordLibraryDetail = (id: string) =>
  requestClient.get<WordLibrary>(base(`/word-libraries/${id}`));

export const updateWordLibrary = (id: string, data: Partial<WordLibrary>) =>
  requestClient.put(base(`/word-libraries/${id}`), data);

export const deleteWordLibrary = (id: string) =>
  requestClient.delete(base(`/word-libraries/${id}`));

export const getWordCategoryList = (libraryId: string) =>
  requestClient.get<WordCategory[]>(base(`/word-categories/${libraryId}`));

export const createWordCategory = (data: Partial<WordCategory>) =>
  requestClient.post<{ id: string }>(base('/word-categories'), data);

export const updateWordCategory = (id: string, data: Partial<WordCategory>) =>
  requestClient.put(base(`/word-categories/${id}`), data);

export const deleteWordCategory = (id: string) =>
  requestClient.delete(base(`/word-categories/${id}`));

export const getWordEntryList = (
  params: PageParams & { category_id: string; word?: string },
) =>
  requestClient.get<{ count: number; data: WordEntry[] }>(
    base('/word-entries'),
    { params, responseReturn: 'body' } as any,
  );

export const batchCreateWordEntries = (data: Partial<WordEntry>[]) =>
  requestClient.post(base('/word-entries'), data);

export const deleteWordEntries = (ids: number[]) =>
  requestClient.delete(base('/word-entries'), { data: { ids } });

export const importWordEntries = (
  file: File,
  categoryId: string,
  severity: string = 'medium',
) => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('category_id', categoryId);
  formData.append('severity', severity);
  return requestClient.post<{ duplicated: number; imported: number }>(
    base('/word-entries/import'),
    formData,
    { headers: { 'Content-Type': 'multipart/form-data' } },
  );
};

export const getFileLibraryList = (params?: PageParams & { name?: string }) =>
  requestClient.get<{ count: number; data: FileLibrary[] }>(
    base('/file-libraries'),
    { params, responseReturn: 'body' } as any,
  );

export const createFileLibrary = (data: Partial<FileLibrary>) =>
  requestClient.post<{ id: string }>(base('/file-libraries'), data);

export const getFileLibraryDetail = (id: string) =>
  requestClient.get<FileLibrary>(base(`/file-libraries/${id}`));

export const updateFileLibrary = (id: string, data: Partial<FileLibrary>) =>
  requestClient.put(base(`/file-libraries/${id}`), data);

export const deleteFileLibrary = (id: string) =>
  requestClient.delete(base(`/file-libraries/${id}`));

export const getFileEntryList = (
  params: PageParams & { library_id: string; path?: string },
) =>
  requestClient.get<{ count: number; data: FileEntry[] }>(
    base('/file-entries'),
    { params, responseReturn: 'body' } as any,
  );

export const batchCreateFileEntries = (data: Partial<FileEntry>[]) =>
  requestClient.post(base('/file-entries'), data);

export const deleteFileEntries = (ids: number[]) =>
  requestClient.delete(base('/file-entries'), { data: { ids } });

export const importFileEntries = (formData: FormData) =>
  requestClient.post(base('/file-entries/import'), formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });

export const getDefaultConfigList = () =>
  requestClient.get<MonitorDefaultConfig[]>(base('/default-configs'));

export const getDefaultConfig = (dimension: string) =>
  requestClient.get<MonitorDefaultConfig>(
    base(`/default-configs/${dimension}`),
  );

export const updateDefaultConfig = (
  dimension: string,
  data: { config_json: DimensionConfig },
) => requestClient.put(base(`/default-configs/${dimension}`), data);

// ════════════════════════════════════════
// 监测目标
// ════════════════════════════════════════

export const fetchPageMeta = (url: string) =>
  requestClient.get<{ error?: string; title: string; url: string }>(
    base('/fetch-meta'),
    { params: { url } },
  );

/** @deprecated 使用 fetchPageMeta */
export const fetchTaskMeta = fetchPageMeta;

export const getTargetList = (
  params?: PageParams & {
    enabled?: string;
    name?: string;
    target_type?: string;
    target_value?: string;
  },
) =>
  requestClient.get<{ count: number; data: MonitorTarget[] }>(
    base('/targets'),
    { params, responseReturn: 'body' } as any,
  );

export const createTarget = (data: Partial<MonitorTarget>) =>
  requestClient.post<MonitorTarget>(base('/targets'), data);

export const getTargetDetail = (id: string) =>
  requestClient.get<MonitorTarget>(base(`/targets/${id}`));

export const updateTarget = (id: string, data: TargetUpdateDTO) =>
  requestClient.put(base(`/targets/${id}`), data);

export const deleteTarget = (id: string) =>
  requestClient.delete(base(`/targets/${id}`));

export const runTarget = (id: string, dimensions?: string[]) =>
  requestClient.post<RunTaskOutcome>(base(`/targets/run/${id}`), {
    dimensions: dimensions ?? [],
  });

export const startCrawl = (
  targetId: string,
  data: {
    use_headless?: boolean;
    max_depth?: number;
    max_pages?: number;
    same_host?: boolean;
    start_url?: string;
    screenshot_width?: number;
    screenshot_height?: number;
    screenshot_quality?: number;
  },
) =>
  requestClient.post<MonitorCrawlJob>(base(`/targets/${targetId}/crawl`), data);

export const getCrawlJob = (jobId: string) =>
  requestClient.get<MonitorCrawlJob>(base(`/crawl-jobs/${jobId}`));

export const applyCrawlPaths = (
  jobId: string,
  data: { skip_existing?: boolean; selected_urls?: string[] } = {},
) =>
  requestClient.post<{ created: number }>(
    base(`/crawl-jobs/${jobId}/apply`),
    data,
  );

// ════════════════════════════════════════
// 路径任务
// ════════════════════════════════════════

export const getPathTaskList = (
  params?: PageParams & {
    target_id?: string;
    enabled?: string;
    name?: string;
  },
) =>
  requestClient.get<{ count: number; data: MonitorPathTask[] }>(
    base('/path-tasks'),
    { params, responseReturn: 'body' } as any,
  );

export const createPathTask = (data: Partial<MonitorPathTask>) =>
  requestClient.post<MonitorPathTask>(base('/path-tasks'), data);

export interface CreateTasksFromAssetsResult {
  total: number;
  success: number;
  results: Array<{
    asset_id: string;
    asset_name: string;
    task_id?: string;
    success: boolean;
    skipped: boolean;
    reason?: string;
    error?: string;
  }>;
}

/** 从资产台账批量创建监测目标与路径任务 */
export const createTasksFromAssets = (assetIds: string[]) =>
  requestClient.post<CreateTasksFromAssetsResult>(base('/targets/from-assets'), {
    asset_ids: assetIds,
  });

export const getPathTaskDetail = (id: string) =>
  requestClient.get<MonitorPathTask>(base(`/path-tasks/${id}`));

export const updatePathTask = (id: string, data: PathTaskUpdateDTO) =>
  requestClient.put(base(`/path-tasks/${id}`), data);

export const deletePathTask = (id: string) =>
  requestClient.delete(base(`/path-tasks/${id}`));

export interface PathTaskTrendParams {
  hours?: number;
  dimension?: string;
  has_issue?: string;
  disposition?: string;
  status?: string;
  time_start?: string;
  time_end?: string;
}

export const getPathTaskTrend = (id: string, params: number | PathTaskTrendParams = 24) => {
  const query = typeof params === 'number' ? { hours: params } : params;
  return requestClient.get<TaskTrendResp>(base(`/path-tasks/${id}/trend`), {
    params: query,
  });
};

export const runPathTask = (id: string, dimensions?: string[]) =>
  requestClient.post<RunTaskOutcome>(base(`/path-tasks/run/${id}`), {
    dimensions: dimensions ?? [],
  });

export const batchDeletePathTasks = (ids: string[]) =>
  requestClient.delete(base('/path-tasks/batch/delete'), { data: { ids } });

/** 批量启停路径任务（逐条切换 enabled） */
export async function batchToggleEnabled(ids: string[]) {
  await Promise.all(
    ids.map(async (id) => {
      const task = await getPathTaskDetail(id);
      await updatePathTask(id, { enabled: !task.enabled });
    }),
  );
}

/** 批量从页面标题同步任务名称 */
export async function batchSyncNames(ids: string[]) {
  let updated = 0;
  for (const id of ids) {
    const task = await getPathTaskDetail(id);
    const target = task.target_id
      ? await getTargetDetail(task.target_id)
      : null;
    const url = resolvePathTaskFetchUrl(task, target);
    if (!url) continue;
    try {
      const res = await fetchPageMeta(url);
      const meta = (res as { data?: { title?: string }; title?: string }).data ?? res;
      const title = meta?.title?.trim();
      if (!title) continue;
      await updatePathTask(id, { name: title });
      updated += 1;
    } catch {
      // 单条失败跳过
    }
  }
  return { data: { updated } };
}

/** 批量更新路径任务维度配置（目标级维度写入关联 target） */
export async function batchUpdateConfigs(
  ids: string[],
  cfgs: Partial<Record<string, DimensionConfig>>,
) {
  const pathPayload: PathTaskUpdateDTO = {};
  const targetPayload: TargetUpdateDTO = {};
  const pathKeys: Record<string, keyof PathTaskUpdateDTO> = {
    availability: 'config_availability',
    tamper: 'config_tamper',
    sensitive_word: 'config_sensitive_word',
    blacklink: 'config_blacklink',
  };
  const targetKeys: Record<string, keyof TargetUpdateDTO> = {
    domain_hijack: 'config_domain_hijack',
    sensitive_file: 'config_sensitive_file',
  };
  for (const [key, cfg] of Object.entries(cfgs)) {
    if (!cfg) continue;
    const pathField = pathKeys[key];
    if (pathField) pathPayload[pathField] = cfg;
    const targetField = targetKeys[key];
    if (targetField) targetPayload[targetField] = cfg;
  }
  const hasPath = Object.keys(pathPayload).length > 0;
  const hasTarget = Object.keys(targetPayload).length > 0;
  await Promise.all(
    ids.map(async (id) => {
      if (hasPath) await updatePathTask(id, pathPayload);
      if (hasTarget) {
        const task = await getPathTaskDetail(id);
        if (task.target_id) await updateTarget(task.target_id, targetPayload);
      }
    }),
  );
}

// ════════════════════════════════════════
// 执行记录 / 统计
// ════════════════════════════════════════

export const getPathTaskExecutionStats = () =>
  requestClient.get<Record<string, Record<string, TaskExecutionStat>>>(
    base('/execution-stats'),
  );

/** @deprecated */
export const getTaskExecutionStats = getPathTaskExecutionStats;

export const getExecutionList = (
  params?: PageParams & {
    dimension?: string;
    disposition?: string;
    has_issue?: string;
    status?: string;
    target_id?: string;
    path_task_id?: string;
    time_end?: string;
    time_start?: string;
  },
) =>
  requestClient.get<{ count: number; data: MonitorExecution[] }>(
    base('/executions'),
    { params, responseReturn: 'body' } as any,
  );

export const deleteExecution = (id: string) =>
  requestClient.delete(base(`/executions/${id}`));

export const batchDeleteExecutions = (ids: string[]) =>
  requestClient.delete(base('/executions/batch/delete'), { data: { ids } });

export const getExecutionDetail = (id: string) =>
  requestClient.get<MonitorExecution>(base(`/executions/${id}`));

export const updateDisposition = (
  id: string,
  disposition: string,
  remark?: string,
) =>
  requestClient.put(base(`/executions/${id}/disposition`), {
    disposition,
    remark,
  });

export const batchUpdateDisposition = (
  ids: string[],
  disposition: string,
  remark?: string,
) =>
  requestClient.put(base('/executions/batch/disposition'), {
    disposition,
    ids,
    remark,
  });

export const getEvidenceAssetUrl = (
  executionId: string,
  type: 'annotated_screenshot' | 'html' | 'screenshot',
) => base(`/executions/${executionId}/evidence/${type}`);

export const getDashboardStats = () =>
  requestClient.get<DashboardStats>(base('/dashboard/stats'));

export const generateMonitorReport = (data: MonitorReportRequest) =>
  requestClient.post<MonitorReportData>(base('/reports/generate'), data);

// ════════════════════════════════════════
// Agent / 规则 / 告警 / 导入
// ════════════════════════════════════════

export const getAgentList = () =>
  requestClient.get<MonitorAgent[]>(base('/agents'));

export const syncAgentRules = (uuid: string) =>
  requestClient.post(base(`/agents/${uuid}/sync-rules`));

export const shutdownAgent = (uuid: string) =>
  requestClient.post(base(`/agents/${uuid}/shutdown`));

export const deleteMonitorAgent = (uuid: string) =>
  requestClient.delete(base(`/agents/${uuid}`));

export const getRuleDataList = () =>
  requestClient.get<any[]>(base('/rule-data'));

export const getRuleData = (moduleKey: string) =>
  requestClient.get<any>(base(`/rule-data/${moduleKey}`));

export const putRuleData = (moduleKey: string, data: string) =>
  requestClient.put(base(`/rule-data/${moduleKey}`), { data });

export const syncAllRuleData = () =>
  requestClient.post(base('/rule-data/sync'));

export const importRuleData = (
  moduleKey: string,
  data: Record<string, any>,
  merge: boolean = false,
) =>
  requestClient.post(base(`/rule-data/${moduleKey}/import`), { data, merge });

export const resetDefaultRuleData = () =>
  requestClient.post(base('/rule-data/reset-defaults'));

export const getAlertConfig = () =>
  requestClient.get<AlertConfig>(base('/alert-config'));

export const updateAlertConfig = (config: Partial<AlertConfig>) =>
  requestClient.put(base('/alert-config'), config);

export const downloadImportTemplate = () => base('/import/template');

export const exportImportResultUrl = (importId: string) =>
  base(`/import/${importId}/export`);

export const importTargets = (file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  return requestClient.post<ImportResult>(base('/import'), formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
};

/** @deprecated */
export const importTasks = importTargets;

/** 将路径任务映射为旧版 MonitorTask 字段，供监测中心等页面过渡使用 */
function mapPathTaskToLegacy(pt: MonitorPathTask): MonitorPathTask & {
  task_name: string;
  target_homepage: string;
  target_domain: string;
  target_ips: string;
} {
  return {
    ...pt,
    task_name: pt.name,
    target_homepage: pt.url_override || pt.path || '/',
    target_domain: '',
    target_ips: '',
  };
}

/** @deprecated 使用 getPathTaskList */
export async function getTaskList(
  params?: PageParams & {
    enabled?: string;
    name?: string;
    target_homepage?: string;
  },
) {
  const res = await getPathTaskList({
    enabled: params?.enabled,
    index: params?.index,
    name: params?.name || params?.target_homepage,
    size: params?.size,
  });
  return {
    ...res,
    data: (res.data || []).map(mapPathTaskToLegacy),
  };
}

/** @deprecated */
export const getTaskDetail = getPathTaskDetail;

/** @deprecated */
export const getTaskTrend = getPathTaskTrend;

/** @deprecated */
export const runTask = runPathTask;

/** @deprecated */
export const createTask = createPathTask;

/** @deprecated */
export const updateTask = (id: string, data: Partial<MonitorPathTask>) =>
  updatePathTask(id, data as PathTaskUpdateDTO);

/** @deprecated */
export const deleteTask = deletePathTask;

/** @deprecated */
export const batchDeleteTasks = batchDeletePathTasks;

export type { CrawlResult };

export type * from './types';
