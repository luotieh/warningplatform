/**
 * 网站监测模块 - API 函数集合
 *
 * 使用 requestClient 发送请求（IAM Token 自动注入）
 * 路径与后端约定保持一致：所有接口均挂在 /monitor 前缀下
 */
import type {
  AlertConfig,
  DashboardStats,
  DimensionConfig,
  FileEntry,
  FileLibrary,
  ImportResult,
  MonitorAgent,
  MonitorDefaultConfig,
  MonitorExecution,
  MonitorReportData,
  MonitorReportRequest,
  MonitorTask,
  PageParams,
  TaskCreateDTO,
  TaskExecutionStat,
  WordCategory,
  WordEntry,
  WordLibrary,
} from './types';

import { requestClient } from '#/api/request';

const base = (url: string) => `/sitemonitor${url}`;

// ════════════════════════════════════════
// 词库 API
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

// ════════════════════════════════════════
// 词库分类 API
// ════════════════════════════════════════

export const getWordCategoryList = (libraryId: string) =>
  requestClient.get<WordCategory[]>(base(`/word-categories/${libraryId}`));

export const createWordCategory = (data: Partial<WordCategory>) =>
  requestClient.post<{ id: string }>(base('/word-categories'), data);

export const updateWordCategory = (id: string, data: Partial<WordCategory>) =>
  requestClient.put(base(`/word-categories/${id}`), data);

export const deleteWordCategory = (id: string) =>
  requestClient.delete(base(`/word-categories/${id}`));

// ════════════════════════════════════════
// 词条 API
// ════════════════════════════════════════

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

// ════════════════════════════════════════
// 文件库 API
// ════════════════════════════════════════

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

// ════════════════════════════════════════
// 文件条目 API
// ════════════════════════════════════════

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

// ════════════════════════════════════════
// 默认配置 API
// ════════════════════════════════════════

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
// 任务 API
// ════════════════════════════════════════

export const fetchTaskMeta = (url: string) =>
  requestClient.get<{ error?: string; title: string; url: string }>(
    base('/tasks/fetch-meta'),
    { params: { url } },
  );

export const getTaskList = (
  params?: PageParams & { enabled?: string; name?: string },
) =>
  requestClient.get<{ count: number; data: MonitorTask[] }>(base('/tasks'), {
    params,
    responseReturn: 'body',
  } as any);

export const createTask = (data: TaskCreateDTO) =>
  requestClient.post<{ id: string }>(base('/tasks'), data);

export const createTasksFromAssets = (assetIds: string[]) =>
  requestClient.post<{
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
  }>(base('/tasks/from-assets'), {
    asset_ids: assetIds,
  });

export const getTaskDetail = (id: string) =>
  requestClient.get<MonitorTask>(base(`/tasks/${id}`));

export const updateTask = (id: string, data: Partial<MonitorTask>) =>
  requestClient.put(base(`/tasks/${id}`), data);

export const deleteTask = (id: string) =>
  requestClient.delete(base(`/tasks/${id}`));

export const getTaskTrend = (id: string, hours = 24) =>
  requestClient.get<any>(base(`/tasks/${id}/trend`), { params: { hours } });

export const runTask = (id: string, dimensions?: string[]) =>
  requestClient.post<{ execution_ids: string[] }>(
    base(`/tasks/run/${id}`),
    dimensions ? { dimensions } : {},
  );

export const batchToggleEnabled = (ids: string[]) =>
  requestClient.put(base('/tasks/batch/toggle-enabled'), { ids });

export const batchUpdateConfigs = (
  ids: string[],
  configs: Partial<Record<string, DimensionConfig>>,
) => {
  const data: any = { ids };
  for (const [dim, cfg] of Object.entries(configs)) {
    data[`config_${dim}`] = cfg;
  }
  return requestClient.put(base('/tasks/batch/update-configs'), data);
};

export const batchSyncNames = (ids: string[]) =>
  requestClient.put(base('/tasks/batch/sync-names'), { ids });

export const batchDeleteTasks = (ids: string[]) =>
  requestClient.delete(base('/tasks/batch/delete'), { data: { ids } });

// ════════════════════════════════════════
// 执行记录 API
// ════════════════════════════════════════

export const getTaskExecutionStats = () =>
  requestClient.get<Record<string, Record<string, TaskExecutionStat>>>(
    base('/tasks/execution-stats'),
  );

export const getExecutionList = (
  params?: PageParams & {
    dimension?: string;
    disposition?: string;
    has_issue?: string;
    status?: string;
    task_id?: string;
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
  type: 'html' | 'screenshot',
) => base(`/executions/${executionId}/evidence/${type}`);

export const getDashboardStats = () =>
  requestClient.get<DashboardStats>(base('/dashboard/stats'));

export const generateMonitorReport = (data: MonitorReportRequest) =>
  requestClient.post<MonitorReportData>(base('/reports/generate'), data);

// ════════════════════════════════════════
// Agent API
// ════════════════════════════════════════

export const getAgentList = () =>
  requestClient.get<MonitorAgent[]>(base('/agents'));

export const syncAgentRules = (uuid: string) =>
  requestClient.post(base(`/agents/${uuid}/sync-rules`));

export const shutdownAgent = (uuid: string) =>
  requestClient.post(base(`/agents/${uuid}/shutdown`));

// ════════════════════════════════════════
// 规则数据 API
// ════════════════════════════════════════

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

// ════════════════════════════════════════
// 告警配置 API
// ════════════════════════════════════════

export const getAlertConfig = () =>
  requestClient.get<AlertConfig>(base('/alert-config'));

export const updateAlertConfig = (config: Partial<AlertConfig>) =>
  requestClient.put(base('/alert-config'), config);

// ════════════════════════════════════════
// 批量导入 API
// ════════════════════════════════════════

export const downloadImportTemplate = () =>
  base('/tasks/import/template');

export const importTasks = (file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  return requestClient.post<ImportResult>(base('/tasks/import'), formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
};

export const getImportResult = (importId: string) =>
  requestClient.get<ImportResult>(base(`/tasks/import/result/${importId}`));

export const exportImportResultUrl = (importId: string) =>
  base(`/tasks/import/result/${importId}/export`);

export type * from './types';
