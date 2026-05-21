export interface ImportIssuePayload {
  row: number;
  field?: string;
  message: string;
}

/** 导入失败的问题行预览（与后端 failed_rows 对应）。 */
export interface ImportFailedRowPayload {
  row: number;
  name?: string;
  organize_name?: string;
  address?: string;
  asset_family?: string;
  is_online?: string;
  error_summary: string;
  issues?: ImportIssuePayload[];
}

interface ApiEnvelope {
  code?: number;
  msg?: string;
  data?: Record<string, unknown>;
}

/** 从接口异常中提取后端返回的 msg（供导入等场景在弹窗内展示）。 */
export function getRequestErrorMessage(error: unknown, fallback = '操作失败'): string {
  const err = error as {
    response?: { data?: { msg?: string; err?: string; message?: string } };
    message?: string;
  };
  const data = err?.response?.data;
  const msg = data?.msg ?? data?.err ?? data?.message ?? err?.message ?? '';
  return String(msg).trim() || fallback;
}

function normalizeImportIssues(raw: unknown): ImportIssuePayload[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (item): item is ImportIssuePayload =>
      item != null &&
      typeof item.row === 'number' &&
      typeof item.message === 'string',
  );
}

function normalizeImportFailedRows(raw: unknown): ImportFailedRowPayload[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (item): item is ImportFailedRowPayload =>
      item != null &&
      typeof item.row === 'number' &&
      typeof item.error_summary === 'string',
  );
}

function pickApiEnvelope(error: unknown): ApiEnvelope | null {
  const typed = error as {
    response?: { data?: ApiEnvelope };
    data?: ApiEnvelope;
  };
  const body = typed?.response?.data ?? typed?.data;
  if (!body || typeof body !== 'object') return null;
  return body;
}

export function parseImportFailureBody(body: ApiEnvelope | null | undefined) {
  if (!body) return null;
  const data = body.data;
  const issues = normalizeImportIssues(data?.errors);
  const failedRows = normalizeImportFailedRows(data?.failed_rows);
  const errorCount = Number(data?.error_count) || issues.length;
  if (issues.length === 0 && failedRows.length === 0 && !body.msg) {
    return null;
  }
  return {
    message: String(body.msg ?? '').trim() || '导入失败',
    issues,
    failedRows,
    errorCount,
  };
}

/** 资产导入失败时解析行级错误与问题行预览。 */
export function getImportErrorPayload(
  error: unknown,
  fallback = '导入失败',
): {
  message: string;
  issues: ImportIssuePayload[];
  failedRows: ImportFailedRowPayload[];
  errorCount: number;
} {
  const typed = error as {
    name?: string;
    message?: string;
    issues?: ImportIssuePayload[];
    failedRows?: ImportFailedRowPayload[];
    errorCount?: number;
  };

  if (typed?.name === 'AssetImportError') {
    const issues = normalizeImportIssues(typed.issues);
    const failedRows = normalizeImportFailedRows(typed.failedRows);
    const errorCount = typed.errorCount ?? issues.length;
    return {
      message: String(typed.message ?? '').trim() || fallback,
      issues,
      failedRows,
      errorCount,
    };
  }

  const parsed = parseImportFailureBody(pickApiEnvelope(error));
  if (parsed) {
    return parsed;
  }

  const typedErr = error as { message?: string };
  return {
    message: String(typedErr?.message ?? '').trim() || fallback,
    issues: [],
    failedRows: [],
    errorCount: 0,
  };
}

export function normalizePagedResponse<T = any>(res: any): { items: T[]; total: number } {
  const envelope = res?.data ?? res;
  const payload = envelope?.data ?? envelope;

  let items: T[] = [];
  if (Array.isArray(payload)) {
    items = payload as T[];
  } else if (payload && typeof payload === 'object') {
    if (Array.isArray(payload.data)) items = payload.data as T[];
    else if (Array.isArray(payload.items)) items = payload.items as T[];
    else if (Array.isArray(payload.list)) items = payload.list as T[];
  }
  if (items.length === 0) {
    if (Array.isArray(envelope?.items)) items = envelope.items as T[];
    else if (Array.isArray(envelope?.list)) items = envelope.list as T[];
  }

  const total = Number(
    (payload && typeof payload === 'object' && !Array.isArray(payload)
      ? payload.count ?? payload.total
      : undefined) ??
      envelope?.count ??
      envelope?.total ??
      items.length,
  );

  return { items, total };
}

export function normalizeListResponse<T = any>(res: any): T[] {
  const body = res?.data ?? res;
  return ((body as { data?: T[] })?.data ?? []) as T[];
}
