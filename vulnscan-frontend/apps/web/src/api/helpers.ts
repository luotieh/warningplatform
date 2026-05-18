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

export function normalizePagedResponse<T = any>(res: any): { items: T[]; total: number } {
  const body = res?.data ?? res;
  return {
    items: (body?.data ?? body?.items ?? []) as T[],
    total: Number(body?.count ?? body?.total ?? 0),
  };
}

export function normalizeListResponse<T = any>(res: any): T[] {
  const body = res?.data ?? res;
  return ((body as { data?: T[] })?.data ?? []) as T[];
}
