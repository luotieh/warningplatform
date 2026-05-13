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
