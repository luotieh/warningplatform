import { message } from '#/adapter/naive';

export function extractErrorMessage(error: unknown, fallback = '操作失败'): string {
  if (!error) return fallback;
  if (typeof error === 'string') return error;
  const e = error as Record<string, any>;
  return e?.message || e?.msg || e?.error || fallback;
}

export function useErrorHandler() {
  function handleError(error: unknown, fallback?: string) {
    const msg = extractErrorMessage(error, fallback);
    message.error(msg);
    console.error('[Error]', error);
  }

  async function tryCatch<T>(
    fn: () => Promise<T>,
    options?: { fallback?: string; silent?: boolean },
  ): Promise<T | undefined> {
    try {
      return await fn();
    } catch (error) {
      if (!options?.silent) {
        handleError(error, options?.fallback);
      }
      return undefined;
    }
  }

  return { handleError, tryCatch, extractErrorMessage };
}
