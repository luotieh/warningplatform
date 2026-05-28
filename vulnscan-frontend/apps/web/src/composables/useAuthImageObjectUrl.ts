export async function fetchAuthImageObjectUrl(url: string) {
  if (!url) return '';

  const requestUrl = normalizeBackendApiUrl(url);
  const { useAccessStore } = await import('@vben/stores');
  const accessStore = useAccessStore();
  const headers: Record<string, string> = {};
  if (accessStore.accessToken) {
    headers.Authorization = `Bearer ${accessStore.accessToken}`;
  }

  const resp = await fetch(requestUrl, { headers });
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}`);
  }

  const blob = await resp.blob();
  if (!blob.size) {
    throw new Error('empty image');
  }

  return URL.createObjectURL(blob);
}

export function normalizeBackendApiUrl(url: string) {
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return url;
  }

  const parsed = new URL(url);
  if (parsed.pathname.startsWith('/api/')) {
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  }

  return url;
}
