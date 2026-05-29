export async function fetchAuthImageObjectUrl(url: string) {
  if (!url) return '';

  const requestUrl = normalizeBackendApiUrl(url);

  try {
    const { baseRequestClient } = await import('#/api/request');
    const resp = await baseRequestClient.get(requestUrl, {
      responseType: 'blob',
    });
    const blob = resp.data instanceof Blob ? resp.data : new Blob([resp.data]);
    if (!blob.size) {
      throw new Error('empty image');
    }
    const ct = blob.type || '';
    if (ct && !ct.startsWith('image/')) {
      throw new Error(`unexpected content-type: ${ct}`);
    }
    return URL.createObjectURL(blob);
  } catch {
    // fallback to raw fetch with auth header
  }

  const { useAccessStore } = await import('@vben/stores');
  const accessStore = useAccessStore();
  const headers: Record<string, string> = {};
  if (accessStore.accessToken) {
    headers.Authorization = `Bearer ${accessStore.accessToken}`;
  }

  const resp = await fetch(requestUrl, { headers, credentials: 'same-origin' });
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}`);
  }

  const ct = resp.headers.get('content-type') || '';
  if (ct && !ct.startsWith('image/')) {
    throw new Error(`unexpected content-type: ${ct}`);
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
