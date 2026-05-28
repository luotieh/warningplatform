const installedKey = '__vulnscan_network_guard_installed__';

function getAllowedOrigins() {
  const origins = new Set([window.location.origin]);
  const apiUrl = import.meta.env.VITE_GLOB_API_URL?.trim();
  if (apiUrl?.startsWith('http://') || apiUrl?.startsWith('https://')) {
    origins.add(new URL(apiUrl).origin);
  }

  const extra = import.meta.env.VITE_ALLOWED_BACKEND_ORIGINS?.trim();
  if (extra) {
    for (const item of extra.split(',')) {
      const origin = item.trim();
      if (origin) origins.add(new URL(origin).origin);
    }
  }
  return origins;
}

function isAllowedFetchUrl(input: Parameters<typeof fetch>[0]) {
  const raw =
    typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url;

  if (!raw.startsWith('http://') && !raw.startsWith('https://')) {
    return true;
  }

  return getAllowedOrigins().has(new URL(raw).origin);
}

export function installFrontendNetworkGuard() {
  const win = window as any;
  if (win[installedKey]) return;
  win[installedKey] = true;

  const nativeFetch = window.fetch.bind(window);
  window.fetch = ((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    if (!isAllowedFetchUrl(input)) {
      const raw =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      return Promise.reject(
        new Error(`Blocked external frontend request: ${raw}`),
      );
    }
    return nativeFetch(input, init);
  }) as typeof fetch;
}
