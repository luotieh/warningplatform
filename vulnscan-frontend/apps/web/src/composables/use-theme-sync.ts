import { onMounted, onUnmounted } from 'vue';

import { preferencesManager } from '@vben/preferences';

export interface IamThemePayload {
  /** Theme mode from IAM. */
  mode?: 'auto' | 'dark' | 'light';
  /** Primary brand color. */
  colorPrimary?: string;
  /** Legacy field from older iframe messages. Ignored by this subsystem. */
  semiDarkSidebar?: boolean;
  /** Naive/Vben border radius. */
  radius?: string;
}

const IAM_THEME_MSG_TYPE = 'iam:theme-sync';
const IAM_THEME_STORAGE_KEY = 'iam_theme';
const THEME_MODES = ['auto', 'dark', 'light'] as const;
type ThemeMode = (typeof THEME_MODES)[number];

const SHELL_THEME = {
  builtinType: 'default',
  semiDarkHeader: false,
  semiDarkSidebar: false,
} as const;

function safeDecode(value: string) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function normalizeThemePayload(value: unknown): IamThemePayload | null {
  if (!value) return null;

  if (typeof value === 'string') {
    const decoded = safeDecode(value);
    if (THEME_MODES.includes(decoded as ThemeMode)) {
      return { mode: decoded as ThemeMode };
    }

    try {
      return normalizeThemePayload(JSON.parse(decoded));
    } catch {
      return null;
    }
  }

  if (typeof value === 'object') {
    const payload = value as IamThemePayload;
    if (
      payload.mode ||
      payload.colorPrimary ||
      payload.semiDarkSidebar !== undefined ||
      payload.radius
    ) {
      return payload;
    }
  }

  return null;
}

function persistTheme(payload: IamThemePayload) {
  try {
    localStorage.setItem(IAM_THEME_STORAGE_KEY, JSON.stringify(payload));
  } catch {
    // Storage can be unavailable in some embedded browser contexts.
  }
}

function applyTheme(payload: IamThemePayload) {
  const theme: Record<string, unknown> = {};

  if (payload.mode) {
    theme.mode = payload.mode;
  }

  if (payload.colorPrimary) {
    theme.colorPrimary = payload.colorPrimary;
  }

  if (payload.radius) {
    theme.radius = payload.radius;
  }

  if (Object.keys(theme).length > 0) {
    preferencesManager.updatePreferences({ theme });
  }
}

export function enforceAppShellTheme() {
  const currentTheme = preferencesManager.getPreferences().theme ?? {};
  preferencesManager.updatePreferences({
    theme: {
      ...SHELL_THEME,
      colorPrimary: currentTheme.colorPrimary,
      mode: currentTheme.mode,
      radius: currentTheme.radius,
    },
  });
}

function handleMessage(event: MessageEvent) {
  if (!event.data) return;

  let payload: IamThemePayload | null = null;

  if (event.data.type === IAM_THEME_MSG_TYPE && event.data.payload) {
    payload = normalizeThemePayload(event.data.payload);
  } else if (
    event.data.source === 'iam' &&
    event.data.type === 'theme-change' &&
    event.data.theme
  ) {
    payload = normalizeThemePayload(event.data.theme);
  } else if (
    event.data.source === 'iam' &&
    event.data.type === 'iframe-params' &&
    event.data.data?.iam_theme
  ) {
    payload = normalizeThemePayload(event.data.data.iam_theme);
  }

  if (payload) {
    applyTheme(payload);
    persistTheme(payload);
  }
}

function loadFromURL(): IamThemePayload | null {
  try {
    const url = new URL(window.location.href);
    return normalizeThemePayload(url.searchParams.get(IAM_THEME_STORAGE_KEY));
  } catch {
    return null;
  }
}

function loadFromStorage(): IamThemePayload | null {
  try {
    return normalizeThemePayload(localStorage.getItem(IAM_THEME_STORAGE_KEY));
  } catch {
    return null;
  }
}

export function applyInitialThemeFromParent() {
  const fromURL = loadFromURL();
  const fromStorage = loadFromStorage();
  const initial = fromURL || fromStorage;

  if (!initial) {
    return false;
  }

  applyTheme(initial);
  if (fromURL) {
    persistTheme(fromURL);
  }
  return true;
}

/**
 * Sync the child system theme with IAM.
 *
 * Priority at startup: URL param > localStorage > app defaults.
 * Runtime updates are received through postMessage.
 */
export function useThemeSync() {
  let handler: null | ((e: MessageEvent) => void) = null;

  onMounted(() => {
    applyInitialThemeFromParent();

    handler = handleMessage;
    window.addEventListener('message', handler);
  });

  onUnmounted(() => {
    if (handler) {
      window.removeEventListener('message', handler);
    }
  });
}

export function postThemeToIframe(
  target: Window | null | undefined,
  payload: IamThemePayload,
  targetOrigin = '*',
) {
  target?.postMessage({ type: IAM_THEME_MSG_TYPE, payload }, targetOrigin);
}
