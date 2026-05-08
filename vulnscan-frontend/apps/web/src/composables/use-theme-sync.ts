/**
 * 主题同步 composable
 *
 * 支持两种场景：
 * 1. iframe 嵌入：监听来自 IAM 主框架的 postMessage
 * 2. 独立部署：启动时从 URL 参数 / localStorage 读取 IAM 主题配置
 *
 * IAM 主框架通过 postMessage 发送：
 * { type: 'iam:theme-sync', payload: { mode: 'dark', colorPrimary: '#1890ff', ... } }
 *
 * 或通过 URL 参数 / localStorage key 'iam_theme' 传递 JSON 字符串。
 */
import { onMounted, onUnmounted } from 'vue';

import { preferencesManager } from '@vben/preferences';

export interface IamThemePayload {
  /** 主题模式：light | dark | auto */
  mode?: 'auto' | 'dark' | 'light';
  /** 主色 */
  colorPrimary?: string;
  /** 是否半黑暗模式 */
  semiDarkSidebar?: boolean;
  /** 圆角大小 */
  radius?: string;
}

const IAM_THEME_MSG_TYPE = 'iam:theme-sync';
const IAM_THEME_STORAGE_KEY = 'iam_theme';

function applyTheme(payload: IamThemePayload) {
  const updates: Record<string, any> = {};

  if (payload.mode) {
    updates.theme = { mode: payload.mode };
  }
  if (payload.colorPrimary) {
    updates.theme = { ...(updates.theme || {}), colorPrimary: payload.colorPrimary };
  }
  if (payload.semiDarkSidebar !== undefined) {
    updates.sidebar = { ...(updates.sidebar || {}), theme: payload.semiDarkSidebar ? 'dark' : 'light' };
  }
  if (payload.radius) {
    updates.theme = { ...(updates.theme || {}), radius: payload.radius };
  }

  if (Object.keys(updates).length > 0) {
    preferencesManager.updatePreferences(updates);
  }
}

function handleMessage(event: MessageEvent) {
  if (!event.data) return;

  let payload: IamThemePayload | null = null;

  if (event.data.type === IAM_THEME_MSG_TYPE && event.data.payload) {
    payload = event.data.payload;
  } else if (
    event.data.source === 'iam' &&
    event.data.type === 'theme-change' &&
    event.data.theme
  ) {
    payload = { mode: event.data.theme };
  } else if (
    event.data.source === 'iam' &&
    event.data.type === 'iframe-params' &&
    event.data.data?.iam_theme
  ) {
    payload = { mode: event.data.data.iam_theme };
  }

  if (payload) {
    applyTheme(payload);
    try {
      localStorage.setItem(IAM_THEME_STORAGE_KEY, JSON.stringify(payload));
    } catch {
      // ignore
    }
  }
}

function loadFromURL(): IamThemePayload | null {
  try {
    const url = new URL(window.location.href);
    const themeParam = url.searchParams.get('iam_theme');
    if (themeParam) {
      return JSON.parse(decodeURIComponent(themeParam));
    }
  } catch {
    // ignore
  }
  return null;
}

function loadFromStorage(): IamThemePayload | null {
  try {
    const raw = localStorage.getItem(IAM_THEME_STORAGE_KEY);
    if (raw) return JSON.parse(raw);
  } catch {
    // ignore
  }
  return null;
}

/**
 * 自动同步 IAM 主题到子系统
 *
 * 启动时优先级：URL 参数 > localStorage > 默认值
 * 运行时通过 postMessage 实时同步。
 */
export function useThemeSync() {
  let handler: ((e: MessageEvent) => void) | null = null;

  onMounted(() => {
    const fromURL = loadFromURL();
    const fromStorage = loadFromStorage();
    const initial = fromURL || fromStorage;

    if (initial) {
      applyTheme(initial);
      if (fromURL) {
        try {
          localStorage.setItem(IAM_THEME_STORAGE_KEY, JSON.stringify(fromURL));
        } catch {
          // ignore
        }
      }
    }

    handler = handleMessage;
    window.addEventListener('message', handler);
  });

  onUnmounted(() => {
    if (handler) {
      window.removeEventListener('message', handler);
    }
  });
}

/**
 * IAM 主框架侧：向 iframe 发送主题变更
 *
 * 示例（在 IAM 主框架中调用）：
 *   postThemeToIframe(iframeRef.value?.contentWindow, { mode: 'dark', colorPrimary: '#1890ff' })
 */
export function postThemeToIframe(
  target: Window | null | undefined,
  payload: IamThemePayload,
  targetOrigin = '*',
) {
  target?.postMessage({ type: IAM_THEME_MSG_TYPE, payload }, targetOrigin);
}
