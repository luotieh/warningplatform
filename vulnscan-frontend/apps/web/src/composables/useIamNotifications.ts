import type { NotificationItem } from '@vben/layouts';

import { computed, onUnmounted, ref, shallowRef } from 'vue';

import { useAccessStore } from '@vben/stores';

import { notification as naiveNotification } from '#/adapter/naive';
import {
  deleteNotification,
  getNotificationList,
  getUnreadCount,
  markAllNotificationsRead,
  markNotificationRead,
} from '#/api/message';

function generateLocalAvatar(seed: string): string {
  let hash = 0;
  for (const ch of String(seed || 'U')) {
    hash = ((hash << 5) - hash + ch.charCodeAt(0)) | 0;
  }
  const hue = ((hash % 360) + 360) % 360;
  const initial = (String(seed)[0] || 'U').toUpperCase();
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40"><rect width="40" height="40" rx="20" fill="hsl(${hue},55%,55%)"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" fill="#fff" font-size="18" font-family="sans-serif">${initial}</text></svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

const POLL_INTERVAL = 30_000;
const WS_RECONNECT_DELAY = 5000;
const WS_MAX_RECONNECT_DELAY = 60_000;

const notifications = shallowRef<NotificationItem[]>([]);
const unreadCount = ref(0);
const lastUpdated = ref(0);
let timer: ReturnType<typeof setInterval> | null = null;
let consumers = 0;
let visibilityBound = false;
let wsConnected = false;

function formatRelativeTime(input?: number | string): string {
  if (!input) return '';
  const ts =
    typeof input === 'string'
      ? new Date(input).getTime()
      : input < 1e12
        ? input * 1000
        : input;
  if (Number.isNaN(ts)) return '';
  const diff = Date.now() - ts;
  if (diff < 0) return new Date(ts).toLocaleString();
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec} 秒前`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min} 分钟前`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h} 小时前`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d} 天前`;
  return new Date(ts).toLocaleDateString();
}

function stripHtml(html: string): string {
  if (!html) return '';
  return html.replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').trim();
}

function mapToItem(raw: any): NotificationItem {
  const id = raw.id;
  const link =
    raw.link ||
    raw.url ||
    (id ? `/message/notification?id=${id}` : undefined);
  const rawContent = raw.content || raw.body || raw.summary || '';
  return {
    id,
    avatar: raw.avatar || generateLocalAvatar(raw.user_id || raw.id || ''),
    date: formatRelativeTime(raw.created_at || raw.send_time),
    isRead: Boolean(raw.is_read || raw.read_at),
    title: raw.title || raw.subject || '系统通知',
    message: stripHtml(rawContent),
    link,
  };
}

async function fetchAll() {
  try {
    const [list, count] = await Promise.all([
      getNotificationList({ size: 20 }),
      getUnreadCount().catch(() => ({ count: 0 })),
    ]);
    notifications.value = (list?.items ?? []).map(mapToItem);
    unreadCount.value = count?.count ?? 0;
    lastUpdated.value = Date.now();
  } catch {
    // 静默失败
  }
}

function startPolling() {
  if (timer) return;
  timer = setInterval(fetchAll, POLL_INTERVAL);
}

function stopPolling() {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

function handleVisibilityChange() {
  if (document.hidden) {
    stopPolling();
    if (wsReconnectTimer) {
      clearTimeout(wsReconnectTimer);
      wsReconnectTimer = null;
    }
  } else if (consumers > 0) {
    if (!wsConnected) startPolling();
    if (wsUrl && !wsExplicitlyClosed && (!socket || socket.readyState > WebSocket.OPEN)) {
      connectNotificationWS();
    }
  }
}

function bindVisibility() {
  if (visibilityBound || typeof document === 'undefined') return;
  document.addEventListener('visibilitychange', handleVisibilityChange);
  visibilityBound = true;
}

async function markRead(id: number | string) {
  try {
    await markNotificationRead(String(id));
    const item = notifications.value.find((n) => n.id === id);
    if (item && !item.isRead) {
      item.isRead = true;
      unreadCount.value = Math.max(0, unreadCount.value - 1);
    }
  } catch {
    // ignore
  }
}

async function markAllRead() {
  try {
    await markAllNotificationsRead();
    notifications.value = notifications.value.map((n) => ({
      ...n,
      isRead: true,
    }));
    unreadCount.value = 0;
  } catch {
    // ignore
  }
}

async function remove(id: number | string) {
  try {
    await deleteNotification(String(id));
  } catch {
    // ignore
  }
  notifications.value = notifications.value.filter((n) => n.id !== id);
}

function clear() {
  notifications.value = [];
}

let socket: null | WebSocket = null;
let wsReconnectTimer: null | ReturnType<typeof setTimeout> = null;
let wsReconnectDelay = WS_RECONNECT_DELAY;
let wsExplicitlyClosed = false;
let wsUrl: null | string = null;

function buildWsUrl(path: string, token: string) {
  const u = new URL(path, window.location.origin);
  if (u.protocol === 'http:') u.protocol = 'ws:';
  else if (u.protocol === 'https:') u.protocol = 'wss:';
  if (token) u.searchParams.set('token', token);
  return u.toString();
}

function handleWsPayload(raw: string) {
  let payload: any;
  try {
    payload = JSON.parse(raw);
  } catch {
    return;
  }
  const type = payload?.type || payload?.event || 'notification';

  if (type === 'unread_count') {
    if (typeof payload.count === 'number') {
      unreadCount.value = payload.count;
    }
    return;
  }

  if (type === 'notification' || type === 'message' || type === 'security') {
    const item = mapToItem(payload.data || payload);
    notifications.value = [item, ...notifications.value].slice(0, 50);
    if (!item.isRead) unreadCount.value += 1;
    naiveNotification.create({
      title: item.title,
      content: item.message,
      duration: 4000,
      keepAliveOnHover: true,
    });
  }
}

export function connectNotificationWS(path?: string) {
  if (!path || typeof window === 'undefined') return;
  const accessStore = useAccessStore();
  const token = accessStore.accessToken || '';
  if (!token) return;

  wsExplicitlyClosed = false;
  wsUrl = buildWsUrl(path, token);

  if (
    socket &&
    (socket.readyState === WebSocket.OPEN ||
      socket.readyState === WebSocket.CONNECTING)
  ) {
    return;
  }

  try {
    socket = new WebSocket(wsUrl);
  } catch {
    scheduleReconnect();
    return;
  }

  socket.addEventListener('open', () => {
    wsReconnectDelay = WS_RECONNECT_DELAY;
    wsConnected = true;
    stopPolling();
  });

  socket.addEventListener('message', (event) => {
    handleWsPayload(event.data);
  });

  socket.addEventListener('close', () => {
    socket = null;
    wsConnected = false;
    if (!wsExplicitlyClosed) {
      if (consumers > 0) startPolling();
      scheduleReconnect();
    }
  });

  socket.addEventListener('error', () => {
    socket?.close();
  });
}

function scheduleReconnect() {
  if (wsReconnectTimer) return;
  if (typeof document !== 'undefined' && document.hidden) return;
  wsReconnectTimer = setTimeout(() => {
    wsReconnectTimer = null;
    if (wsUrl && !wsExplicitlyClosed && !document.hidden) {
      wsReconnectDelay = Math.min(
        wsReconnectDelay * 2,
        WS_MAX_RECONNECT_DELAY,
      );
      connectNotificationWS();
    }
  }, wsReconnectDelay);
}

export function disconnectNotificationWS() {
  wsExplicitlyClosed = true;
  if (wsReconnectTimer) {
    clearTimeout(wsReconnectTimer);
    wsReconnectTimer = null;
  }
  socket?.close();
  socket = null;
  wsConnected = false;
}

export function useIamNotifications() {
  consumers++;
  fetchAll();
  bindVisibility();
  connectNotificationWS();
  if (!wsConnected) startPolling();

  onUnmounted(() => {
    consumers--;
    if (consumers <= 0) {
      stopPolling();
    }
  });

  return {
    notifications,
    unreadCount,
    showDot: computed(() => unreadCount.value > 0),
    refresh: fetchAll,
    markRead,
    markAllRead,
    remove,
    clear,
    connectWS: connectNotificationWS,
    disconnectWS: disconnectNotificationWS,
  };
}
