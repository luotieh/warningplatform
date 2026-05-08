import { onActivated, onDeactivated, onMounted, onUnmounted, ref } from 'vue';

interface UsePollingOptions {
  /** 轮询间隔（毫秒） */
  interval: number;
  /** 是否在挂载时立即执行一次 */
  immediate?: boolean;
}

/**
 * 智能轮询 composable：页面不可见或组件 deactivated 时自动暂停，
 * 重新可见 / activated 时自动恢复并立即刷新一次。
 */
export function usePolling(fn: () => Promise<void> | void, options: UsePollingOptions) {
  const { interval, immediate = true } = options;

  let timer: ReturnType<typeof setInterval> | null = null;
  const isActive = ref(true);
  const lastUpdated = ref('');

  function start() {
    stop();
    timer = setInterval(async () => {
      if (!isActive.value) return;
      await fn();
      lastUpdated.value = new Date().toLocaleTimeString();
    }, interval);
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  function pause() {
    isActive.value = false;
  }

  async function resume() {
    if (isActive.value) return;
    isActive.value = true;
    await fn();
    lastUpdated.value = new Date().toLocaleTimeString();
  }

  function onVisibilityChange() {
    if (document.hidden) {
      pause();
    } else {
      resume();
    }
  }

  onMounted(async () => {
    if (immediate) {
      await fn();
      lastUpdated.value = new Date().toLocaleTimeString();
    }
    start();
    document.addEventListener('visibilitychange', onVisibilityChange);
  });

  onUnmounted(() => {
    stop();
    document.removeEventListener('visibilitychange', onVisibilityChange);
  });

  onActivated(() => {
    isActive.value = true;
    start();
    fn();
  });

  onDeactivated(() => {
    isActive.value = false;
    stop();
  });

  return { lastUpdated, isActive, pause, resume };
}
