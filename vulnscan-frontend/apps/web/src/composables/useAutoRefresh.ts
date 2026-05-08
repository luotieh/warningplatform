import { onBeforeUnmount, onMounted, ref, watch } from 'vue';

interface UseAutoRefreshOptions {
  task: () => Promise<void> | void;
  interval?: number;
  immediate?: boolean;
  pauseOnHidden?: boolean;
  runOnMount?: boolean;
}

export function useAutoRefresh(options: UseAutoRefreshOptions) {
  const {
    task,
    interval: initialInterval = 60_000,
    immediate = true,
    pauseOnHidden = true,
    runOnMount = false,
  } = options;

  const enabled = ref(immediate);
  const interval = ref(initialInterval);
  const running = ref(false);

  let timerId: null | ReturnType<typeof setTimeout> = null;

  async function run() {
    if (running.value) return;
    running.value = true;
    try {
      await task();
    } finally {
      running.value = false;
    }
  }

  function clearTimer() {
    if (timerId !== null) {
      clearTimeout(timerId);
      timerId = null;
    }
  }

  function schedule() {
    clearTimer();
    if (!enabled.value) return;
    if (pauseOnHidden && typeof document !== 'undefined' && document.hidden) {
      return;
    }
    timerId = setTimeout(async () => {
      await run();
      schedule();
    }, interval.value);
  }

  function handleVisibilityChange() {
    if (!pauseOnHidden) return;
    if (document.hidden) {
      clearTimer();
    } else {
      schedule();
    }
  }

  onMounted(() => {
    if (runOnMount) void run();
    schedule();
    if (pauseOnHidden && typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', handleVisibilityChange);
    }
  });

  onBeforeUnmount(() => {
    clearTimer();
    if (pauseOnHidden && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    }
  });

  watch([enabled, interval], () => {
    schedule();
  });

  return {
    enabled,
    interval,
    running,
    run,
  };
}
