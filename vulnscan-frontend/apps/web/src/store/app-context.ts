import { ref } from 'vue';

import { defineStore } from 'pinia';

/**
 * 子系统应用上下文 Store（精简版）
 *
 * 子系统不需要 AppSwitcher，只需要维护自身的应用 ID，
 * 用于拉取当前应用的菜单和权限。
 */
export const useAppContextStore = defineStore('app-context', () => {
  const currentAppId = ref<string>('');
  const loading = ref(false);

  async function loadApplications() {
    // 子系统不需要加载应用列表，IAM 在后端根据 Token 自动识别
  }

  function reconcileWithMenus(_appIdsWithMenus: string[]) {
    // 子系统无需纠偏
  }

  function setCurrentApp(appId: string) {
    currentAppId.value = appId;
  }

  function syncToIamIfNeeded() {
    // 子系统无需此逻辑
  }

  function $reset() {
    currentAppId.value = '';
  }

  return {
    applications: ref([]),
    currentAppId,
    currentApp: ref(undefined),
    isMicroFrontApp: ref(false),
    loading,
    loadApplications,
    setCurrentApp,
    syncToIamIfNeeded,
    reconcileWithMenus,
    $reset,
  };
});
