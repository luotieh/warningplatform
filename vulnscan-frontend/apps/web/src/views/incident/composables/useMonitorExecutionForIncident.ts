import type { MonitorExecution } from '#/api/sitemonitor';

import { computed, ref, watch, type Ref } from 'vue';

import { getExecutionDetail } from '#/api/sitemonitor';

const dimensionLabels: Record<string, string> = {
  availability: '可用性监测',
  blacklink: '暗链监测',
  domain_hijack: '域名劫持监测',
  sensitive_file: '敏感文件监测',
  sensitive_word: '敏感词监测',
  tamper: '篡改监测',
};

export function useMonitorExecutionForIncident(executionId: Ref<string | undefined>) {
  const loading = ref(false);
  const error = ref('');
  const execution = ref<MonitorExecution | null>(null);

  const parsedResult = computed(() => {
    const raw = execution.value?.result_json;
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  });

  const dimensionLabel = computed(() => {
    const d = execution.value?.dimension;
    return d ? dimensionLabels[d] || d : '';
  });

  async function fetchExecution() {
    const id = executionId.value;
    if (!id) {
      execution.value = null;
      error.value = '';
      return;
    }
    loading.value = true;
    error.value = '';
    try {
      const res: any = await getExecutionDetail(id);
      execution.value = res?.data ?? res;
    } catch (e: any) {
      execution.value = null;
      error.value = e?.msg || e?.message || '加载监测执行记录失败';
    } finally {
      loading.value = false;
    }
  }

  watch(executionId, () => fetchExecution(), { immediate: true });

  return {
    loading,
    error,
    execution,
    parsedResult,
    dimensionLabel,
    refetch: fetchExecution,
  };
}
