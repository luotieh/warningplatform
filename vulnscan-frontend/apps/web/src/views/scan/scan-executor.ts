import { ref } from 'vue';

import { getUnifiedNodes, type UnifiedNode } from '#/api/cluster';

export const EXECUTOR_LOCAL_ID = 'local';

export type ScanExecutorOption = { label: string; value: string; disabled?: boolean };

export function appendExecutorNodeParams(
  params: Record<string, unknown>,
  executorNodeIds: string[],
) {
  const ids =
    executorNodeIds?.length > 0 ? [...executorNodeIds] : [EXECUTOR_LOCAL_ID];
  params.executor_node_ids = ids;
}

export function useScanExecutorNodes() {
  const executorNodeIds = ref<string[]>([EXECUTOR_LOCAL_ID]);
  const executorNodeOptions = ref<ScanExecutorOption[]>([
    { label: '本地执行引擎（默认）', value: EXECUTOR_LOCAL_ID },
  ]);
  const executorNodesLoading = ref(false);

  async function loadExecutorNodeOptions() {
    executorNodesLoading.value = true;
    try {
      const res = await getUnifiedNodes();
      const nodes = (res?.nodes ?? []) as UnifiedNode[];
      const options: ScanExecutorOption[] = [];
      for (const node of nodes) {
        if (node.type !== 'local' && node.type !== 'worker') continue;
        const online = node.status === 'online' || node.type === 'local';
        const suffix =
          node.type === 'local'
            ? ' · 本机'
            : online
              ? ''
              : ' · 离线';
        options.push({
          label: `${node.name || node.id}${suffix}`,
          value: node.id,
          disabled: node.type === 'worker' && !online,
        });
      }
      if (!options.some((o) => o.value === EXECUTOR_LOCAL_ID)) {
        options.unshift({ label: '本地执行引擎（默认）', value: EXECUTOR_LOCAL_ID });
      }
      executorNodeOptions.value = options;
      if (
        executorNodeIds.value.length === 0 ||
        !executorNodeIds.value.every((id) => options.some((o) => o.value === id && !o.disabled))
      ) {
        executorNodeIds.value = [EXECUTOR_LOCAL_ID];
      }
    } catch {
      executorNodeOptions.value = [
        { label: '本地执行引擎（默认）', value: EXECUTOR_LOCAL_ID },
      ];
      executorNodeIds.value = [EXECUTOR_LOCAL_ID];
    } finally {
      executorNodesLoading.value = false;
    }
  }

  return {
    executorNodeIds,
    executorNodeOptions,
    executorNodesLoading,
    loadExecutorNodeOptions,
    appendExecutorNodeParams,
  };
}
