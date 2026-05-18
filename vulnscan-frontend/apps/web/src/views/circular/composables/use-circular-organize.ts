import { ref } from 'vue';

import { getIamOrganizeTree, getOrganizeTree } from '#/api/assetmgr';
import { buildOrgTreeOptions, flattenOrgTree } from '#/views/asset/ledger/utils';

import { buildLabelToIdMap, resolveOrganizeIdByHint } from '../utils';

export function useCircularOrganizeMaps() {
  const idToLabel = ref<Record<string, string>>({});
  const labelToId = ref<Record<string, string>>({});
  const knownIds = ref<Set<string>>(new Set());
  const loading = ref(false);

  async function ensureLoaded() {
    if (Object.keys(idToLabel.value).length > 0) return;
    loading.value = true;
    try {
      let nodes: unknown[] = [];
      try {
        const res = await getOrganizeTree();
        nodes = Array.isArray(res) ? res : ((res as { data?: unknown[] })?.data ?? []);
      } catch {
        nodes = [];
      }
      if (!nodes.length) {
        try {
          const iam = await getIamOrganizeTree();
          nodes = Array.isArray(iam) ? iam : ((iam as { data?: unknown[] })?.data ?? []);
        } catch {
          nodes = [];
        }
      }
      const options = buildOrgTreeOptions(nodes as never[]);
      idToLabel.value = flattenOrgTree(options);
      labelToId.value = buildLabelToIdMap(idToLabel.value);
      knownIds.value = new Set(Object.keys(idToLabel.value));
    } finally {
      loading.value = false;
    }
  }

  function displayOrganize(idOrName?: string | null) {
    if (!idOrName) return '-';
    return idToLabel.value[idOrName] ?? idOrName;
  }

  function resolveOrganizeId(hint?: string | null): string | null {
    if (!hint) return null;
    return resolveOrganizeIdByHint(hint, labelToId.value, knownIds.value);
  }

  return {
    ensureLoaded,
    displayOrganize,
    resolveOrganizeId,
    loading,
  };
}
