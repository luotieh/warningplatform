import { ref } from 'vue';

import { syncAssetOnlineStatus } from '#/api/asset';

const syncing = ref(false);
let inflight: Promise<void> | null = null;

/** 对指定资产做轻量可达性探测（不阻塞列表首屏时可后台调用）。 */
export async function runAssetOnlineSync(
  params?: Record<string, unknown>,
  assetIds?: string[],
) {
  if (!assetIds?.length) {
    return;
  }
  if (inflight) {
    return inflight;
  }
  syncing.value = true;
  inflight = syncAssetOnlineStatus(params, assetIds)
    .then(() => undefined)
    .catch(() => undefined)
    .finally(() => {
      syncing.value = false;
      inflight = null;
    });
  return inflight;
}

export function useAssetOnlineSync() {
  return { syncing, runAssetOnlineSync };
}
