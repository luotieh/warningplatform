import { ref } from 'vue';
import { useMessage } from 'naive-ui';

import { deleteAsset, exportAssets, type Asset } from '#/api/asset';
import { createTasksFromAssets } from '#/api/sitemonitor';

import { downloadBlob } from '../file-utils';

function exportFileName(format: 'csv' | 'xlsx') {
  const now = new Date();
  const pad = (value: number) => String(value).padStart(2, '0');
  return `assets-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}.${format}`;
}

export function useLedgerSideActions(options: {
  buildQueryParams: () => Record<string, any>;
  getCheckedRowKeys: () => string[];
  getSelectedAssets: () => Asset[];
  reload: () => Promise<void>;
}) {
  const message = useMessage();
  const sendingToMonitor = ref(false);
  const exporting = ref(false);
  const showMonitorResult = ref(false);
  const monitorResult = ref<any>(null);

  async function handleBatchDelete() {
    const ids = options.getCheckedRowKeys();
    if (ids.length === 0) {
      message.warning('请先选择资产');
      return;
    }
    for (const id of ids) {
      await deleteAsset(id);
    }
    message.success('批量删除完成');
    await options.reload();
  }

  async function sendToMonitor() {
    const assets = options.getSelectedAssets();
    if (assets.length === 0) {
      message.warning('请先选择需要发送监测的资产');
      return;
    }
    sendingToMonitor.value = true;
    try {
      monitorResult.value = await createTasksFromAssets(assets.map((item) => item.id));
      showMonitorResult.value = true;
    } finally {
      sendingToMonitor.value = false;
    }
  }

  async function exportCurrentAssets(format: 'csv' | 'xlsx') {
    exporting.value = true;
    try {
      const blob = await exportAssets(options.buildQueryParams(), format);
      downloadBlob(blob, exportFileName(format));
    } finally {
      exporting.value = false;
    }
  }

  return {
    sendingToMonitor,
    exporting,
    showMonitorResult,
    monitorResult,
    handleBatchDelete,
    sendToMonitor,
    exportCurrentAssets,
  };
}
