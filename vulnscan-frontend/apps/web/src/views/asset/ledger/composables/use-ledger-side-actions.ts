import { ref } from 'vue';
import { useMessage } from 'naive-ui';

import { batchDeleteAssets, exportAssets, type Asset } from '#/api/asset';
import { getRequestErrorMessage } from '#/api/helpers';
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
  clearSelection: () => void;
  reload: () => Promise<void>;
}) {
  const message = useMessage();
  const sendingToMonitor = ref(false);
  const exporting = ref(false);
  const batchDeleting = ref(false);
  const showMonitorResult = ref(false);
  const monitorResult = ref<any>(null);

  async function handleBatchDelete() {
    const ids = options.getCheckedRowKeys();
    if (ids.length === 0) {
      message.warning('请先选择资产');
      return;
    }
    batchDeleting.value = true;
    try {
      const res = await batchDeleteAssets(ids);
      const affected = (res as { affected?: number })?.affected ?? ids.length;
      message.success(`已删除 ${affected} 条资产`);
      options.clearSelection();
      await options.reload();
    } catch (error: unknown) {
      message.error(getRequestErrorMessage(error, '批量删除失败'));
    } finally {
      batchDeleting.value = false;
    }
  }

  function confirmBatchDelete() {
    const ids = options.getCheckedRowKeys();
    if (ids.length === 0) {
      message.warning('请先选择资产');
      return;
    }
    const ok = window.confirm(
      `确认删除已选的 ${ids.length} 条资产？删除后不可恢复。`,
    );
    if (!ok) return;
    void handleBatchDelete();
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
    batchDeleting,
    showMonitorResult,
    monitorResult,
    handleBatchDelete,
    confirmBatchDelete,
    sendToMonitor,
    exportCurrentAssets,
  };
}
