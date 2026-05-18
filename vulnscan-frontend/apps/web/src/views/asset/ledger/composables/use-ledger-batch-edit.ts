import { computed, reactive, ref } from 'vue';
import { useMessage } from 'naive-ui';

import { batchUpdateAssets } from '#/api/asset';

import { BATCH_EDIT_FIELD_OPTIONS, EMPTY_BATCH_EDIT_FORM } from '../constants';
import type { LedgerBatchEditForm } from '../types';

export function useLedgerBatchEdit(options: {
  getCheckedRowKeys: () => string[];
  reload: () => Promise<void>;
}) {
  const message = useMessage();
  const showBatchEditModal = ref(false);
  const batchUpdating = ref(false);
  const batchEditForm = reactive<LedgerBatchEditForm>(EMPTY_BATCH_EDIT_FORM());
  const batchEditFieldOptions = computed(() => BATCH_EDIT_FIELD_OPTIONS.map((item) => ({ ...item })));

  function resetBatchEditForm() {
    Object.assign(batchEditForm, EMPTY_BATCH_EDIT_FORM());
  }

  function openBatchEditModal() {
    if (options.getCheckedRowKeys().length === 0) {
      message.warning('请先选择需要批量编辑的资产');
      return;
    }
    resetBatchEditForm();
    showBatchEditModal.value = true;
  }

  function resolveBatchEditValue() {
    if (!batchEditForm.field) {
      message.warning('请选择需要更新的字段');
      return null;
    }
    if (batchEditForm.field === 'is_key' || batchEditForm.field === 'is_online') {
      const value = String(batchEditForm.value ?? '');
      if (value !== 'true' && value !== 'false') {
        message.warning('请选择是或否');
        return null;
      }
      return { [batchEditForm.field]: value === 'true' };
    }

    const text = String(batchEditForm.value ?? '').trim();
    if (!text) {
      message.warning('请填写更新值');
      return null;
    }
    return { [batchEditForm.field]: text };
  }

  async function submitBatchEdit() {
    const ids = options.getCheckedRowKeys();
    if (ids.length === 0) {
      message.warning('请先选择需要批量编辑的资产');
      return;
    }

    const updates = resolveBatchEditValue();
    if (!updates) {
      return;
    }

    batchUpdating.value = true;
    try {
      await batchUpdateAssets(ids, updates);
      message.success(`已批量更新 ${ids.length} 项资产`);
      showBatchEditModal.value = false;
      resetBatchEditForm();
      await options.reload();
    } finally {
      batchUpdating.value = false;
    }
  }

  return {
    batchUpdating,
    batchEditFieldOptions,
    batchEditForm,
    showBatchEditModal,
    openBatchEditModal,
    submitBatchEdit,
  };
}
