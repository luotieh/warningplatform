<script lang="ts" setup>
import type { TreeOption } from 'naive-ui';

import { computed, watch } from 'vue';
import { NButton, NForm, NFormItem, NInput, NModal, NSelect, NSpace, NTreeSelect } from 'naive-ui';

import type { LedgerBatchEditForm, LedgerOption } from '../types';

defineOptions({ name: 'LedgerBatchEditModal' });

const props = defineProps<{
  show: boolean;
  loading?: boolean;
  selectedCount: number;
  form: LedgerBatchEditForm;
  fieldOptions: LedgerOption[];
  sourceOptions: LedgerOption[];
  securityOptions: LedgerOption[];
  orgTreeOptions: TreeOption[];
}>();

const emit = defineEmits<{
  close: [];
  submit: [];
  'update:show': [value: boolean];
}>();

const booleanOptions = [
  { label: '是', value: 'true' },
  { label: '否', value: 'false' },
];

const selectValue = computed<string | null>({
  get: () => {
    const value = props.form.value;
    return value === null || value === undefined || value === '' ? null : String(value);
  },
  set: (value) => {
    props.form.value = value ?? '';
  },
});

const textValue = computed<string>({
  get: () => String(props.form.value ?? ''),
  set: (value) => {
    props.form.value = value;
  },
});

watch(
  () => props.form.field,
  () => {
    props.form.value = '';
  },
);
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    title="批量编辑资产"
    style="width: min(640px, calc(100vw - 32px))"
    @update:show="(value) => emit('update:show', value)"
  >
    <NForm label-placement="top">
      <NFormItem :label="`已选择 ${selectedCount} 项资产`">
        <div class="ledger-batch-edit__hint">本次仅更新同一字段，避免批量操作时误改其他信息。</div>
      </NFormItem>

      <NFormItem label="编辑字段" required>
        <NSelect v-model:value="form.field" :options="fieldOptions" placeholder="请选择需要更新的字段" />
      </NFormItem>

      <NFormItem v-if="form.field === 'organize_id'" label="所属单位" required>
        <NTreeSelect
          v-model:value="selectValue"
          filterable
          :options="orgTreeOptions"
          placeholder="请选择所属单位"
        />
      </NFormItem>

      <NFormItem v-else-if="form.field === 'data_source'" label="数据来源" required>
        <NSelect v-model:value="selectValue" :options="sourceOptions" placeholder="请选择数据来源" />
      </NFormItem>

      <NFormItem v-else-if="form.field === 'security_protection_level'" label="等保等级" required>
        <NSelect v-model:value="selectValue" :options="securityOptions" placeholder="请选择等保等级" />
      </NFormItem>

      <NFormItem v-else-if="form.field === 'is_key'" label="重点资产" required>
        <NSelect v-model:value="selectValue" :options="booleanOptions" placeholder="请选择是否为重点资产" />
      </NFormItem>

      <NFormItem v-else-if="form.field === 'is_online'" label="在线状态" required>
        <NSelect v-model:value="selectValue" :options="booleanOptions" placeholder="请选择在线状态" />
      </NFormItem>

      <NFormItem v-else-if="form.field === 'responsible_user_name'" label="责任人" required>
        <NInput v-model:value="textValue" placeholder="请输入责任人姓名" />
      </NFormItem>

      <NFormItem v-else-if="form.field === 'remark'" label="备注" required>
        <NInput v-model:value="textValue" type="textarea" :rows="4" placeholder="请输入备注信息" />
      </NFormItem>
    </NForm>

    <template #footer>
      <NSpace justify="end">
        <NButton @click="emit('close')">取消</NButton>
        <NButton type="primary" :loading="loading" @click="emit('submit')">确认更新</NButton>
      </NSpace>
    </template>
  </NModal>
</template>

<style scoped>
.ledger-batch-edit__hint {
  color: var(--n-text-color-2);
  line-height: 1.6;
}
</style>
