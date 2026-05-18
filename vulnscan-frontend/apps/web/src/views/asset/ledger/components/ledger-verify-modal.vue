<script lang="ts" setup>
import type { TreeOption } from 'naive-ui';

import { NButton, NForm, NFormItem, NInput, NModal, NSelect, NSpace, NTreeSelect } from 'naive-ui';

import type { LedgerOption, LedgerVerifyForm } from '../types';

defineOptions({ name: 'LedgerVerifyModal' });

defineProps<{
  show: boolean;
  loading?: boolean;
  form: LedgerVerifyForm;
  sourceOptions: LedgerOption[];
  orgTreeOptions: TreeOption[];
  selectedCount: number;
}>();

const emit = defineEmits<{
  close: [];
  submit: [];
  'update:show': [value: boolean];
}>();
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    title="下发核验任务"
    style="width: min(620px, calc(100vw - 32px))"
    @update:show="(value) => emit('update:show', value)"
  >
    <NForm label-placement="top">
      <NFormItem label="目标单位" required>
        <NTreeSelect
          v-model:value="form.targetOrganizeId"
          filterable
          clearable
          default-expand-all
          key-field="key"
          label-field="label"
          children-field="children"
          :options="orgTreeOptions"
          placeholder="请选择目标单位"
        />
      </NFormItem>

      <NFormItem label="来源">
        <NSelect v-model:value="form.sourceType" :options="sourceOptions" placeholder="请选择来源" />
      </NFormItem>

      <NFormItem :label="`备注（本次共 ${selectedCount} 项资产）`">
        <NInput v-model:value="form.remark" type="textarea" :rows="3" placeholder="请输入备注信息" />
      </NFormItem>
    </NForm>

    <template #footer>
      <NSpace justify="end">
        <NButton @click="emit('close')">取消</NButton>
        <NButton type="primary" :loading="loading" @click="emit('submit')">确认下发</NButton>
      </NSpace>
    </template>
  </NModal>
</template>
