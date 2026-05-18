<script lang="ts" setup>
import type { FormInst, TreeOption } from 'naive-ui';

import { ref, watch } from 'vue';
import {
  NButton,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NSpace,
  NTreeSelect,
} from 'naive-ui';

import { quickOrganizeFormRules } from '#/utils/form-rules';

import type { LedgerQuickOrganizeForm } from '../types';

defineOptions({ name: 'LedgerQuickOrganizeModal' });

const props = defineProps<{
  show: boolean;
  loading?: boolean;
  form: LedgerQuickOrganizeForm;
  orgTreeOptions: TreeOption[];
}>();

const emit = defineEmits<{
  close: [];
  submit: [];
  'update:show': [value: boolean];
}>();

const formRef = ref<FormInst | null>(null);

watch(
  () => props.show,
  (visible) => {
    if (!visible) formRef.value?.restoreValidation();
  },
);

async function handleSubmit() {
  try {
    await formRef.value?.validate();
    emit('submit');
  } catch {
    /* 校验未通过 */
  }
}
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    title="快速新增单位"
    style="width: min(520px, calc(100vw - 32px))"
    @update:show="(value) => emit('update:show', value)"
  >
    <NForm ref="formRef" :model="form" :rules="quickOrganizeFormRules" label-placement="top">
      <NFormItem label="单位名称" required>
        <NInput v-model:value="form.name" placeholder="请输入单位名称" />
      </NFormItem>
      <NFormItem label="上级单位">
        <NTreeSelect
          v-model:value="form.parentId"
          filterable
          clearable
          default-expand-all
          key-field="key"
          label-field="label"
          children-field="children"
          :options="orgTreeOptions"
          placeholder="不选则为顶级单位"
        />
      </NFormItem>
      <NFormItem label="统一社会信用代码" path="unifiedSocialCreditCode">
        <NInput v-model:value="form.unifiedSocialCreditCode" placeholder="18 位，可选" maxlength="18" />
      </NFormItem>
      <p class="ledger-quick-organize__hint">
        保存后将自动选为当前资产的所属单位，并刷新单位列表。
      </p>
    </NForm>

    <template #footer>
      <NSpace justify="end">
        <NButton @click="emit('close')">取消</NButton>
        <NButton type="primary" :loading="loading" @click="handleSubmit">确认新增</NButton>
      </NSpace>
    </template>
  </NModal>
</template>

<style scoped>
.ledger-quick-organize__hint {
  color: var(--n-text-color-3);
  font-size: 12px;
  line-height: 1.5;
  margin: 0;
}
</style>
