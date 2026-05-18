<script lang="ts" setup>
import type { FormInst } from 'naive-ui';

import { ref, watch } from 'vue';
import {
  NButton,
  NCascader,
  NForm,
  NFormItem,
  NGrid,
  NGridItem,
  NInput,
  NModal,
  NSpace,
} from 'naive-ui';

import { quickConstructionFormRules } from '#/utils/form-rules';
import { regionOptions } from '#/utils/region';

import type { LedgerConstructionForm } from '../types';

defineOptions({ name: 'LedgerQuickConstructionModal' });

const props = defineProps<{
  show: boolean;
  loading?: boolean;
  form: LedgerConstructionForm;
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
    title="快速新增运维单位"
    style="width: min(760px, calc(100vw - 32px))"
    @update:show="(value) => emit('update:show', value)"
  >
    <NForm ref="formRef" :model="form" :rules="quickConstructionFormRules" label-placement="top">
      <NGrid :cols="2" :x-gap="16">
        <NGridItem>
          <NFormItem label="单位名称" required>
            <NInput v-model:value="form.name" placeholder="请输入单位名称" />
          </NFormItem>
        </NGridItem>
        <NGridItem>
          <NFormItem label="所在地区">
            <NCascader
              v-model:value="form.location_code"
              :options="regionOptions"
              filterable
              clearable
              check-strategy="child"
              placeholder="请选择省 / 市 / 区县"
            />
          </NFormItem>
        </NGridItem>
        <NGridItem :span="2">
          <NFormItem label="详细地址">
            <NInput v-model:value="form.address" placeholder="请输入详细办公地址，可具体到门牌号" />
          </NFormItem>
        </NGridItem>
        <NGridItem>
          <NFormItem label="负责人及职务">
            <NInput v-model:value="form.charge_person" placeholder="请输入负责人及职务" />
          </NFormItem>
        </NGridItem>
        <NGridItem>
          <NFormItem label="联系电话" path="charge_phone">
            <NInput v-model:value="form.charge_phone" placeholder="11 位手机或固话" />
          </NFormItem>
        </NGridItem>
      </NGrid>
      <p class="ledger-quick-construction__hint">保存后将自动关联到当前资产的运维单位</p>
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
.ledger-quick-construction__hint {
  color: var(--n-text-color-3);
  font-size: 12px;
  margin: 12px 0 0;
}
</style>
