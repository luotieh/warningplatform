<script lang="ts" setup>
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
  NSwitch,
} from 'naive-ui';

import { regionOptions } from '#/utils/region';

import type { LedgerConstructionForm } from '../types';

defineOptions({ name: 'LedgerQuickConstructionModal' });

defineProps<{
  show: boolean;
  loading?: boolean;
  form: LedgerConstructionForm;
  target: 'construction' | 'operation';
  linkToBoth: boolean;
}>();

const emit = defineEmits<{
  close: [];
  submit: [];
  'update:show': [value: boolean];
  'update:linkToBoth': [value: boolean];
}>();
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    :title="target === 'construction' ? '快速新增建设单位' : '快速新增运维单位'"
    style="width: min(760px, calc(100vw - 32px))"
    @update:show="(value) => emit('update:show', value)"
  >
    <NForm label-placement="top">
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
          <NFormItem label="联系电话">
            <NInput v-model:value="form.charge_phone" placeholder="请输入联系电话" />
          </NFormItem>
        </NGridItem>
        <NGridItem :span="2">
          <NFormItem label="公网安备案号">
            <NInput v-model:value="form.security_filing" placeholder="请输入公网安备案号" />
          </NFormItem>
        </NGridItem>
      </NGrid>

      <div class="ledger-quick-construction__switch">
        <NSwitch
          :value="linkToBoth"
          @update:value="(value) => emit('update:linkToBoth', value)"
        />
        <div>
          <div>同时关联建设和运维单位</div>
          <div class="ledger-quick-construction__hint">保存后会自动回填到当前资产表单</div>
        </div>
      </div>
    </NForm>

    <template #footer>
      <NSpace justify="end">
        <NButton @click="emit('close')">取消</NButton>
        <NButton type="primary" :loading="loading" @click="emit('submit')">确认新增</NButton>
      </NSpace>
    </template>
  </NModal>
</template>

<style scoped>
.ledger-quick-construction__switch {
  align-items: center;
  border-top: 1px dashed var(--n-border-color);
  display: flex;
  gap: 12px;
  margin-top: 8px;
  padding-top: 16px;
}

.ledger-quick-construction__hint {
  color: var(--n-text-color-3);
  font-size: 12px;
  margin-top: 4px;
}
</style>
