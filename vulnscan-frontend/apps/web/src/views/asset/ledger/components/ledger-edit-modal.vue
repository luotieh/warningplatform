<script lang="ts" setup>
import type { FormInst, TreeOption } from 'naive-ui';

import { computed, ref, watch } from 'vue';
import { useLocalStorage, useWindowSize } from '@vueuse/core';
import { IconifyIcon } from '@vben/icons';
import {
  NButton,
  NButtonGroup,
  NCascader,
  NDivider,
  NDrawer,
  NDrawerContent,
  NForm,
  NFormItem,
  NGrid,
  NGridItem,
  NInput,
  NInputNumber,
  NSelect,
  NSpace,
  NSpin,
  NSwitch,
  NTag,
  NTooltip,
  NTreeSelect,
} from 'naive-ui';

import type { DynamicFormSubmissionDetail, DynamicFormTemplate } from '#/api/formdesign';
import DynamicFormRenderer from '#/components/dynamic-form/DynamicFormRenderer.vue';
import { ledgerAssetFormRules } from '#/utils/form-rules';
import { regionOptions } from '#/utils/region';

import type { LedgerFormModel, LedgerOption } from '../types';

defineOptions({ name: 'LedgerEditModal' });

type FormDensity = 'comfortable' | 'compact';

const props = defineProps<{
  show: boolean;
  saving?: boolean;
  editing: boolean;
  form: LedgerFormModel;
  dynamicTemplate?: DynamicFormTemplate | null;
  dynamicSubmission?: DynamicFormSubmissionDetail | null;
  dynamicFormData?: Record<string, any>;
  dynamicLoading?: boolean;
  assetFamilyOptions: LedgerOption[];
  securityOptions: LedgerOption[];
  unitTypeOptions: LedgerOption[];
  industryCategoryOptions: LedgerOption[];
  sourceOptions: LedgerOption[];
  orgTreeOptions: TreeOption[];
  constructionOptions: LedgerOption[];
}>();

const emit = defineEmits<{
  close: [];
  submit: [];
  quickOrganize: [];
  quickConstruction: [];
  'update:dynamicFormData': [value: Record<string, any>];
  'update:show': [value: boolean];
}>();

const dynamicModel = computed({
  get: () => props.dynamicFormData ?? {},
  set: (value: Record<string, any>) => emit('update:dynamicFormData', value),
});

const { width: windowWidth } = useWindowSize();

const drawerWidth = computed(() => {
  const w = windowWidth.value;
  if (w <= 640) return '100%';
  return Math.min(680, Math.max(400, w - 40));
});

const drawerBodyContentStyle = computed(() => ({
  boxSizing: 'border-box' as const,
  padding: isCompact.value ? '0 10px 10px' : '0 12px 12px',
}));

const modalTitle = computed(() => (props.editing ? '编辑资产' : '资产登记'));

const URL_FIRST_FAMILIES = new Set(['domain_site', 'official_account', 'mini_program']);

const showIpv4Row = computed(() => !URL_FIRST_FAMILIES.has(props.form.assetFamily || ''));

const formRules = computed(() => {
  const rules = { ...ledgerAssetFormRules };
  if (!showIpv4Row.value) {
    delete rules.ipv4;
    delete rules.port;
  }
  return rules;
});

const accessAddressRequired = computed(() => URL_FIRST_FAMILIES.has(props.form.assetFamily || ''));

const targetFieldHint = computed(() => {
  if (accessAddressRequired.value) {
    return '当前分类请填写访问地址（域名、URL 或小程序路径等）。';
  }
  return '访问地址与 IPv4 至少填写一项。';
});

const formRef = ref<FormInst | null>(null);

/** 表单间距：标准 / 紧凑（本地记忆） */
const formDensity = useLocalStorage<FormDensity>('vulnscan-ledger-edit-density', 'comfortable');
const isCompact = computed(() => formDensity.value === 'compact');
const formSize = computed(() => (isCompact.value ? 'small' : 'medium'));
const labelWidth = computed(() => (isCompact.value ? 108 : 124));
const gridXGap = computed(() => (isCompact.value ? 12 : 20));
const gridYGap = computed(() => (isCompact.value ? 4 : 10));
const remarkRows = computed(() => (isCompact.value ? 2 : 3));

const formClass = computed(() => [
  'ledger-edit-modal__form',
  { 'ledger-edit-modal__form--compact': isCompact.value },
]);

const panelClass = computed(() => [
  'ledger-edit-modal__panel',
  { 'ledger-edit-modal__panel--compact': isCompact.value },
]);

const panelHeadClass = computed(() => [
  'ledger-edit-modal__panel-head',
  { 'ledger-edit-modal__panel-head--compact': isCompact.value },
]);

watch(
  () => props.show,
  (visible) => {
    if (!visible) formRef.value?.restoreValidation();
  },
);

function handleDrawerUpdate(show: boolean) {
  emit('update:show', show);
  if (!show) emit('close');
}

async function handleSubmit() {
  try {
    await formRef.value?.validate();
    emit('submit');
  } catch {
    /* 校验未通过，表单项已标红 */
  }
}
</script>

<template>
  <NDrawer
    :show="show"
    class="ledger-edit-drawer"
    :width="drawerWidth"
    placement="right"
    :trap-focus="false"
    :auto-focus="false"
    :mask-closable="true"
    @update:show="handleDrawerUpdate"
  >
    <NDrawerContent
      closable
      :native-scrollbar="false"
      :body-content-style="drawerBodyContentStyle"
    >
      <template #header>
        <div class="ledger-edit-drawer__header">
          <span class="ledger-edit-drawer__title">{{ modalTitle }}</span>
          <NTooltip>
            <template #trigger>
              <NButtonGroup size="small" class="ledger-edit-drawer__density">
                <NButton
                  :type="!isCompact ? 'primary' : 'default'"
                  :focusable="false"
                  @click="formDensity = 'comfortable'"
                >
                  <IconifyIcon icon="mdi:format-line-spacing" class="ledger-edit-drawer__density-icon" />
                  标准
                </NButton>
                <NButton
                  :type="isCompact ? 'primary' : 'default'"
                  :focusable="false"
                  @click="formDensity = 'compact'"
                >
                  <IconifyIcon icon="mdi:unfold-less-vertical" class="ledger-edit-drawer__density-icon" />
                  紧凑
                </NButton>
              </NButtonGroup>
            </template>
            切换表单行距与控件大小，设置会自动保存
          </NTooltip>
        </div>
      </template>

      <NForm
        ref="formRef"
        :model="form"
        :rules="formRules"
        label-placement="left"
        :label-width="labelWidth"
        :size="formSize"
        :class="formClass"
      >
        <!-- 资产信息 -->
        <div :class="panelClass">
          <div :class="panelHeadClass">
            <div class="ledger-edit-modal__panel-head-left">
              <IconifyIcon icon="ri:information-line" class="ledger-edit-modal__panel-icon" />
              <span class="ledger-edit-modal__panel-title">资产信息</span>
            </div>
            <span class="ledger-edit-modal__panel-hint">带 * 为必填</span>
          </div>

          <NGrid cols="1 s:2" responsive="screen" :x-gap="gridXGap" :y-gap="gridYGap">
            <NGridItem>
              <NFormItem label="系统名称" required>
                <NInput v-model:value="form.name" placeholder="请输入" />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="资产分类" required>
                <NSelect
                  v-model:value="form.assetFamily"
                  :options="assetFamilyOptions"
                  placeholder="请选择"
                />
              </NFormItem>
            </NGridItem>

            <NGridItem>
              <NFormItem label="是否联网" required class="ledger-edit-modal__switch-item">
                <NSwitch v-model:value="form.isOnline" />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="是否关键基础设施" class="ledger-edit-modal__switch-item">
                <NSwitch v-model:value="form.isKey" />
              </NFormItem>
            </NGridItem>

            <NGridItem :span="2" class="ledger-edit-modal__hint-row">
              <span class="ledger-edit-modal__field-hint">{{ targetFieldHint }}</span>
            </NGridItem>

            <NGridItem v-if="showIpv4Row">
              <NFormItem label="IPv4地址" path="ipv4">
                <NInput v-model:value="form.ipv4" placeholder="如 192.168.1.1，多个用逗号分隔" />
              </NFormItem>
            </NGridItem>
            <NGridItem v-if="showIpv4Row">
              <NFormItem label="端口" path="port">
                <NInputNumber
                  v-model:value="form.port"
                  clearable
                  :min="1"
                  :max="65535"
                  placeholder="可选"
                  style="width: 100%"
                />
              </NFormItem>
            </NGridItem>

            <NGridItem :span="2">
              <NFormItem label="访问地址" :required="accessAddressRequired">
                <NInput v-model:value="form.address" placeholder="IP、域名或 URL" />
              </NFormItem>
            </NGridItem>

            <NGridItem>
              <NFormItem label="IPv6地址">
                <NInput v-model:value="form.ipv6" placeholder="无则留空" />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="安全保护等级">
                <NSelect
                  v-model:value="form.securityProtectionLevel"
                  clearable
                  :options="securityOptions"
                  placeholder="请选择"
                />
              </NFormItem>
            </NGridItem>

            <NGridItem>
              <NFormItem label="等保备案证明编号">
                <NInput v-model:value="form.filingCertNumber" placeholder="请输入等保备案证明编号" />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="ICP备案号">
                <NInput v-model:value="form.icpFilingNumber" placeholder="请输入" />
              </NFormItem>
            </NGridItem>

            <NGridItem>
              <NFormItem label="公网安备案号">
                <NInput v-model:value="form.publicSecurityFiling" placeholder="请输入" />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="数据来源">
                <NSelect v-model:value="form.dataSource" :options="sourceOptions" placeholder="请选择" />
              </NFormItem>
            </NGridItem>

            <NGridItem :span="2">
              <NFormItem label="运维单位">
                <NSpace vertical :size="8" style="width: 100%">
                  <NSelect
                    v-model:value="form.operationOrgId"
                    filterable
                    clearable
                    :options="constructionOptions"
                    placeholder="请选择运维单位"
                  />
                  <NButton size="tiny" text type="primary" @click="emit('quickConstruction')">
                    快速新增运维单位
                  </NButton>
                </NSpace>
              </NFormItem>
            </NGridItem>

            <NGridItem :span="2">
              <NFormItem label="备注">
                <NInput v-model:value="form.remark" type="textarea" :rows="remarkRows" placeholder="请输入" />
              </NFormItem>
            </NGridItem>
          </NGrid>
        </div>

        <!-- 单位信息 -->
        <div :class="panelClass">
          <div :class="panelHeadClass">
            <div class="ledger-edit-modal__panel-head-left">
              <IconifyIcon icon="ri:building-2-line" class="ledger-edit-modal__panel-icon" />
              <span class="ledger-edit-modal__panel-title">单位信息</span>
            </div>
          </div>

          <NGrid cols="1 s:2" responsive="screen" :x-gap="gridXGap" :y-gap="gridYGap">
            <NGridItem :span="2">
              <NFormItem label="所属单位" required>
                <NSpace vertical :size="8" style="width: 100%">
                  <NTreeSelect
                    v-model:value="form.organizeId"
                    filterable
                    clearable
                    default-expand-all
                    key-field="key"
                    label-field="label"
                    children-field="children"
                    :options="orgTreeOptions"
                    placeholder="请选择所属单位"
                  />
                  <NButton size="tiny" text type="primary" @click="emit('quickOrganize')">
                    快速新增单位
                  </NButton>
                </NSpace>
              </NFormItem>
            </NGridItem>

            <NGridItem>
              <NFormItem label="单位类型">
                <NSelect
                  v-model:value="form.extra.unit_type"
                  :options="unitTypeOptions"
                  clearable
                  filterable
                  placeholder="请选择"
                />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="行业分类">
                <NSelect
                  v-model:value="form.extra.industry_category"
                  :options="industryCategoryOptions"
                  clearable
                  filterable
                  placeholder="请选择"
                />
              </NFormItem>
            </NGridItem>
            <NGridItem :span="2">
              <NFormItem label="统一社会信用代码" path="extra.unified_social_credit_code">
                <NInput
                  v-model:value="form.extra.unified_social_credit_code"
                  placeholder="18 位统一社会信用代码"
                  maxlength="18"
                />
              </NFormItem>
            </NGridItem>
            <NGridItem :span="2">
              <NFormItem label="省市区">
                <NCascader
                  v-model:value="form.extra.unit_location_code"
                  clearable
                  filterable
                  check-strategy="child"
                  :options="regionOptions"
                  placeholder="请选择省 / 市 / 区县"
                />
              </NFormItem>
            </NGridItem>
            <NGridItem :span="2">
              <NFormItem label="详细地址">
                <NInput v-model:value="form.extra.unit_address" placeholder="街道、门牌号等" />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="网络安全分管领导"><NInput v-model:value="form.extra.leader_name" /></NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="分管领导职务 / 职称"><NInput v-model:value="form.extra.leader_title" /></NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="网络安全责任部门">
                <NInput v-model:value="form.extra.responsible_department_name" />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="责任部门负责人姓名">
                <NInput v-model:value="form.extra.department_leader_name" />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="负责人职务 / 职称"><NInput v-model:value="form.extra.department_leader_title" /></NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="负责人电话" path="extra.department_leader_phone">
                <NInput v-model:value="form.extra.department_leader_phone" placeholder="11 位手机或固话" />
              </NFormItem>
            </NGridItem>
            <NGridItem><NFormItem label="联系人姓名"><NInput v-model:value="form.extra.contact_name" /></NFormItem></NGridItem>
            <NGridItem>
              <NFormItem label="联系人职务 / 职称"><NInput v-model:value="form.extra.contact_title" /></NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="联系人电话" path="extra.contact_phone">
                <NInput v-model:value="form.extra.contact_phone" placeholder="11 位手机或固话" />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="是否是通报机制成员单位">
                <NSwitch v-model:value="form.extra.is_notification_member" />
              </NFormItem>
            </NGridItem>
          </NGrid>
        </div>

        <div v-if="dynamicTemplate || dynamicLoading" class="ledger-edit-modal__dynamic">
          <NDivider style="margin: 16px 0 12px" />
          <div class="ledger-edit-modal__dynamic-head">
            <span class="ledger-edit-modal__panel-title">动态扩展信息</span>
            <NTag v-if="dynamicTemplate" size="small" :bordered="false" type="info">
              {{ dynamicTemplate.name }}
            </NTag>
          </div>
          <NSpin :show="dynamicLoading">
            <DynamicFormRenderer
              v-if="dynamicTemplate"
              v-model="dynamicModel"
              :schema="dynamicSubmission?.version?.schema || dynamicTemplate.schema"
              :options="dynamicSubmission?.version?.options || dynamicTemplate.options"
            />
          </NSpin>
        </div>
      </NForm>

      <template #footer>
        <NSpace justify="end" :size="12">
          <NButton @click="handleDrawerUpdate(false)">取消</NButton>
          <NButton type="primary" :loading="saving" @click="handleSubmit">
            {{ editing ? '保存' : '确认' }}
          </NButton>
        </NSpace>
      </template>
    </NDrawerContent>
  </NDrawer>
</template>

<style scoped>
.ledger-edit-drawer__header {
  align-items: center;
  display: flex;
  gap: 12px;
  justify-content: space-between;
  padding-right: 28px;
  width: 100%;
}

.ledger-edit-drawer__title {
  color: var(--n-text-color-1);
  font-size: 16px;
  font-weight: 600;
}

.ledger-edit-drawer__density-icon {
  font-size: 14px;
  margin-right: 2px;
  vertical-align: -2px;
}

.ledger-edit-modal__form--compact :deep(.n-form-item) {
  margin-bottom: 8px;
}

.ledger-edit-modal__form--compact :deep(.n-form-item-label) {
  min-height: 22px;
}

.ledger-edit-modal__form--compact :deep(.n-form-item-feedback-wrapper) {
  min-height: 18px;
  padding-top: 0;
}

.ledger-edit-modal__panel--compact {
  margin-bottom: 10px;
  padding: 10px 12px 2px;
}

.ledger-edit-modal__panel-head--compact {
  margin-bottom: 6px;
}

.ledger-edit-modal__panel--compact .ledger-edit-modal__panel-title {
  font-size: 13px;
}

.ledger-edit-modal__form--compact .ledger-edit-modal__switch-item :deep(.n-form-item-blank) {
  min-height: 24px;
}

.ledger-edit-modal__panel-head-left {
  align-items: center;
  display: flex;
  gap: 8px;
  min-width: 0;
}

.ledger-edit-modal__panel-icon {
  color: var(--n-primary-color);
  flex-shrink: 0;
  font-size: 18px;
}

.ledger-edit-modal__form {
  margin-top: 0;
}

.ledger-edit-modal__form :deep(.n-form-item) {
  margin-bottom: 18px;
}

.ledger-edit-modal__form :deep(.n-form-item-label) {
  align-items: center;
  min-height: 28px;
}

.ledger-edit-modal__panel {
  background: var(--n-color-embedded);
  border: 1px solid var(--n-border-color);
  border-radius: 8px;
  margin-bottom: 16px;
  padding: 16px 18px 8px;
}

.ledger-edit-modal__panel-head {
  align-items: baseline;
  display: flex;
  gap: 10px;
  justify-content: space-between;
  margin-bottom: 10px;
}

.ledger-edit-modal__panel-title {
  color: var(--n-text-color-1);
  font-size: 14px;
  font-weight: 600;
}

.ledger-edit-modal__panel-hint {
  color: var(--n-text-color-3);
  font-size: 12px;
}

.ledger-edit-modal__switch-item :deep(.n-form-item-blank) {
  min-height: 32px;
}

.ledger-edit-modal__hint-row {
  margin-bottom: 2px;
  margin-top: -4px;
}

.ledger-edit-modal__field-hint {
  color: var(--n-text-color-3);
  display: block;
  font-size: 12px;
  line-height: 1.5;
  padding: 0 2px 4px;
}

.ledger-edit-modal__dynamic {
  margin-top: 4px;
}

.ledger-edit-modal__dynamic-head {
  align-items: center;
  display: flex;
  gap: 10px;
  justify-content: space-between;
  margin-bottom: 10px;
}
</style>
