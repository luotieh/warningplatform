<script lang="ts" setup>
import type { TreeOption } from 'naive-ui';

import { computed, ref, watch } from 'vue';
import { useWindowSize } from '@vueuse/core';
import { IconifyIcon } from '@vben/icons';
import {
  NButton,
  NCascader,
  NCollapse,
  NCollapseItem,
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
  NTreeSelect,
} from 'naive-ui';

import type { DynamicFormSubmissionDetail, DynamicFormTemplate } from '#/api/formdesign';
import DynamicFormRenderer from '#/components/dynamic-form/DynamicFormRenderer.vue';
import { regionOptions } from '#/utils/region';

import type { LedgerFormModel, LedgerOption } from '../types';

defineOptions({ name: 'LedgerEditModal' });

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
  sourceOptions: LedgerOption[];
  orgTreeOptions: TreeOption[];
  constructionOptions: LedgerOption[];
}>();

const emit = defineEmits<{
  close: [];
  submit: [];
  quickConstruction: [target: 'construction' | 'operation'];
  useConstructionAsOperation: [];
  useOperationAsConstruction: [];
  'update:dynamicFormData': [value: Record<string, any>];
  'update:show': [value: boolean];
}>();

/** 折叠面板 name：与 NCollapseItem name 一致 */
const expandedNames = ref<string[]>([]);

const dynamicModel = computed({
  get: () => props.dynamicFormData ?? {},
  set: (value: Record<string, any>) => emit('update:dynamicFormData', value),
});

const hasUnitExtra = computed(() =>
  Object.entries(props.form.extra).some(([key, value]) =>
    key === 'is_notification_member' ? value === true : value !== '',
  ),
);

const { width: windowWidth } = useWindowSize();

/** 抽屉宽度：避免过宽导致表单「发空」；窄屏仍全宽 */
const drawerWidth = computed(() => {
  const w = windowWidth.value;
  if (w <= 640) return '100%';
  return Math.min(680, Math.max(400, w - 40));
});

/**
 * 仅设置内边距，不要在 body 上再加 overflow/maxHeight：
 * NDrawerContent（native-scrollbar=false）内部已有 NScrollbar，再套一层会出双滚动条。
 */
const drawerBodyContentStyle = computed(() => ({
  boxSizing: 'border-box' as const,
  padding: '0 12px 12px',
}));

const modalTitle = computed(() => (props.editing ? '编辑资产' : '资产登记'));

/** 域名/站点类：以访问地址为主，表单中不展示 IPv4 行 */
const URL_FIRST_FAMILIES = new Set(['domain_site', 'official_account', 'mini_program']);

const showIpv4Row = computed(() => !URL_FIRST_FAMILIES.has(props.form.assetFamily || ''));

const accessAddressRequired = computed(() => URL_FIRST_FAMILIES.has(props.form.assetFamily || ''));

const targetFieldHint = computed(() => {
  if (accessAddressRequired.value) {
    return '当前分类请填写访问地址（域名、URL 或小程序路径等）。';
  }
  return '访问地址与 IPv4 至少填写一项。';
});

function handleDrawerUpdate(show: boolean) {
  emit('update:show', show);
  if (!show) emit('close');
}

function defaultExpandedPanels(): string[] {
  const names: string[] = [];
  if (hasUnitExtra.value) names.push('unit');
  if (props.form.constructionOrgId || props.form.operationOrgId) names.push('construction');
  if (props.form.port || props.form.responsibleUserName || props.form.remark?.trim()) {
    names.push('more');
  }
  return names;
}

watch(
  () => props.show,
  (open) => {
    if (open) {
      expandedNames.value = defaultExpandedPanels();
    }
  },
  { immediate: true },
);
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
      :title="modalTitle"
      closable
      :native-scrollbar="false"
      :body-content-style="drawerBodyContentStyle"
    >
      <NForm
        label-placement="left"
        label-width="124"
        size="medium"
        :show-feedback="false"
        class="ledger-edit-modal__form"
      >
        <div class="ledger-edit-modal__panel">
          <div class="ledger-edit-modal__panel-head">
            <div class="ledger-edit-modal__panel-head-left">
              <IconifyIcon icon="ri:information-line" class="ledger-edit-modal__panel-icon" />
              <span class="ledger-edit-modal__panel-title">资产信息</span>
            </div>
            <span class="ledger-edit-modal__panel-hint">带 * 为必填</span>
          </div>

          <NGrid cols="1 s:2" responsive="screen" :x-gap="20" :y-gap="10">
          <NGridItem>
            <NFormItem label="系统名称" required>
              <NInput v-model:value="form.name" placeholder="请输入" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="所属单位" required>
              <NTreeSelect
                v-model:value="form.organizeId"
                filterable
                :options="orgTreeOptions"
                placeholder="请选择"
              />
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

          <NGridItem :span="2" class="ledger-edit-modal__hint-row">
            <span class="ledger-edit-modal__field-hint">{{ targetFieldHint }}</span>
          </NGridItem>

          <NGridItem v-if="showIpv4Row" :span="2">
            <NFormItem label="IPv4地址">
              <NInput v-model:value="form.ipv4" placeholder="多个用逗号分隔（可选）" />
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
            <NFormItem label="是否关键基础设施" class="ledger-edit-modal__switch-item">
              <NSwitch v-model:value="form.isKey" />
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
            <NFormItem label="备案证明编号">
              <NInput v-model:value="form.filingCertNumber" placeholder="请输入" />
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

          <NGridItem :span="2">
            <NFormItem label="地域">
              <NCascader
                v-model:value="form.regionCode"
                clearable
                filterable
                :options="regionOptions"
                placeholder="请选择"
              />
            </NFormItem>
          </NGridItem>
        </NGrid>
      </div>

      <NCollapse
        v-model:expanded-names="expandedNames"
        class="ledger-edit-modal__collapse"
        display-directive="show"
      >
        <NCollapseItem title="更多字段" name="more">
          <template #header-extra>
            <span class="ledger-edit-modal__collapse-extra">备注、端口、责任人等</span>
          </template>
          <NGrid cols="1 s:2" responsive="screen" :x-gap="20" :y-gap="10">
            <NGridItem :span="2">
              <NFormItem label="备注">
                <NInput v-model:value="form.remark" type="textarea" :rows="3" placeholder="请输入" />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="端口">
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
            <NGridItem>
              <NFormItem label="责任人">
                <NInput v-model:value="form.responsibleUserName" placeholder="请输入责任人姓名" />
              </NFormItem>
            </NGridItem>
            <NGridItem :span="2">
              <NFormItem label="数据来源">
                <NSelect v-model:value="form.dataSource" :options="sourceOptions" placeholder="请选择" />
              </NFormItem>
            </NGridItem>
          </NGrid>
        </NCollapseItem>

        <NCollapseItem title="建设 / 运维单位" name="construction">
          <template #header-extra>
            <span class="ledger-edit-modal__collapse-extra">可选</span>
          </template>
          <NGrid cols="1 s:2" responsive="screen" :x-gap="20" :y-gap="10">
            <NGridItem>
              <NFormItem label="建设单位">
                <NSpace vertical :size="8" style="width: 100%">
                  <NSelect
                    v-model:value="form.constructionOrgId"
                    filterable
                    clearable
                    :options="constructionOptions"
                    placeholder="请选择建设单位"
                  />
                  <NSpace :size="8">
                    <NButton size="tiny" text type="primary" @click="emit('quickConstruction', 'construction')">
                      快速新增
                    </NButton>
                    <NButton
                      size="tiny"
                      text
                      :disabled="!form.operationOrgId"
                      @click="emit('useOperationAsConstruction')"
                    >
                      同运维单位
                    </NButton>
                  </NSpace>
                </NSpace>
              </NFormItem>
            </NGridItem>

            <NGridItem>
              <NFormItem label="运维单位">
                <NSpace vertical :size="8" style="width: 100%">
                  <NSelect
                    v-model:value="form.operationOrgId"
                    filterable
                    clearable
                    :options="constructionOptions"
                    placeholder="请选择运维单位"
                  />
                  <NSpace :size="8">
                    <NButton size="tiny" text type="primary" @click="emit('quickConstruction', 'operation')">
                      快速新增
                    </NButton>
                    <NButton
                      size="tiny"
                      text
                      :disabled="!form.constructionOrgId"
                      @click="emit('useConstructionAsOperation')"
                    >
                      同建设单位
                    </NButton>
                  </NSpace>
                </NSpace>
              </NFormItem>
            </NGridItem>
          </NGrid>
        </NCollapseItem>

        <NCollapseItem title="单位信息" name="unit">
          <template #header-extra>
            <span class="ledger-edit-modal__collapse-extra">联系人、地址等</span>
          </template>
          <NGrid cols="1 s:2" responsive="screen" :x-gap="20" :y-gap="10">
            <NGridItem><NFormItem label="单位类型"><NInput v-model:value="form.extra.unit_type" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="行业分类"><NInput v-model:value="form.extra.industry_category" /></NFormItem></NGridItem>
            <NGridItem>
              <NFormItem label="统一社会信用代码"><NInput v-model:value="form.extra.unified_social_credit_code" /></NFormItem>
            </NGridItem>
            <NGridItem><NFormItem label="单位地址"><NInput v-model:value="form.extra.unit_address" /></NFormItem></NGridItem>
            <NGridItem :span="2">
              <NFormItem label="单位详细地址"><NInput v-model:value="form.extra.unit_detail_address" /></NFormItem>
            </NGridItem>
            <NGridItem><NFormItem label="分管领导姓名"><NInput v-model:value="form.extra.leader_name" /></NFormItem></NGridItem>
            <NGridItem>
              <NFormItem label="分管领导职务 / 职称"><NInput v-model:value="form.extra.leader_title" /></NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="责任部门名称"><NInput v-model:value="form.extra.responsible_department_name" /></NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="责任部门负责人姓名">
                <NInput v-model:value="form.extra.department_leader_name" />
              </NFormItem>
            </NGridItem>
            <NGridItem>
              <NFormItem label="负责人职务 / 职称"><NInput v-model:value="form.extra.department_leader_title" /></NFormItem>
            </NGridItem>
            <NGridItem><NFormItem label="负责人电话"><NInput v-model:value="form.extra.department_leader_phone" /></NFormItem></NGridItem>
            <NGridItem><NFormItem label="联系人姓名"><NInput v-model:value="form.extra.contact_name" /></NFormItem></NGridItem>
            <NGridItem>
              <NFormItem label="联系人职务 / 职称"><NInput v-model:value="form.extra.contact_title" /></NFormItem>
            </NGridItem>
            <NGridItem><NFormItem label="联系人电话"><NInput v-model:value="form.extra.contact_phone" /></NFormItem></NGridItem>
            <NGridItem>
              <NFormItem label="是否是通报机制成员单位">
                <NSwitch v-model:value="form.extra.is_notification_member" />
              </NFormItem>
            </NGridItem>
          </NGrid>
        </NCollapseItem>
      </NCollapse>

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
          <NButton type="primary" :loading="saving" @click="emit('submit')">
            {{ editing ? '保存' : '确认' }}
          </NButton>
        </NSpace>
      </template>
    </NDrawerContent>
  </NDrawer>
</template>

<style scoped>
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

.ledger-edit-modal__form :deep(.n-form-item-feedback-wrapper) {
  min-height: 0;
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

.ledger-edit-modal__collapse {
  margin-top: 4px;
}

.ledger-edit-modal__collapse :deep(.n-collapse-item) {
  margin-top: 0;
}

.ledger-edit-modal__collapse :deep(.n-collapse-item__header) {
  font-size: 13px;
  font-weight: 500;
  padding: 10px 2px;
}

.ledger-edit-modal__collapse :deep(.n-collapse-item__content-wrapper) {
  border-top: 1px solid var(--n-border-color);
}

.ledger-edit-modal__collapse :deep(.n-collapse-item__content-inner) {
  padding: 10px 2px 6px;
}

.ledger-edit-modal__collapse-extra {
  color: var(--n-text-color-3);
  font-size: 12px;
  font-weight: 400;
  margin-left: 8px;
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
