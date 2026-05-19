<script lang="ts" setup>
import type { TreeOption } from 'naive-ui';

import { computed, ref } from 'vue';

import { NButton, NCard, NTabPane, NTabs } from 'naive-ui';

import type { LedgerScopeDimension } from '../types';
import LedgerFilterTree from './ledger-filter-tree.vue';
import LedgerOrgTree from './ledger-org-tree.vue';

defineOptions({ name: 'LedgerScopePanel' });

const props = defineProps<{
  assetFamilyTree: TreeOption[];
  dimension: LedgerScopeDimension;
  industryTree: TreeOption[];
  loading?: boolean;
  orgSearchMode?: boolean;
  orgTree: TreeOption[];
  regionTree: TreeOption[];
  scopeLabel: string;
  selectedAssetFamilyKey: null | string;
  selectedIndustryKey: null | string;
  selectedOrgKey: null | string;
  selectedRegionKey: null | string;
}>();

const emit = defineEmits<{
  'update:dimension': [value: LedgerScopeDimension];
  'update:selectedAssetFamilyKey': [key: null | string];
  'update:selectedIndustryKey': [key: null | string];
  'update:selectedOrgKey': [key: null | string];
  'update:selectedRegionKey': [key: null | string];
  orgReset: [];
  orgSearch: [keyword: string];
  resetAll: [];
}>();

const regionTreeRef = ref<InstanceType<typeof LedgerFilterTree> | null>(null);
const industryTreeRef = ref<InstanceType<typeof LedgerFilterTree> | null>(null);
const assetFamilyTreeRef = ref<InstanceType<typeof LedgerFilterTree> | null>(null);

const dimensionModel = computed({
  get: () => props.dimension,
  set: (value: LedgerScopeDimension) => emit('update:dimension', value),
});

function handleResetAll() {
  regionTreeRef.value?.clearSearch?.();
  industryTreeRef.value?.clearSearch?.();
  assetFamilyTreeRef.value?.clearSearch?.();
  emit('resetAll');
}

function handleOrgReset() {
  emit('orgReset');
}
</script>

<template>
  <NCard size="small" class="ledger-scope-panel">
    <template #header>
      <div class="ledger-scope-panel__head">
        <span class="ledger-scope-panel__title">资产范围</span>
        <NButton text type="primary" size="small" @click="handleResetAll">清空</NButton>
      </div>
    </template>

    <NTabs v-model:value="dimensionModel" type="line" size="small" class="ledger-scope-panel__tabs">
      <NTabPane name="organize" tab="组织" />
      <NTabPane name="region" tab="地域" />
      <NTabPane name="industry" tab="行业" />
      <NTabPane name="asset_family" tab="类型" />
    </NTabs>

    <div v-if="scopeLabel" class="ledger-scope-panel__active">
      <span class="ledger-scope-panel__active-label">已选</span>
      <span class="ledger-scope-panel__active-value">{{ scopeLabel }}</span>
    </div>

    <div v-show="dimension === 'organize'" class="ledger-scope-panel__body">
      <LedgerOrgTree
        embedded
        :data="orgTree"
        :loading="loading"
        :search-mode="orgSearchMode"
        :selected-key="selectedOrgKey"
        @search="emit('orgSearch', $event)"
        @reset="handleOrgReset"
        @update:selected-key="emit('update:selectedOrgKey', $event)"
      />
    </div>

    <div v-show="dimension === 'region'" class="ledger-scope-panel__body">
      <LedgerFilterTree
        ref="regionTreeRef"
        :data="regionTree"
        :loading="loading"
        expand-all
        empty-text="暂无已登记地域的资产"
        search-placeholder="搜索省 / 市 / 区县"
        :selected-key="selectedRegionKey"
        @update:selected-key="emit('update:selectedRegionKey', $event)"
      />
    </div>

    <div v-show="dimension === 'industry'" class="ledger-scope-panel__body">
      <p class="ledger-scope-panel__hint">按资产所属单位的行业分类筛选</p>
      <LedgerFilterTree
        ref="industryTreeRef"
        :data="industryTree"
        empty-text="暂无单位行业字典"
        search-placeholder="搜索单位行业"
        :selected-key="selectedIndustryKey"
        @update:selected-key="emit('update:selectedIndustryKey', $event)"
      />
    </div>

    <div v-show="dimension === 'asset_family'" class="ledger-scope-panel__body">
      <p class="ledger-scope-panel__hint">按资产分类筛选</p>
      <LedgerFilterTree
        ref="assetFamilyTreeRef"
        :data="assetFamilyTree"
        empty-text="暂无资产类型字典"
        search-placeholder="搜索资产类型"
        :selected-key="selectedAssetFamilyKey"
        @update:selected-key="emit('update:selectedAssetFamilyKey', $event)"
      />
    </div>
  </NCard>
</template>

<style scoped>
.ledger-scope-panel {
  height: 100%;
}

.ledger-scope-panel__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.ledger-scope-panel__title {
  font-size: 14px;
  font-weight: 600;
}

.ledger-scope-panel__tabs {
  margin-bottom: 8px;
}

.ledger-scope-panel__hint {
  margin: 0 0 8px;
  font-size: 12px;
  line-height: 1.5;
  color: var(--n-text-color-3);
}

.ledger-scope-panel__active {
  display: flex;
  gap: 6px;
  align-items: flex-start;
  padding: 6px 8px;
  margin-bottom: 8px;
  font-size: 12px;
  line-height: 1.5;
  background: var(--n-color-target);
  border-radius: 6px;
}

.ledger-scope-panel__active-label {
  flex: 0 0 auto;
  color: var(--n-text-color-3);
}

.ledger-scope-panel__active-value {
  color: var(--n-text-color-1);
  word-break: break-all;
}

.ledger-scope-panel :deep(.n-card__content) {
  display: flex;
  flex-direction: column;
  max-height: calc(100vh - 210px);
  overflow: hidden;
}

.ledger-scope-panel__body {
  flex: 1;
  min-height: 0;
  overflow: hidden;
}

.ledger-scope-panel__body :deep(.ledger-org-tree.n-card) {
  border: none;
  box-shadow: none;
}

.ledger-scope-panel__body :deep(.ledger-org-tree .n-card-header) {
  display: none;
}

.ledger-scope-panel__body :deep(.ledger-org-tree .n-card__content) {
  padding: 0;
  max-height: none;
}
</style>
