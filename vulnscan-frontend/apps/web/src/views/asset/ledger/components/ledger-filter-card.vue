<script lang="ts" setup>
import {
  NButton,
  NCard,
  NCollapseTransition,
  NForm,
  NFormItem,
  NGrid,
  NGridItem,
  NInput,
  NInputNumber,
  NSpace,
  NSelect,
  NTag,
} from 'naive-ui';

import type { LedgerOption, LedgerSearchForm } from '../types';

defineOptions({ name: 'LedgerFilterCard' });

defineProps<{
  activeFamily: string;
  familyOptions: readonly LedgerOption[];
  securityOptions: LedgerOption[];
  sourceOptions: LedgerOption[];
  yesNoOptions: LedgerOption[];
  form: LedgerSearchForm;
  selectedOrgName?: string;
  showAdvanced: boolean;
}>();

const emit = defineEmits<{
  familyChange: [value: string];
  search: [];
  reset: [];
  toggle: [];
}>();
</script>

<template>
  <NCard size="small" class="ledger-filter-card">
    <div class="ledger-filter-card__head">
      <div class="ledger-filter-card__scope">
        <span class="ledger-filter-card__label">当前范围</span>
        <NTag type="info" size="small" :bordered="false" class="ledger-filter-card__scope-tag">
          {{ selectedOrgName || '全部单位' }}
        </NTag>
      </div>

      <button
        class="ledger-filter-card__toggle"
        type="button"
        @click="emit('toggle')"
      >
        {{ showAdvanced ? '收起高级筛选' : '展开高级筛选' }}
      </button>
    </div>

    <div class="ledger-filter-card__family">
      <span class="ledger-filter-card__label">资产分类</span>
      <NSpace class="ledger-filter-card__family-options" :size="8" :wrap="true">
        <NButton
          v-for="item in familyOptions"
          :key="item.value"
          size="small"
          round
          class="ledger-filter-card__family-btn"
          :type="activeFamily === item.value ? 'primary' : 'default'"
          :secondary="activeFamily === item.value"
          @click="emit('familyChange', item.value)"
        >
          {{ item.label }}
        </NButton>
      </NSpace>
    </div>

    <div class="ledger-filter-card__basic">
      <div class="ledger-filter-card__keyword">
        <span class="ledger-filter-card__label">关键字</span>
        <NInput
          v-model:value="form.keyword"
          clearable
          size="small"
          placeholder="资产名称、地址、IPv4"
          @keyup.enter="emit('search')"
        />
      </div>

      <NSpace class="ledger-filter-card__actions" :size="8" :wrap="false">
        <NButton type="primary" size="small" @click="emit('search')">查询</NButton>
        <NButton size="small" @click="emit('reset')">重置</NButton>
      </NSpace>
    </div>

    <NCollapseTransition :show="showAdvanced">
      <NForm
        label-placement="left"
        label-width="88"
        size="small"
        :show-feedback="false"
        class="ledger-filter-card__advanced"
      >
        <NGrid cols="1 s:2 m:3 l:4" responsive="screen" :x-gap="16" :y-gap="8">
          <NGridItem>
            <NFormItem label="等保等级">
              <NSelect
                v-model:value="form.securityLevel"
                clearable
                size="small"
                :options="securityOptions"
                placeholder="请选择等级"
              />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="数据来源">
              <NSelect
                v-model:value="form.dataSource"
                clearable
                size="small"
                :options="sourceOptions"
                placeholder="请选择来源"
              />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="重点资产">
              <NSelect
                v-model:value="form.isKey"
                size="small"
                :options="yesNoOptions"
                placeholder="请选择"
              />
            </NFormItem>
          </NGridItem>
          <NGridItem span="1 m:2 l:2">
            <NFormItem label="风险分">
              <div class="ledger-filter-card__risk-range">
                <NInputNumber
                  v-model:value="form.riskScoreMin"
                  clearable
                  size="small"
                  placeholder="下限"
                  :min="0"
                  class="ledger-filter-card__risk-input"
                />
                <span class="ledger-filter-card__risk-sep">~</span>
                <NInputNumber
                  v-model:value="form.riskScoreMax"
                  clearable
                  size="small"
                  placeholder="上限"
                  :min="0"
                  class="ledger-filter-card__risk-input"
                />
              </div>
            </NFormItem>
          </NGridItem>
        </NGrid>
      </NForm>
    </NCollapseTransition>
  </NCard>
</template>

<style scoped>
.ledger-filter-card :deep(.n-card__content) {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* 顶部：左侧「当前范围 + 标签」成组，右侧高级筛选（中间留白由 margin-left:auto 吸收） */
.ledger-filter-card__head {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: 8px 12px;
}

.ledger-filter-card__scope {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  min-width: 0;
}

.ledger-filter-card__scope-tag {
  flex-shrink: 0;
  max-width: 100%;
}

.ledger-filter-card__toggle {
  background: transparent;
  border: 0;
  color: var(--n-primary-color);
  cursor: pointer;
  flex-shrink: 0;
  font-size: 14px;
  line-height: 22px;
  margin-left: auto;
  padding: 0;
  white-space: nowrap;
}

.ledger-filter-card__basic {
  align-items: flex-end;
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}

.ledger-filter-card__keyword {
  display: flex;
  flex: 1 1 280px;
  flex-direction: column;
  gap: 8px;
  max-width: 560px;
  min-width: 0;
}

.ledger-filter-card__actions {
  flex-shrink: 0;
}

.ledger-filter-card__label {
  color: var(--n-text-color-3);
  font-size: 13px;
}

.ledger-filter-card__family {
  align-items: center;
  background: var(--n-color);
  border: 1px solid var(--n-border-color);
  border-radius: 6px;
  display: flex;
  gap: 10px;
  padding: 8px 10px;
}

.ledger-filter-card__family-options {
  flex: 1 1 auto;
  min-width: 0;
}

.ledger-filter-card__family-btn {
  min-width: 72px;
}

.ledger-filter-card__family-btn:deep(.n-button__content) {
  font-weight: 500;
}

.ledger-filter-card__advanced {
  padding-top: 2px;
}

.ledger-filter-card__advanced :deep(.n-form-item) {
  margin-bottom: 0;
}

.ledger-filter-card__advanced :deep(.n-form-item .n-form-item-feedback-wrapper) {
  min-height: 0;
}

.ledger-filter-card__risk-range {
  align-items: center;
  display: flex;
  gap: 8px;
  min-width: 0;
  width: 100%;
}

.ledger-filter-card__risk-input {
  flex: 1 1 0;
  min-width: 0;
}

.ledger-filter-card__risk-input :deep(.n-input-number) {
  width: 100%;
}

.ledger-filter-card__risk-sep {
  color: var(--n-text-color-3);
  flex-shrink: 0;
  font-size: 13px;
  line-height: 1;
}

@media (max-width: 960px) {
  .ledger-filter-card__basic {
    align-items: stretch;
    flex-direction: column;
  }

  .ledger-filter-card__keyword {
    flex: none;
    max-width: none;
  }

  .ledger-filter-card__actions {
    align-self: flex-end;
  }

  .ledger-filter-card__head {
    align-items: flex-start;
  }

  .ledger-filter-card__toggle {
    margin-left: 0;
    padding-top: 2px;
    text-align: right;
    width: 100%;
  }

  .ledger-filter-card__family {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
