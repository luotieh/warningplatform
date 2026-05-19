<script lang="ts" setup>
import type { TreeOption } from 'naive-ui';

import { computed, ref, watch } from 'vue';

import { useDebounceFn } from '@vueuse/core';
import { NButton, NCard, NEmpty, NInput, NSpace, NTree } from 'naive-ui';

defineOptions({ name: 'LedgerOrgTree' });

const props = withDefaults(
  defineProps<{
    data: TreeOption[];
    embedded?: boolean;
    loading?: boolean;
    searchMode?: boolean;
    selectedKey: null | string;
  }>(),
  {
    embedded: false,
    loading: false,
    searchMode: false,
  },
);

const emit = defineEmits<{
  reset: [];
  search: [keyword: string];
  'update:selectedKey': [key: null | string];
}>();

const pattern = ref('');
const selectedKeys = computed(() => (props.selectedKey ? [props.selectedKey] : []));

const debouncedSearch = useDebounceFn((keyword: string) => {
  emit('search', keyword);
}, 300);

watch(pattern, (value) => {
  void debouncedSearch(value);
});

function handleSelect(keys: Array<string | number>) {
  emit('update:selectedKey', keys.length > 0 ? String(keys[0]) : null);
}

function handleReset() {
  pattern.value = '';
  emit('search', '');
  emit('reset');
}

const emptyDescription = computed(() => {
  if (props.loading) return '查询中…';
  if (props.searchMode) return '未找到匹配单位';
  return '暂无组织数据';
});

defineExpose({
  clearSearch() {
    pattern.value = '';
    emit('search', '');
  },
});
</script>

<template>
  <NCard
    v-if="!embedded"
    title="所属单位"
    size="small"
    class="ledger-org-tree"
  >
    <template #header-extra>
      <NSpace>
        <NButton text type="primary" @click="handleReset">清空</NButton>
      </NSpace>
    </template>
    <div class="ledger-org-tree__inner">
      <NInput
        v-model:value="pattern"
        clearable
        size="small"
        placeholder="搜索单位名称（实时查询）"
        class="ledger-org-tree__search"
      />
      <NTree
        v-if="data.length > 0"
        block-line
        :default-expand-all="!searchMode"
        :expand-on-click="!searchMode"
        selectable
        key-field="key"
        label-field="label"
        children-field="children"
        :data="data"
        :selected-keys="selectedKeys"
        @update:selected-keys="handleSelect"
      />
      <NEmpty v-else size="small" :description="emptyDescription" />
    </div>
  </NCard>

  <div v-else class="ledger-org-tree ledger-org-tree--embedded">
    <NInput
      v-model:value="pattern"
      clearable
      size="small"
      placeholder="搜索单位名称（实时查询）"
      class="ledger-org-tree__search"
    />
    <NTree
      v-if="data.length > 0"
      block-line
      :default-expand-all="!searchMode"
      :expand-on-click="!searchMode"
      selectable
      key-field="key"
      label-field="label"
      children-field="children"
      :data="data"
      :selected-keys="selectedKeys"
      @update:selected-keys="handleSelect"
    />
    <NEmpty v-else size="small" :description="emptyDescription" />
  </div>
</template>

<style scoped>
.ledger-org-tree {
  height: 100%;
}

.ledger-org-tree__search {
  margin-bottom: 10px;
}

.ledger-org-tree__inner,
.ledger-org-tree--embedded {
  min-height: 120px;
}

.ledger-org-tree :deep(.n-card__content) {
  max-height: calc(100vh - 210px);
  overflow: auto;
}

.ledger-org-tree--embedded :deep(.n-tree) {
  max-height: calc(100vh - 320px);
  overflow: auto;
}
</style>
