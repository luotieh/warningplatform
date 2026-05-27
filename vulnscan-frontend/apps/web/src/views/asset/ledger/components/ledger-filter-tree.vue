<script lang="ts" setup>
import type { TreeOption } from 'naive-ui';

import { computed, h, ref } from 'vue';

import { NEmpty, NInput, NTag, NTree } from 'naive-ui';

defineOptions({ name: 'LedgerFilterTree' });

const props = withDefaults(
  defineProps<{
    data: TreeOption[];
    emptyText?: string;
    expandAll?: boolean;
    loading?: boolean;
    searchPlaceholder?: string;
    selectedKey: null | string;
    showSearch?: boolean;
  }>(),
  {
    emptyText: '暂无数据',
    expandAll: false,
    loading: false,
    searchPlaceholder: '搜索',
    showSearch: true,
  },
);

const emit = defineEmits<{
  'update:selectedKey': [key: null | string];
}>();

const pattern = ref('');
const selectedKeys = computed(() => (props.selectedKey ? [props.selectedKey] : []));

function handleSelect(keys: Array<string | number>) {
  emit('update:selectedKey', keys.length > 0 ? String(keys[0]) : null);
}

function renderSuffix({ option }: { option: TreeOption & { assetCount?: number } }) {
  const count = option.assetCount;
  if (!count || count <= 0) return null;
  return h(NTag, { size: 'tiny', round: true, bordered: false, type: 'info' }, () => String(count));
}

defineExpose({
  clearSearch() {
    pattern.value = '';
  },
});
</script>

<template>
  <div class="ledger-filter-tree">
    <NInput
      v-if="showSearch"
      v-model:value="pattern"
      clearable
      size="small"
      :placeholder="searchPlaceholder"
      class="ledger-filter-tree__search"
    />

    <NTree
      v-if="data.length > 0"
      block-line
      :default-expand-all="expandAll"
      expand-on-click
      selectable
      key-field="key"
      label-field="label"
      children-field="children"
      :data="data"
      :pattern="pattern"
      :selected-keys="selectedKeys"
      :render-suffix="renderSuffix"
      @update:selected-keys="handleSelect"
    />

    <NEmpty v-else size="small" :description="loading ? '加载中…' : emptyText" />
  </div>
</template>

<style scoped>
.ledger-filter-tree {
  min-height: 120px;
}

.ledger-filter-tree__search {
  margin-bottom: 10px;
}

.ledger-filter-tree :deep(.n-tree) {
  max-height: calc(100vh - 320px);
  overflow: auto;
}
</style>
