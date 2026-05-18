<script lang="ts" setup>
import type { TreeOption } from 'naive-ui';

import { computed, ref } from 'vue';
import { NButton, NCard, NEmpty, NInput, NSpace, NTree } from 'naive-ui';

defineOptions({ name: 'LedgerOrgTree' });

const props = defineProps<{
  data: TreeOption[];
  loading?: boolean;
  selectedKey: null | string;
}>();

const emit = defineEmits<{
  reset: [];
  'update:selectedKey': [key: null | string];
}>();

const pattern = ref('');
const selectedKeys = computed(() => (props.selectedKey ? [props.selectedKey] : []));

function handleSelect(keys: Array<string | number>) {
  emit('update:selectedKey', keys.length > 0 ? String(keys[0]) : null);
}
</script>

<template>
  <NCard title="所属单位" size="small" class="ledger-org-tree">
    <template #header-extra>
      <NSpace>
        <NButton text type="primary" @click="emit('reset')">清空</NButton>
      </NSpace>
    </template>

    <NInput
      v-model:value="pattern"
      clearable
      placeholder="搜索单位名称"
      class="ledger-org-tree__search"
    />

    <NTree
      v-if="data.length > 0"
      block-line
      default-expand-all
      expand-on-click
      selectable
      key-field="key"
      label-field="label"
      children-field="children"
      :data="data"
      :pattern="pattern"
      :selected-keys="selectedKeys"
      @update:selected-keys="handleSelect"
    />

    <NEmpty v-else :description="loading ? '组织树加载中' : '暂无组织数据'" />
  </NCard>
</template>

<style scoped>
.ledger-org-tree {
  height: 100%;
}

.ledger-org-tree__search {
  margin-bottom: 12px;
}

.ledger-org-tree :deep(.n-card__content) {
  max-height: calc(100vh - 210px);
  overflow: auto;
}
</style>
