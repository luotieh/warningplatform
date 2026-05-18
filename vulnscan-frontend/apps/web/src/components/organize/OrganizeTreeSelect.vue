<script lang="ts" setup>
import type { TreeOption } from 'naive-ui';

import { onMounted, ref } from 'vue';
import { NTreeSelect } from 'naive-ui';

import { getIamOrganizeTree, getOrganizeTree } from '#/api/assetmgr';
import { buildOrgTreeOptions } from '#/views/asset/ledger/utils';

defineOptions({ name: 'OrganizeTreeSelect' });

const model = defineModel<string | null>({ default: null });

withDefaults(
  defineProps<{
    disabled?: boolean;
    placeholder?: string;
  }>(),
  {
    disabled: false,
    placeholder: '请选择目标单位',
  },
);

const options = ref<TreeOption[]>([]);
const loading = ref(false);

async function loadOptions() {
  loading.value = true;
  let nodes: any[] = [];
  try {
    const res = await getOrganizeTree();
    nodes = Array.isArray(res) ? res : ((res as any)?.data ?? (res as any)?.items ?? []);
  } catch {
    nodes = [];
  }
  if (!nodes.length) {
    try {
      const iam = await getIamOrganizeTree();
      nodes = Array.isArray(iam) ? iam : ((iam as any)?.data ?? []);
    } catch {
      nodes = [];
    }
  }
  options.value = buildOrgTreeOptions(nodes);
  loading.value = false;
}

onMounted(loadOptions);
</script>

<template>
  <NTreeSelect
    v-model:value="model"
    filterable
    clearable
    default-expand-all
    key-field="key"
    label-field="label"
    children-field="children"
    :options="options"
    :loading="loading"
    :disabled="disabled"
    :placeholder="placeholder"
  />
</template>
