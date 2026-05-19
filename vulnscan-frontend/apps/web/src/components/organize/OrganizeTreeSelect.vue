<script lang="ts" setup>
import type { SelectOption, TreeOption } from 'naive-ui';

import { computed, ref, watch } from 'vue';

import { useDebounceFn } from '@vueuse/core';
import { NSelect, NTreeSelect } from 'naive-ui';

import type { Organize } from '#/api/assetmgr';
import {
  getIamOrganizeTree,
  getOrganizeDetail,
  getOrganizeList,
  getOrganizeTree,
} from '#/api/assetmgr';
import { buildOrgTreeOptions } from '#/views/asset/ledger/utils';

defineOptions({ name: 'OrganizeTreeSelect' });

const model = defineModel<string | null>({ default: null });

const props = withDefaults(
  defineProps<{
    disabled?: boolean;
    /** 编辑时排除自身，避免选为上级单位 */
    excludeId?: string | null;
    placeholder?: string;
    /** remote：分页搜索（单位多时推荐）；tree：完整树（少量数据） */
    mode?: 'remote' | 'tree';
  }>(),
  {
    disabled: false,
    excludeId: null,
    placeholder: '请选择目标单位',
    mode: 'remote',
  },
);

const PAGE_SIZE = 20;

const treeOptions = ref<TreeOption[]>([]);
const treeLoading = ref(false);

const selectOptions = ref<SelectOption[]>([]);
const selectLoading = ref(false);
const selectKeyword = ref('');
const selectPage = ref(1);
const selectTotal = ref(0);
const selectHasMore = computed(
  () => selectOptions.value.length < selectTotal.value,
);

function formatOrganizeLabel(org: Partial<Organize> & { path_names?: string[] }) {
  const path = (org.path_names ?? []).filter(Boolean).join(' / ');
  const name = String(org.name ?? '').trim();
  if (path) return path;
  return name || String(org.id ?? '');
}

function parseListResponse(res: unknown) {
  const body = (res as any)?.data ?? res;
  const items = body?.data ?? body?.items ?? [];
  const count = Number(body?.count ?? body?.total ?? 0);
  return {
    count,
    items: (Array.isArray(items) ? items : []) as Organize[],
  };
}

function mergeSelectOptions(incoming: SelectOption[], reset: boolean) {
  const map = new Map<string, SelectOption>();
  if (!reset) {
    for (const item of selectOptions.value) {
      map.set(String(item.value), item);
    }
  }
  for (const item of incoming) {
    const key = String(item.value);
    if (!key || key === props.excludeId) continue;
    map.set(key, item);
  }
  if (model.value && !map.has(model.value)) {
    const kept = selectOptions.value.find((item) => item.value === model.value);
    if (kept) map.set(String(kept.value), kept);
  }
  selectOptions.value = Array.from(map.values());
}

async function loadSelectPage(reset = false) {
  if (reset) {
    selectPage.value = 1;
  }
  selectLoading.value = true;
  try {
    const res = await getOrganizeList({
      page: selectPage.value,
      page_size: PAGE_SIZE,
      name: selectKeyword.value.trim() || undefined,
    });
    const { items, count } = parseListResponse(res);
    selectTotal.value = count;
    const mapped = items
      .filter((item) => item.id && item.id !== props.excludeId)
      .map((item) => ({
        label: formatOrganizeLabel(item),
        value: item.id,
      }));
    mergeSelectOptions(mapped, reset);
  } catch {
    if (reset) {
      selectOptions.value = [];
      selectTotal.value = 0;
    }
  } finally {
    selectLoading.value = false;
  }
}

const debouncedSearch = useDebounceFn((query: string) => {
  selectKeyword.value = query;
  void loadSelectPage(true);
}, 300);

async function ensureSelectedOption() {
  const id = model.value;
  if (!id || selectOptions.value.some((item) => item.value === id)) {
    return;
  }
  try {
    const org = (await getOrganizeDetail(id)) as Organize;
    mergeSelectOptions(
      [{ label: formatOrganizeLabel(org), value: org.id }],
      false,
    );
  } catch {
    // 详情不可用时仍保留 value，由 Naive 展示 id
  }
}

function handleSelectScroll(e: Event) {
  const el = e.currentTarget as HTMLElement | null;
  if (!el || selectLoading.value || !selectHasMore.value) return;
  if (el.scrollTop + el.offsetHeight >= el.scrollHeight - 24) {
    selectPage.value += 1;
    void loadSelectPage(false);
  }
}

function handleMenuShow(show: boolean) {
  if (!show) return;
  if (!selectOptions.value.length) {
    void loadSelectPage(true);
  }
}

watch(
  () => model.value,
  () => {
    if (props.mode === 'remote') {
      void ensureSelectedOption();
    }
  },
  { immediate: true },
);

watch(
  () => props.excludeId,
  () => {
    if (props.mode !== 'remote') return;
    selectOptions.value = selectOptions.value.filter(
      (item) => item.value !== props.excludeId,
    );
  },
);

async function loadTreeOptions() {
  treeLoading.value = true;
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
  const options = buildOrgTreeOptions(nodes);
  treeOptions.value = disableTreeNode(options, props.excludeId);
  treeLoading.value = false;
}

function disableTreeNode(nodes: TreeOption[] = [], disabledValue: null | string): TreeOption[] {
  return nodes.map((node) => ({
    ...node,
    disabled: !!disabledValue && node.key === disabledValue,
    children: node.children
      ? disableTreeNode(node.children as TreeOption[], disabledValue)
      : undefined,
  }));
}

watch(
  () => props.mode,
  (mode) => {
    if (mode === 'tree' && !treeOptions.value.length) {
      void loadTreeOptions();
    }
  },
  { immediate: true },
);
</script>

<template>
  <NSelect
    v-if="mode === 'remote'"
    v-model:value="model"
    :options="selectOptions"
    :loading="selectLoading"
    :disabled="disabled"
    :placeholder="placeholder"
    clearable
    filterable
    remote
    :consistent-menu-width="false"
    :menu-props="{ style: { maxHeight: '280px' } }"
    @search="debouncedSearch"
    @scroll="handleSelectScroll"
    @update:show="handleMenuShow"
  />
  <NTreeSelect
    v-else
    v-model:value="model"
    filterable
    clearable
    virtual-scroll
    key-field="key"
    label-field="label"
    children-field="children"
    :options="treeOptions"
    :loading="treeLoading"
    :disabled="disabled"
    :placeholder="placeholder"
    :menu-props="{ style: { maxHeight: '320px' } }"
  />
</template>
