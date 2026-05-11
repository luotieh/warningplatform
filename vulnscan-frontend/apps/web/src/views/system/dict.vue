<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from 'vue';
import type { DataTableColumns } from 'naive-ui';
import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NModal,
  NPopconfirm,
  NSelect,
  NSpace,
  NSwitch,
  NTag,
  useMessage,
} from 'naive-ui';

import type { SystemDict, SystemDictItem, SystemDictItemInput } from '#/api/system/dict';
import {
  addSystemDictItems,
  createSystemDict,
  deleteSystemDict,
  deleteSystemDictItems,
  getSystemDictItems,
  getSystemDictList,
  updateSystemDict,
  updateSystemDictItem,
} from '#/api/system/dict';

defineOptions({ name: 'SystemDict' });

const message = useMessage();
const loading = ref(false);
const itemLoading = ref(false);
const saving = ref(false);
const itemSaving = ref(false);
const dicts = ref<SystemDict[]>([]);
const items = ref<SystemDictItem[]>([]);
const currentDict = ref<SystemDict | null>(null);
const editingDictId = ref('');
const editingItemId = ref('');
const showDictModal = ref(false);
const showItemsModal = ref(false);
const showItemModal = ref(false);

const searchForm = reactive({
  keyword: '',
  category: undefined as string | undefined,
});

const pagination = reactive({
  page: 1,
  pageSize: 20,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onChange: (page: number) => {
    pagination.page = page;
    fetchDicts();
  },
  onUpdatePageSize: (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.page = 1;
    fetchDicts();
  },
});

const dictForm = reactive({
  id: '',
  name: '',
  category: '',
  description: '',
});

const itemForm = reactive<SystemDictItemInput>({
  label: '',
  value: '',
  sort: 0,
  enabled: true,
  remark: '',
});

const categoryOptions = computed(() => {
  const values = new Set(dicts.value.map(item => item.category).filter(Boolean));
  values.add('资产台账');
  values.add('系统管理');
  return [...values].map(value => ({ label: value, value }));
});

function normalizeListResponse(res: any) {
  const body = res?.data ?? res;
  return {
    items: (body?.data ?? body?.items ?? []) as SystemDict[],
    total: Number(body?.count ?? body?.total ?? 0),
  };
}

async function fetchDicts() {
  loading.value = true;
  try {
    const res = await getSystemDictList({
      page: pagination.page,
      page_size: pagination.pageSize,
      keyword: searchForm.keyword,
      category: searchForm.category,
    });
    const normalized = normalizeListResponse(res);
    dicts.value = normalized.items;
    pagination.itemCount = normalized.total;
  } catch {
    message.error('加载系统字典失败');
  } finally {
    loading.value = false;
  }
}

async function fetchItems(dict: SystemDict) {
  currentDict.value = dict;
  itemLoading.value = true;
  try {
    items.value = await getSystemDictItems(dict.id, false);
  } catch {
    items.value = [];
    message.error('加载字典项失败');
  } finally {
    itemLoading.value = false;
  }
}

function onSearch() {
  pagination.page = 1;
  fetchDicts();
}

function onReset() {
  searchForm.keyword = '';
  searchForm.category = undefined;
  onSearch();
}

function openCreateDict() {
  editingDictId.value = '';
  Object.assign(dictForm, { id: '', name: '', category: '资产台账', description: '' });
  showDictModal.value = true;
}

function openEditDict(row: SystemDict) {
  editingDictId.value = row.id;
  Object.assign(dictForm, {
    id: row.id,
    name: row.name,
    category: row.category || '',
    description: row.description || '',
  });
  showDictModal.value = true;
}

async function saveDict() {
  if (!dictForm.name) {
    message.warning('请填写字典名称');
    return;
  }
  saving.value = true;
  try {
    if (editingDictId.value) {
      await updateSystemDict(editingDictId.value, { ...dictForm });
      message.success('字典已更新');
    } else {
      await createSystemDict({ ...dictForm, id: dictForm.id || undefined });
      message.success('字典已创建');
    }
    showDictModal.value = false;
    await fetchDicts();
  } catch {
    message.error('保存字典失败');
  } finally {
    saving.value = false;
  }
}

async function removeDict(row: SystemDict) {
  try {
    await deleteSystemDict(row.id);
    message.success('字典已删除');
    await fetchDicts();
    if (currentDict.value?.id === row.id) {
      currentDict.value = null;
      items.value = [];
      showItemsModal.value = false;
    }
  } catch {
    message.error('删除字典失败');
  }
}

async function openItems(row: SystemDict) {
  await fetchItems(row);
  showItemsModal.value = true;
}

function openCreateItem() {
  editingItemId.value = '';
  Object.assign(itemForm, { label: '', value: '', sort: items.value.length + 1, enabled: true, remark: '' });
  showItemModal.value = true;
}

function openEditItem(row: SystemDictItem) {
  editingItemId.value = row.id;
  Object.assign(itemForm, {
    id: row.id,
    label: row.label,
    value: row.value,
    sort: row.sort,
    enabled: row.enabled,
    remark: row.remark || '',
  });
  showItemModal.value = true;
}

async function saveItem() {
  if (!currentDict.value) return;
  if (!itemForm.label || !itemForm.value) {
    message.warning('请填写标签和值');
    return;
  }
  itemSaving.value = true;
  try {
    if (editingItemId.value) {
      await updateSystemDictItem(currentDict.value.id, { ...itemForm, id: editingItemId.value });
      message.success('字典项已更新');
    } else {
      await addSystemDictItems(currentDict.value.id, [{ ...itemForm }]);
      message.success('字典项已新增');
    }
    showItemModal.value = false;
    await fetchItems(currentDict.value);
    await fetchDicts();
  } catch {
    message.error('保存字典项失败');
  } finally {
    itemSaving.value = false;
  }
}

async function removeItem(row: SystemDictItem) {
  if (!currentDict.value) return;
  try {
    await deleteSystemDictItems(currentDict.value.id, [row.id]);
    message.success('字典项已删除');
    await fetchItems(currentDict.value);
    await fetchDicts();
  } catch {
    message.error('删除字典项失败');
  }
}

async function toggleItem(row: SystemDictItem, enabled: boolean) {
  if (!currentDict.value) return;
  try {
    await updateSystemDictItem(currentDict.value.id, { ...row, enabled });
    row.enabled = enabled;
    message.success(enabled ? '已启用' : '已停用');
  } catch {
    message.error('更新状态失败');
  }
}

const dictColumns: DataTableColumns<SystemDict> = [
  {
    title: '字典',
    key: 'name',
    minWidth: 220,
    render: row => h('div', { class: 'dict-name-cell' }, [
      h('div', { class: 'dict-title' }, row.name),
      h('div', { class: 'dict-id' }, row.id),
    ]),
  },
  { title: '分类', key: 'category', width: 120, render: row => row.category || '-' },
  {
    title: '说明',
    key: 'description',
    minWidth: 220,
    ellipsis: { tooltip: true },
    render: row => row.description || '-',
  },
  {
    title: '字典项',
    key: 'item_count',
    width: 90,
    align: 'center',
    render: row => h(NTag, { size: 'small', bordered: false }, () => String(row.item_count ?? 0)),
  },
  {
    title: '操作',
    key: 'actions',
    width: 220,
    fixed: 'right',
    render: row => h(NSpace, { size: 6 }, () => [
      h(NButton, { size: 'small', type: 'info', onClick: () => openItems(row) }, () => '字典项'),
      h(NButton, { size: 'small', onClick: () => openEditDict(row) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => removeDict(row) }, {
        trigger: () => h(NButton, { size: 'small', type: 'error' }, () => '删除'),
        default: () => `确认删除字典「${row.name}」？`,
      }),
    ]),
  },
];

const itemColumns: DataTableColumns<SystemDictItem> = [
  { title: '标签', key: 'label', minWidth: 160, ellipsis: { tooltip: true } },
  { title: '值', key: 'value', minWidth: 160, ellipsis: { tooltip: true } },
  { title: '排序', key: 'sort', width: 80, align: 'center' },
  {
    title: '状态',
    key: 'enabled',
    width: 90,
    render: row => h(NSwitch, {
      size: 'small',
      value: row.enabled,
      'onUpdate:value': (value: boolean) => toggleItem(row, value),
    }),
  },
  { title: '备注', key: 'remark', minWidth: 160, ellipsis: { tooltip: true }, render: row => row.remark || '-' },
  {
    title: '操作',
    key: 'actions',
    width: 140,
    fixed: 'right',
    render: row => h(NSpace, { size: 6 }, () => [
      h(NButton, { size: 'small', onClick: () => openEditItem(row) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => removeItem(row) }, {
        trigger: () => h(NButton, { size: 'small', type: 'error' }, () => '删除'),
        default: () => `确认删除字典项「${row.label}」？`,
      }),
    ]),
  },
];

onMounted(fetchDicts);
</script>

<template>
  <div class="system-dict-page">
    <NCard title="数据字典" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NButton size="small" @click="fetchDicts">刷新</NButton>
          <NButton type="primary" size="small" @click="openCreateDict">新增字典</NButton>
        </NSpace>
      </template>

      <NForm inline label-placement="left" :show-feedback="false" class="dict-filter">
        <NFormItem label="关键词">
          <NInput v-model:value="searchForm.keyword" placeholder="名称 / ID" clearable style="width: 220px" />
        </NFormItem>
        <NFormItem label="分类">
          <NSelect
            v-model:value="searchForm.category"
            :options="categoryOptions"
            clearable
            filterable
            tag
            placeholder="全部"
            style="width: 160px"
          />
        </NFormItem>
        <NFormItem>
          <NSpace :size="8">
            <NButton type="primary" @click="onSearch">查询</NButton>
            <NButton @click="onReset">重置</NButton>
          </NSpace>
        </NFormItem>
      </NForm>

      <NDataTable
        :columns="dictColumns"
        :data="dicts"
        :loading="loading"
        :pagination="pagination"
        :bordered="false"
        :row-key="(row: SystemDict) => row.id"
        :scroll-x="900"
        size="small"
        striped
        remote
      />
    </NCard>

    <NModal
      v-model:show="showDictModal"
      preset="dialog"
      :title="editingDictId ? '编辑字典' : '新增字典'"
      style="width: min(560px, calc(100vw - 32px))"
    >
      <NForm label-placement="left" label-width="86" :show-feedback="false" class="dict-modal-form">
        <NFormItem label="字典ID">
          <NInput
            v-model:value="dictForm.id"
            :disabled="!!editingDictId"
            placeholder="如 asset_system_type"
          />
        </NFormItem>
        <NFormItem label="名称" required>
          <NInput v-model:value="dictForm.name" placeholder="请输入字典名称" />
        </NFormItem>
        <NFormItem label="分类">
          <NSelect
            v-model:value="dictForm.category"
            :options="categoryOptions"
            filterable
            tag
            clearable
            placeholder="请选择或输入分类"
          />
        </NFormItem>
        <NFormItem label="说明">
          <NInput v-model:value="dictForm.description" type="textarea" :rows="3" placeholder="请输入说明" />
        </NFormItem>
      </NForm>
      <template #action>
        <NSpace>
          <NButton @click="showDictModal = false">取消</NButton>
          <NButton type="primary" :loading="saving" @click="saveDict">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <NModal
      v-model:show="showItemsModal"
      preset="card"
      :title="currentDict ? `${currentDict.name} - 字典项` : '字典项'"
      style="width: min(860px, calc(100vw - 32px))"
    >
      <template #header-extra>
        <NButton type="primary" size="small" @click="openCreateItem">新增字典项</NButton>
      </template>
      <div v-if="currentDict" class="dict-items-meta">
        <NTag size="small" :bordered="false">{{ currentDict.id }}</NTag>
        <span>{{ currentDict.description || '维护下拉选项和枚举值' }}</span>
      </div>
      <NDataTable
        :columns="itemColumns"
        :data="items"
        :loading="itemLoading"
        :bordered="false"
        :pagination="{ pageSize: 10 }"
        :row-key="(row: SystemDictItem) => row.id"
        :scroll-x="740"
        size="small"
        striped
      />
    </NModal>

    <NModal
      v-model:show="showItemModal"
      preset="dialog"
      :title="editingItemId ? '编辑字典项' : '新增字典项'"
      style="width: min(520px, calc(100vw - 32px))"
    >
      <NForm label-placement="left" label-width="76" :show-feedback="false" class="dict-modal-form">
        <NFormItem label="标签" required>
          <NInput v-model:value="itemForm.label" placeholder="页面显示文本" />
        </NFormItem>
        <NFormItem label="值" required>
          <NInput v-model:value="itemForm.value" placeholder="接口保存值" />
        </NFormItem>
        <NFormItem label="排序">
          <NInputNumber v-model:value="itemForm.sort" :min="0" style="width: 100%" />
        </NFormItem>
        <NFormItem label="启用">
          <NSwitch v-model:value="itemForm.enabled" />
        </NFormItem>
        <NFormItem label="备注">
          <NInput v-model:value="itemForm.remark" type="textarea" :rows="2" placeholder="可选" />
        </NFormItem>
      </NForm>
      <template #action>
        <NSpace>
          <NButton @click="showItemModal = false">取消</NButton>
          <NButton type="primary" :loading="itemSaving" @click="saveItem">保存</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.system-dict-page {
  padding: 16px;
}

.dict-filter {
  margin-bottom: 16px;
}

.dict-name-cell {
  min-width: 0;
}

.dict-title {
  color: var(--n-text-color);
  font-weight: 500;
  line-height: 1.4;
}

.dict-id {
  margin-top: 2px;
  color: var(--n-text-color-3);
  font-size: 12px;
  line-height: 1.35;
}

.dict-modal-form {
  margin-top: 12px;
}

.dict-items-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
  color: var(--n-text-color-3);
  font-size: 12px;
}
</style>
