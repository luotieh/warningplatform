<script lang="ts" setup>
import { h, onMounted, reactive, ref } from 'vue';
import {
  NButton, NCard, NColorPicker, NDataTable, NForm, NFormItem, NInput,
  NModal, NPopconfirm, NSelect, NSpace, NTag,
} from 'naive-ui';
import type { Tag } from '#/api/assetmgr';
import { createTag, deleteTag, getTagList, updateTag } from '#/api/assetmgr';
import { message } from '#/adapter/naive';
import { useErrorHandler } from '#/composables/useErrorHandler';

defineOptions({ name: 'AssetTag' });

const { handleError } = useErrorHandler();
const loading = ref(false);
const data = ref<Tag[]>([]);
const showModal = ref(false);
const editingId = ref<null | number>(null);

const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50],
  onChange: (p: number) => { pagination.page = p; fetchList(); },
  onUpdatePageSize: (ps: number) => { pagination.pageSize = ps; pagination.page = 1; fetchList(); },
});

const searchForm = reactive({ keyword: '', category: undefined as string | undefined });
const formData = reactive({ name: '', color: '#2080f0', category: '', is_auto: false });

const categoryOptions = [
  { label: '业务', value: 'business' },
  { label: '技术', value: 'tech' },
  { label: '安全', value: 'security' },
  { label: '其他', value: 'other' },
];

const columns = [
  {
    title: '标签', key: 'name', width: 160,
    render: (row: Tag) => h(NTag, { size: 'small', color: { color: row.color, textColor: '#fff', borderColor: row.color } }, () => row.name),
  },
  { title: '分类', key: 'category', width: 100 },
  {
    title: '类型', key: 'is_auto', width: 80,
    render: (row: Tag) => h(NTag, { size: 'small', type: row.is_auto ? 'info' : 'default' }, () => row.is_auto ? '自动' : '手动'),
  },
  {
    title: '操作', key: 'actions', width: 140, fixed: 'right' as const,
    render: (row: Tag) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'small', onClick: () => onEdit(row) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => onDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'small', type: 'error' }, () => '删除'),
        default: () => '确认删除？',
      }),
    ]),
  },
];

async function fetchList() {
  loading.value = true;
  try {
    const params: Record<string, any> = { page: pagination.page, page_size: pagination.pageSize, ...searchForm };
    const res = await getTagList(params);
    const body = (res as any)?.data ?? res;
    data.value = body?.data ?? body?.items ?? [];
    pagination.itemCount = body?.count ?? 0;
  } catch (e) { handleError(e, '获取标签列表失败'); }
  finally { loading.value = false; }
}

function onAdd() {
  editingId.value = null;
  Object.assign(formData, { name: '', color: '#2080f0', category: '', is_auto: false });
  showModal.value = true;
}

function onEdit(row: Tag) {
  editingId.value = row.id;
  Object.assign(formData, { name: row.name, color: row.color, category: row.category, is_auto: row.is_auto });
  showModal.value = true;
}

async function onSave() {
  if (!formData.name) { message.warning('请输入标签名称'); return; }
  try {
    if (editingId.value) {
      await updateTag(editingId.value, formData);
      message.success('更新成功');
    } else {
      await createTag(formData);
      message.success('创建成功');
    }
    showModal.value = false;
    fetchList();
  } catch (e) { handleError(e, '操作失败'); }
}

async function onDelete(id: number) {
  try { await deleteTag(id); message.success('删除成功'); fetchList(); }
  catch (e) { handleError(e, '删除失败'); }
}

onMounted(fetchList);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="标签管理" size="small">
      <template #header-extra>
        <NButton type="primary" size="small" @click="onAdd">新增标签</NButton>
      </template>
      <NForm inline label-placement="left" :show-feedback="false" style="margin-bottom: 16px">
        <NFormItem label="关键词"><NInput v-model:value="searchForm.keyword" placeholder="标签名称" clearable style="width: 160px" /></NFormItem>
        <NFormItem label="分类"><NSelect v-model:value="searchForm.category" :options="categoryOptions" placeholder="全部" clearable style="width: 120px" /></NFormItem>
        <NFormItem><NButton type="primary" @click="fetchList">查询</NButton></NFormItem>
      </NForm>
      <NDataTable :columns="columns" :data="data" :loading="loading" :pagination="pagination" :bordered="false" :scroll-x="500" size="small" striped remote />
    </NCard>

    <NModal v-model:show="showModal" preset="dialog" :title="editingId ? '编辑标签' : '新增标签'" style="width: 420px">
      <NForm label-placement="left" label-width="80" style="margin-top: 16px">
        <NFormItem label="名称" required><NInput v-model:value="formData.name" /></NFormItem>
        <NFormItem label="颜色"><NColorPicker v-model:value="formData.color" :modes="['hex']" /></NFormItem>
        <NFormItem label="分类"><NSelect v-model:value="formData.category" :options="categoryOptions" /></NFormItem>
      </NForm>
      <template #action><NSpace><NButton @click="showModal = false">取消</NButton><NButton type="primary" @click="onSave">确认</NButton></NSpace></template>
    </NModal>
  </div>
</template>
