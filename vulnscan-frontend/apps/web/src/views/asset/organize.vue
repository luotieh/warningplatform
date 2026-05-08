<script lang="ts" setup>
import { h, onMounted, reactive, ref } from 'vue';
import {
  NButton, NCard, NDataTable, NForm, NFormItem, NGrid, NGridItem, NInput,
  NModal, NPopconfirm, NSelect, NSpace, useMessage,
} from 'naive-ui';
import type { Organize } from '#/api/assetmgr';
import { createOrganize, deleteOrganize, getOrganizeList, updateOrganize } from '#/api/assetmgr';

defineOptions({ name: 'AssetOrganize' });

const message = useMessage();
const loading = ref(false);
const data = ref<Organize[]>([]);
const showModal = ref(false);
const editingId = ref<null | string>(null);

const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50],
  onChange: (p: number) => { pagination.page = p; fetchList(); },
  onUpdatePageSize: (ps: number) => { pagination.pageSize = ps; pagination.page = 1; fetchList(); },
});

const searchForm = reactive({ keyword: '' });

const formData = reactive({
  name: '', parent_id: '', unified_social_credit_code: '', industry_category: '',
  unit_type: '', address: '', contact_name: '', contact_phone: '',
});

const unitTypeOptions = [
  { label: '政府机关', value: '政府机关' },
  { label: '事业单位', value: '事业单位' },
  { label: '企业', value: '企业' },
  { label: '其他', value: '其他' },
];

const columns = [
  { title: '名称', key: 'name', width: 200, ellipsis: { tooltip: true } },
  { title: '统一社会信用代码', key: 'unified_social_credit_code', width: 200 },
  { title: '类型', key: 'unit_type', width: 100 },
  { title: '行业', key: 'industry_category', width: 120 },
  { title: '联系人', key: 'contact_name', width: 100 },
  { title: '联系电话', key: 'contact_phone', width: 130 },
  { title: '资产数', key: 'asset_count', width: 80 },
  {
    title: '操作', key: 'actions', width: 140, fixed: 'right' as const,
    render: (row: Organize) => h(NSpace, { size: 4 }, () => [
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
    const res = await getOrganizeList(params);
    const body = (res as any)?.data ?? res;
    data.value = body?.data ?? body?.items ?? [];
    pagination.itemCount = body?.count ?? 0;
  } catch { message.error('获取组织列表失败'); }
  finally { loading.value = false; }
}

function resetForm() {
  Object.assign(formData, { name: '', parent_id: '', unified_social_credit_code: '', industry_category: '', unit_type: '', address: '', contact_name: '', contact_phone: '' });
}

function onAdd() { editingId.value = null; resetForm(); showModal.value = true; }

function onEdit(row: Organize) {
  editingId.value = row.id;
  Object.assign(formData, {
    name: row.name, parent_id: row.parent_id, unified_social_credit_code: row.unified_social_credit_code,
    industry_category: row.industry_category, unit_type: row.unit_type, address: row.address,
    contact_name: row.contact_name, contact_phone: row.contact_phone,
  });
  showModal.value = true;
}

async function onSave() {
  if (!formData.name) { message.warning('请输入组织名称'); return; }
  try {
    if (editingId.value) { await updateOrganize(editingId.value, formData); message.success('更新成功'); }
    else { await createOrganize(formData); message.success('创建成功'); }
    showModal.value = false; fetchList();
  } catch { message.error('操作失败'); }
}

async function onDelete(id: string) {
  try { await deleteOrganize(id); message.success('删除成功'); fetchList(); }
  catch { message.error('删除失败'); }
}

onMounted(fetchList);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="组织管理" size="small">
      <template #header-extra><NButton type="primary" size="small" @click="onAdd">新增组织</NButton></template>
      <NForm inline label-placement="left" :show-feedback="false" style="margin-bottom: 16px">
        <NFormItem label="关键词"><NInput v-model:value="searchForm.keyword" placeholder="组织名称" clearable style="width: 200px" /></NFormItem>
        <NFormItem><NSpace :size="8"><NButton type="primary" @click="fetchList">查询</NButton><NButton @click="searchForm.keyword = ''; fetchList()">重置</NButton></NSpace></NFormItem>
      </NForm>
      <NDataTable :columns="columns" :data="data" :loading="loading" :pagination="pagination" :bordered="false" :scroll-x="1080" size="small" striped remote />
    </NCard>

    <NModal v-model:show="showModal" preset="dialog" :title="editingId ? '编辑组织' : '新增组织'" style="width: 640px">
      <NForm label-placement="left" label-width="120" style="margin-top: 16px">
        <NGrid :cols="2" :x-gap="16">
          <NGridItem><NFormItem label="名称" required><NInput v-model:value="formData.name" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="上级组织ID"><NInput v-model:value="formData.parent_id" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="统一信用代码"><NInput v-model:value="formData.unified_social_credit_code" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="类型"><NSelect v-model:value="formData.unit_type" :options="unitTypeOptions" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="行业类别"><NInput v-model:value="formData.industry_category" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="地址"><NInput v-model:value="formData.address" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="联系人"><NInput v-model:value="formData.contact_name" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="联系电话"><NInput v-model:value="formData.contact_phone" /></NFormItem></NGridItem>
        </NGrid>
      </NForm>
      <template #action><NSpace><NButton @click="showModal = false">取消</NButton><NButton type="primary" @click="onSave">确认</NButton></NSpace></template>
    </NModal>
  </div>
</template>
