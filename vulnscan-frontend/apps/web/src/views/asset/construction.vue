<script lang="ts" setup>
import { h, onMounted, reactive, ref } from 'vue';
import {
  NButton, NCard, NCascader, NDataTable, NForm, NFormItem, NGrid, NGridItem, NInput,
  NModal, NPopconfirm, NSpace, useMessage,
} from 'naive-ui';
import type { ConstructionOrg } from '#/api/assetmgr';
import { createConstruction, deleteConstruction, getConstructionList, updateConstruction } from '#/api/assetmgr';
import { regionCodeFromLabel, regionLabelFromCode, regionOptions } from '#/utils/region';

defineOptions({ name: 'AssetConstruction' });

const message = useMessage();
const loading = ref(false);
const data = ref<ConstructionOrg[]>([]);
const showModal = ref(false);
const editingId = ref<null | string>(null);

const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50],
  onChange: (p: number) => { pagination.page = p; fetchList(); },
  onUpdatePageSize: (ps: number) => { pagination.pageSize = ps; pagination.page = 1; fetchList(); },
});

const searchForm = reactive({ keyword: '' });

const formData = reactive({
  name: '', location: '', location_code: null as null | string, address: '', charge_person: '', charge_phone: '', security_filing: '',
});

const columns = [
  { title: '单位名称', key: 'name', width: 200, ellipsis: { tooltip: true } },
  { title: '所在地', key: 'location', width: 120 },
  { title: '地址', key: 'address', width: 200, ellipsis: { tooltip: true } },
  { title: '负责人', key: 'charge_person', width: 100 },
  { title: '联系电话', key: 'charge_phone', width: 130 },
  { title: '安全备案', key: 'security_filing', width: 120 },
  { title: '关联资产数', key: 'used', width: 100 },
  {
    title: '操作', key: 'actions', width: 140, fixed: 'right' as const,
    render: (row: ConstructionOrg) => h(NSpace, { size: 4 }, () => [
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
    const res = await getConstructionList(params);
    const body = (res as any)?.data ?? res;
    data.value = body?.data ?? body?.items ?? [];
    pagination.itemCount = body?.count ?? 0;
  } catch { message.error('获取列表失败'); }
  finally { loading.value = false; }
}

function resetForm() { Object.assign(formData, { name: '', location: '', location_code: null, address: '', charge_person: '', charge_phone: '', security_filing: '' }); }

function onAdd() { editingId.value = null; resetForm(); showModal.value = true; }

function onEdit(row: ConstructionOrg) {
  editingId.value = row.id;
  Object.assign(formData, {
    name: row.name,
    location: row.location,
    location_code: regionCodeFromLabel(row.location),
    address: row.address,
    charge_person: row.charge_person,
    charge_phone: row.charge_phone,
    security_filing: row.security_filing,
  });
  showModal.value = true;
}

async function onSave() {
  if (!formData.name) { message.warning('请输入单位名称'); return; }
  const payload = {
    name: formData.name,
    location: regionLabelFromCode(formData.location_code) || formData.location,
    address: formData.address,
    charge_person: formData.charge_person,
    charge_phone: formData.charge_phone,
    security_filing: formData.security_filing,
  };
  try {
    if (editingId.value) { await updateConstruction(editingId.value, payload); message.success('更新成功'); }
    else { await createConstruction(payload); message.success('创建成功'); }
    showModal.value = false; fetchList();
  } catch { message.error('操作失败'); }
}

async function onDelete(id: string) {
  try { await deleteConstruction(id); message.success('删除成功'); fetchList(); }
  catch { message.error('删除失败'); }
}

onMounted(fetchList);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="建设运维单位" size="small">
      <template #header-extra><NButton type="primary" size="small" @click="onAdd">新增单位</NButton></template>
      <NForm inline label-placement="left" :show-feedback="false" style="margin-bottom: 16px">
        <NFormItem label="关键词"><NInput v-model:value="searchForm.keyword" placeholder="单位名称" clearable style="width: 200px" /></NFormItem>
        <NFormItem><NButton type="primary" @click="fetchList">查询</NButton></NFormItem>
      </NForm>
      <NDataTable :columns="columns" :data="data" :loading="loading" :pagination="pagination" :bordered="false" :scroll-x="1100" size="small" striped remote />
    </NCard>

    <NModal v-model:show="showModal" preset="dialog" :title="editingId ? '编辑单位' : '新增单位'" style="width: 580px">
      <NForm label-placement="left" label-width="80" style="margin-top: 16px">
        <NGrid :cols="2" :x-gap="16">
          <NGridItem><NFormItem label="名称" required><NInput v-model:value="formData.name" /></NFormItem></NGridItem>
          <NGridItem>
            <NFormItem label="所在地">
              <NCascader
                v-model:value="formData.location_code"
                :options="regionOptions"
                filterable
                clearable
                check-strategy="child"
                placeholder="请选择省/市/区县"
              />
            </NFormItem>
          </NGridItem>
          <NGridItem span="2"><NFormItem label="地址"><NInput v-model:value="formData.address" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="负责人"><NInput v-model:value="formData.charge_person" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="电话"><NInput v-model:value="formData.charge_phone" /></NFormItem></NGridItem>
          <NGridItem span="2"><NFormItem label="安全备案"><NInput v-model:value="formData.security_filing" /></NFormItem></NGridItem>
        </NGrid>
      </NForm>
      <template #action><NSpace><NButton @click="showModal = false">取消</NButton><NButton type="primary" @click="onSave">确认</NButton></NSpace></template>
    </NModal>
  </div>
</template>
