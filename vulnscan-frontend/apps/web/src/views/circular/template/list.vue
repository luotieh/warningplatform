<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';
import { NButton, NCard, NDataTable, NSpace, NTag, NPopconfirm, NModal, NForm, NFormItem, NInput, NSelect, NSwitch, useMessage } from 'naive-ui';
import { getTemplateList, createTemplate, updateTemplate, deleteTemplate, type CircularTemplate, type CircularTemplateType, TemplateTypeLabels } from '#/api/circular';

defineOptions({ name: 'CircularTemplateList' });

const message = useMessage();
const loading = ref(false);
const data = ref<CircularTemplate[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const showModal = ref(false);
const editingId = ref('');
const form = ref({ template_name: '', type: 'input' as CircularTemplateType, template_description: '', template_data: '', default_flag: false });
const typeOptions = Object.entries(TemplateTypeLabels).map(([v, l]) => ({ label: l, value: v }));

const columns = computed(() => [
  { title: '模板名称', key: 'template_name', minWidth: 200 },
  { title: '类型', key: 'type', width: 100, render: (row: CircularTemplate) => TemplateTypeLabels[row.type] ?? row.type },
  { title: '默认', key: 'default_flag', width: 80, render: (row: CircularTemplate) => h(NTag, { size: 'small', type: row.default_flag ? 'success' : 'default', bordered: false }, () => row.default_flag ? '是' : '否') },
  { title: '创建时间', key: 'created_at', width: 170 },
  { title: '操作', key: 'actions', width: 150, fixed: 'right' as const, render: (row: CircularTemplate) => h(NSpace, { size: 4 }, () => [
    h(NButton, { size: 'tiny', type: 'primary', text: true, onClick: () => openEdit(row) }, () => '编辑'),
    h(NPopconfirm, { onPositiveClick: () => handleDelete(row.id) }, { trigger: () => h(NButton, { size: 'tiny', type: 'error', text: true }, () => '删除'), default: () => '确定删除？' }),
  ]) },
]);

function openCreate() { editingId.value = ''; form.value = { template_name: '', type: 'input', template_description: '', template_data: '', default_flag: false }; showModal.value = true; }
function openEdit(row: CircularTemplate) { editingId.value = row.id; form.value = { template_name: row.template_name, type: row.type, template_description: row.template_description || '', template_data: row.template_data || '', default_flag: row.default_flag }; showModal.value = true; }

async function fetchData() {
  loading.value = true;
  try { const r = await getTemplateList({ index: page.value, size: pageSize.value }); data.value = r.items; total.value = r.total; }
  finally { loading.value = false; }
}

async function handleSave() {
  if (!form.value.template_name) { message.warning('请输入模板名称'); return; }
  try {
    if (editingId.value) { await updateTemplate(editingId.value, form.value); message.success('更新成功'); }
    else { await createTemplate(form.value); message.success('创建成功'); }
    showModal.value = false; await fetchData();
  } catch (e: any) { message.error(e?.message || '保存失败'); }
}

async function handleDelete(id: string) {
  try { await deleteTemplate(id); message.success('已删除'); await fetchData(); } catch (e: any) { message.error(e?.message || '删除失败'); }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NCard title="通报模板" size="small">
      <template #header-extra>
        <NButton size="small" type="primary" @click="openCreate">新建模板</NButton>
      </template>
      <NDataTable :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped
        :pagination="{ page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20,50,100], onUpdatePage:(p:number)=>{page=p;fetchData()}, onUpdatePageSize:(s:number)=>{pageSize=s;page=1;fetchData()} }" />
    </NCard>
    <NModal v-model:show="showModal" preset="dialog" :title="editingId ? '编辑模板' : '新建模板'" positive-text="保存" negative-text="取消" @positive-click="handleSave">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="模板名称" required><NInput v-model:value="form.template_name" placeholder="请输入模板名称" /></NFormItem>
        <NFormItem label="模板类型"><NSelect v-model:value="form.type" :options="typeOptions" /></NFormItem>
        <NFormItem label="描述"><NInput v-model:value="form.template_description" type="textarea" :rows="2" /></NFormItem>
        <NFormItem label="模板数据"><NInput v-model:value="form.template_data" type="textarea" placeholder="JSON格式" :rows="4" /></NFormItem>
        <NFormItem label="设为默认"><NSwitch v-model:value="form.default_flag" /></NFormItem>
      </NForm>
    </NModal>
  </div>
</template>
