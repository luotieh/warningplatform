<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';
import { NButton, NCard, NDataTable, NInput, NSelect, NSpace, NTag, NPopconfirm, NModal, NForm, NFormItem, useMessage } from 'naive-ui';
import { useRouter } from 'vue-router';
import { getKnowledgeList, createKnowledge, updateKnowledge, deleteKnowledge, archiveKnowledge, type KnowledgeArticle } from '#/api/incident';

defineOptions({ name: 'KnowledgeArticles' });

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const data = ref<KnowledgeArticle[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const categoryFilter = ref<string | null>(null);
const showModal = ref(false);
const editingId = ref('');
const form = ref({ title: '', category: '', content: '', tags: [] as string[] });

const categoryOptions = [
  { label: '案例', value: '案例' }, { label: '预案', value: '预案' },
  { label: '知识', value: '知识' }, { label: '经验', value: '经验' },
];

const columns = computed(() => [
  { title: '标题', key: 'title', minWidth: 200, render: (row: KnowledgeArticle) => h('a', { style: 'color:#2080f0;cursor:pointer', onClick: () => router.push(`/knowledge/articles/${row.id}`) }, row.title) },
  { title: '分类', key: 'category', width: 80, render: (row: KnowledgeArticle) => h(NTag, { size: 'small', bordered: false }, () => row.category || '-') },
  { title: '标签', key: 'tags', width: 200, render: (row: KnowledgeArticle) => { const tags = row.tags ?? []; if (!tags.length) return '-'; return h(NSpace, { size: 4 }, () => tags.slice(0, 3).map(t => h(NTag, { size: 'tiny', bordered: false, type: 'info' }, () => t))); } },
  { title: '浏览量', key: 'view_count', width: 80 },
  { title: '创建时间', key: 'created_at', width: 170 },
  { title: '操作', key: 'actions', width: 200, fixed: 'right' as const, render: (row: KnowledgeArticle) => h(NSpace, { size: 4 }, () => [
    h(NButton, { size: 'tiny', type: 'info', text: true, onClick: () => router.push(`/knowledge/articles/${row.id}`) }, () => '查看'),
    h(NButton, { size: 'tiny', type: 'primary', text: true, onClick: () => openEdit(row) }, () => '编辑'),
    h(NButton, { size: 'tiny', text: true, onClick: () => handleArchive(row.id) }, () => '归档'),
    h(NPopconfirm, { onPositiveClick: () => handleDelete(row.id) }, { trigger: () => h(NButton, { size: 'tiny', type: 'error', text: true }, () => '删除'), default: () => '确定删除？' }),
  ]) },
]);

function openCreate() { editingId.value = ''; form.value = { title: '', category: '', content: '', tags: [] }; showModal.value = true; }
function openEdit(row: KnowledgeArticle) { editingId.value = row.id; form.value = { title: row.title, category: row.category, content: row.content, tags: row.tags ?? [] }; showModal.value = true; }

async function fetchData() {
  loading.value = true;
  try { const r = await getKnowledgeList({ index: page.value, size: pageSize.value, keyword: keyword.value || undefined, category: categoryFilter.value || undefined }); data.value = r.items; total.value = r.total; }
  finally { loading.value = false; }
}

async function handleSave() {
  if (!form.value.title) { message.warning('请输入标题'); return; }
  try {
    if (editingId.value) { await updateKnowledge(editingId.value, form.value); message.success('更新成功'); }
    else { await createKnowledge(form.value); message.success('创建成功'); }
    showModal.value = false; await fetchData();
  } catch (e: any) { message.error(e?.message || '保存失败'); }
}

async function handleDelete(id: string) { try { await deleteKnowledge(id); message.success('已删除'); await fetchData(); } catch (e: any) { message.error(e?.message || '删除失败'); } }
async function handleArchive(id: string) { try { await archiveKnowledge(id); message.success('已归档'); await fetchData(); } catch (e: any) { message.error(e?.message || '归档失败'); } }

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NCard title="安全知识库" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NSelect v-model:value="categoryFilter" :options="categoryOptions" placeholder="分类" size="small" style="width:100px" clearable @update:value="()=>{page=1;fetchData()}" />
          <NInput v-model:value="keyword" placeholder="搜索..." size="small" clearable style="width:200px" @keyup.enter="()=>{page=1;fetchData()}" />
          <NButton size="small" type="primary" @click="()=>{page=1;fetchData()}">搜索</NButton>
          <NButton size="small" type="primary" @click="openCreate">新建文章</NButton>
        </NSpace>
      </template>
      <NDataTable :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped
        :pagination="{ page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20,50,100], onUpdatePage:(p:number)=>{page=p;fetchData()}, onUpdatePageSize:(s:number)=>{pageSize=s;page=1;fetchData()} }" />
    </NCard>
    <NModal v-model:show="showModal" preset="dialog" :title="editingId?'编辑文章':'新建文章'" positive-text="保存" negative-text="取消" @positive-click="handleSave" style="width:600px">
      <NForm label-placement="left" label-width="60">
        <NFormItem label="标题" required><NInput v-model:value="form.title" /></NFormItem>
        <NFormItem label="分类"><NSelect v-model:value="form.category" :options="categoryOptions" /></NFormItem>
        <NFormItem label="内容"><NInput v-model:value="form.content" type="textarea" :rows="8" /></NFormItem>
      </NForm>
    </NModal>
  </div>
</template>
