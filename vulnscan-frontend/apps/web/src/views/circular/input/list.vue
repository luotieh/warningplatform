<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';
import { NButton, NCard, NDataTable, NInput, NSelect, NSpace, NTag, NPopconfirm, useMessage } from 'naive-ui';
import { useRouter } from 'vue-router';
import { getInputList, deleteInput, submitForVerify, type CircularItem, CircularStatusLabels, CircularStatusTypes, DataSourceLabels } from '#/api/circular';
import { formatCircularTime } from '../utils';
import CircularInputDrawer from './components/circular-input-drawer.vue';

defineOptions({ name: 'CircularInputList' });

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const data = ref<CircularItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const statusFilter = ref<string | null>(null);
const drawerVisible = ref(false);
const drawerEditId = ref('');

const statusOptions = Object.entries(CircularStatusLabels).map(([value, label]) => ({ label, value }));

const columns = computed(() => [
  { title: '通报编号', key: 'code', width: 160, ellipsis: { tooltip: true } },
  { title: '标题', key: 'title', minWidth: 200, render: (row: CircularItem) => h('a', { style: 'color:#2080f0;cursor:pointer', onClick: () => router.push(`/circular/input/${row.id}`) }, row.title) },
  { title: '来源', key: 'source', width: 110, render: (row: CircularItem) => DataSourceLabels[row.source] ?? row.source },
  { title: '状态', key: 'status', width: 100, render: (row: CircularItem) => h(NTag, { size: 'small', type: (CircularStatusTypes[row.status] || 'default') as any, bordered: false }, () => CircularStatusLabels[row.status] ?? row.status) },
  { title: '所属组织', key: 'organize', width: 140, ellipsis: { tooltip: true } },
  {
    title: '创建时间',
    key: 'created_at',
    width: 172,
    render: (row: CircularItem) => h('span', { style: 'white-space:nowrap;font-size:13px' }, formatCircularTime(row.created_at)),
  },
  { title: '操作', key: 'actions', width: 200, fixed: 'right' as const, render: (row: CircularItem) => h(NSpace, { size: 4 }, () => {
    const items: any[] = [h(NButton, { size: 'tiny', type: 'info', text: true, onClick: () => router.push(`/circular/input/${row.id}`) }, () => '详情')];
    if (row.status === 'to_be_submit') {
      items.push(h(NButton, { size: 'tiny', type: 'primary', text: true, onClick: () => openEditDrawer(row.id) }, () => '编辑'));
      items.push(h(NButton, { size: 'tiny', type: 'success', text: true, onClick: () => handleSubmit(row.id) }, () => '提交'));
      items.push(h(NPopconfirm, { onPositiveClick: () => handleDelete(row.id) }, { trigger: () => h(NButton, { size: 'tiny', type: 'error', text: true }, () => '删除'), default: () => '确定删除？' }));
    }
    return items;
  }) },
]);

function openCreateDrawer() {
  drawerEditId.value = '';
  drawerVisible.value = true;
}

function openEditDrawer(id: string) {
  drawerEditId.value = id;
  drawerVisible.value = true;
}

async function fetchData() {
  loading.value = true;
  try {
    const r = await getInputList({ index: page.value, size: pageSize.value, keyword: keyword.value || undefined, status: statusFilter.value || undefined });
    data.value = r.items; total.value = r.total;
  } finally { loading.value = false; }
}

async function handleSubmit(id: string) {
  try { await submitForVerify(id); message.success('已提交核验'); await fetchData(); } catch (e: any) { message.error(e?.message || '提交失败'); }
}
async function handleDelete(id: string) {
  try { await deleteInput(id); message.success('已删除'); await fetchData(); } catch (e: any) { message.error(e?.message || '删除失败'); }
}

function applyRouteDrawerQuery() {
  const q = router.currentRoute.value.query;
  if (q.create === '1' || q.create === 'true') {
    openCreateDrawer();
    router.replace({ path: '/circular/input' });
    return;
  }
  const editId = typeof q.edit === 'string' ? q.edit : '';
  if (editId) {
    openEditDrawer(editId);
    router.replace({ path: '/circular/input' });
  }
}

onMounted(async () => {
  await fetchData();
  applyRouteDrawerQuery();
});
</script>

<template>
  <div style="padding:16px">
    <NCard title="通报录入" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NSelect v-model:value="statusFilter" :options="statusOptions" placeholder="状态" size="small" style="width:130px" clearable @update:value="()=>{page=1;fetchData()}" />
          <NInput v-model:value="keyword" placeholder="搜索..." size="small" clearable style="width:200px" @keyup.enter="()=>{page=1;fetchData()}" @clear="()=>{page=1;fetchData()}" />
          <NButton size="small" type="primary" @click="()=>{page=1;fetchData()}">搜索</NButton>
          <NButton size="small" type="primary" @click="openCreateDrawer">新建通报</NButton>
        </NSpace>
      </template>
      <NDataTable :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped :scroll-x="1000"
        :pagination="{ page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20,50,100], onUpdatePage: (p:number)=>{page=p;fetchData()}, onUpdatePageSize: (s:number)=>{pageSize=s;page=1;fetchData()} }" />
    </NCard>

    <CircularInputDrawer
      v-model:show="drawerVisible"
      :edit-id="drawerEditId"
      @saved="fetchData"
    />
  </div>
</template>
