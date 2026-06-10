<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';
import { NButton, NCard, NDataTable, NInput, NSelect, NSpace, NTag } from 'naive-ui';
import { useRouter } from 'vue-router';
import { getLedgerList, type CircularItem, CircularStatusLabels, CircularStatusTypes } from '#/api/circular';
import { useNaiveTablePagination } from '#/composables/useNaiveTablePagination';
import { formatCircularTime } from '../utils';

defineOptions({ name: 'CircularLedgerList' });

const router = useRouter();
const loading = ref(false);
const data = ref<CircularItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const statusFilter = ref<string | null>(null);
const statusOptions = Object.entries(CircularStatusLabels).map(([value, label]) => ({ label, value }));

const columns = computed(() => [
  { title: '通报编号', key: 'code', width: 160 },
  { title: '标题', key: 'title', minWidth: 200, render: (row: CircularItem) => h('a', { style: 'color:#2080f0;cursor:pointer', onClick: () => router.push(`/circular/ledger/${row.id}`) }, row.title) },
  { title: '状态', key: 'status', width: 100, render: (row: CircularItem) => h(NTag, { size: 'small', type: (CircularStatusTypes[row.status]||'default') as any, bordered: false }, () => CircularStatusLabels[row.status] ?? row.status) },
  { title: '所属组织', key: 'organize', width: 140 },
  {
    title: '创建时间',
    key: 'created_at',
    width: 172,
    render: (row: CircularItem) => h('span', { style: 'white-space:nowrap;font-size:13px' }, formatCircularTime(row.created_at)),
  },
  { title: '操作', key: 'actions', width: 80, fixed: 'right' as const, render: (row: CircularItem) => h(NButton, { size: 'tiny', type: 'info', text: true, onClick: () => router.push(`/circular/ledger/${row.id}`) }, () => '详情') },
]);

async function fetchData() {
  loading.value = true;
  try { const r = await getLedgerList({ page: page.value, page_size: pageSize.value, keyword: keyword.value || undefined, status: statusFilter.value || undefined }); data.value = r.items; total.value = r.total; }
  finally { loading.value = false; }
}

const { pagination } = useNaiveTablePagination({ page, pageSize, total, onFetch: fetchData });

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NCard title="通报台账" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NSelect v-model:value="statusFilter" :options="statusOptions" placeholder="状态" size="small" style="width:130px" clearable @update:value="()=>{page=1;fetchData()}" />
          <NInput v-model:value="keyword" placeholder="搜索..." size="small" clearable style="width:200px" @keyup.enter="()=>{page=1;fetchData()}" />
          <NButton size="small" type="primary" @click="()=>{page=1;fetchData()}">搜索</NButton>
        </NSpace>
      </template>
      <NDataTable :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped
        remote :pagination="pagination" />
    </NCard>
  </div>
</template>
