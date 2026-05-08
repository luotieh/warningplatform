<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';
import { NButton, NCard, NDataTable, NInput, NSpace, NTag, NModal, NRadioGroup, NRadio, NFormItem, useMessage } from 'naive-ui';
import { getVerifyList, verifyCircular, type CircularItem, CircularStatusLabels, CircularStatusTypes } from '#/api/circular';

defineOptions({ name: 'CircularVerifyList' });

const message = useMessage();
const loading = ref(false);
const data = ref<CircularItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const showModal = ref(false);
const selectedIds = ref<string[]>([]);
const verifyResult = ref('pass');

const columns = computed(() => [
  { title: '通报编号', key: 'code', width: 160 },
  { title: '标题', key: 'title', minWidth: 200 },
  { title: '状态', key: 'status', width: 100, render: (row: CircularItem) => h(NTag, { size: 'small', type: (CircularStatusTypes[row.status]||'default') as any, bordered: false }, () => CircularStatusLabels[row.status] ?? row.status) },
  { title: '所属组织', key: 'organize', width: 140 },
  { title: '创建时间', key: 'created_at', width: 170 },
  { title: '操作', key: 'actions', width: 100, fixed: 'right' as const, render: (row: CircularItem) => h(NButton, { size: 'tiny', type: 'primary', onClick: () => { selectedIds.value = [row.id]; showModal.value = true; } }, () => '核验') },
]);

async function fetchData() {
  loading.value = true;
  try { const r = await getVerifyList({ index: page.value, size: pageSize.value, keyword: keyword.value || undefined }); data.value = r.items; total.value = r.total; }
  finally { loading.value = false; }
}

async function handleVerify() {
  try { await verifyCircular({ circular_ids: selectedIds.value, result: verifyResult.value }); message.success('核验完成'); showModal.value = false; await fetchData(); }
  catch (e: any) { message.error(e?.message || '核验失败'); }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NCard title="通报核验" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NInput v-model:value="keyword" placeholder="搜索..." size="small" clearable style="width:200px" @keyup.enter="()=>{page=1;fetchData()}" />
          <NButton size="small" type="primary" @click="()=>{page=1;fetchData()}">搜索</NButton>
        </NSpace>
      </template>
      <NDataTable :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped
        :pagination="{ page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20,50,100], onUpdatePage:(p:number)=>{page=p;fetchData()}, onUpdatePageSize:(s:number)=>{pageSize=s;page=1;fetchData()} }" />
    </NCard>
    <NModal v-model:show="showModal" preset="dialog" title="核验通报" positive-text="确认" negative-text="取消" @positive-click="handleVerify">
      <NFormItem label="核验结果">
        <NRadioGroup v-model:value="verifyResult">
          <NRadio value="pass">通过</NRadio>
          <NRadio value="reject">驳回</NRadio>
        </NRadioGroup>
      </NFormItem>
    </NModal>
  </div>
</template>
