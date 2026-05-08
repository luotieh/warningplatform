<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';
import { NButton, NCard, NDataTable, NSpace, NTag, NModal, NForm, NFormItem, NInput, useMessage } from 'naive-ui';
import { useRouter } from 'vue-router';
import { getDisposalList, redistributeCircular, type CircularItem, CircularStatusLabels, CircularStatusTypes } from '#/api/circular';

defineOptions({ name: 'CircularDisposalList' });

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const data = ref<CircularItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const showRedist = ref(false);
const redistForm = ref({ circular_id: '', distribution_id: '', target_organize: '', processing_deadline: '', requirements: '' });

const columns = computed(() => [
  { title: '通报编号', key: 'code', width: 160 },
  { title: '标题', key: 'title', minWidth: 200 },
  { title: '状态', key: 'status', width: 100, render: (row: CircularItem) => h(NTag, { size: 'small', type: (CircularStatusTypes[row.status]||'default') as any, bordered: false }, () => CircularStatusLabels[row.status] ?? row.status) },
  { title: '处置期限', key: 'processing_deadline', width: 170 },
  { title: '操作', key: 'actions', width: 150, fixed: 'right' as const, render: (row: CircularItem) => h(NSpace, { size: 4 }, () => [
    h(NButton, { size: 'tiny', type: 'primary', onClick: () => router.push(`/circular/disposal/${row.id}`) }, () => '处置'),
    h(NButton, { size: 'tiny', onClick: () => { redistForm.value.circular_id = row.id; showRedist.value = true; } }, () => '转派'),
  ]) },
]);

async function fetchData() {
  loading.value = true;
  try { const r = await getDisposalList({ index: page.value, size: pageSize.value }); data.value = r.items; total.value = r.total; }
  finally { loading.value = false; }
}

async function handleRedistribute() {
  if (!redistForm.value.target_organize) { message.warning('请输入目标组织'); return; }
  try { await redistributeCircular(redistForm.value); message.success('转派成功'); showRedist.value = false; await fetchData(); }
  catch (e: any) { message.error(e?.message || '转派失败'); }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NCard title="通报处置" size="small">
      <NDataTable :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped
        :pagination="{ page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20,50,100], onUpdatePage:(p:number)=>{page=p;fetchData()}, onUpdatePageSize:(s:number)=>{pageSize=s;page=1;fetchData()} }" />
    </NCard>
    <NModal v-model:show="showRedist" preset="dialog" title="转派通报" positive-text="确认" negative-text="取消" @positive-click="handleRedistribute">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="目标组织" required><NInput v-model:value="redistForm.target_organize" placeholder="请输入目标组织" /></NFormItem>
        <NFormItem label="处置期限"><NInput v-model:value="redistForm.processing_deadline" placeholder="YYYY-MM-DD" /></NFormItem>
        <NFormItem label="要求"><NInput v-model:value="redistForm.requirements" type="textarea" :rows="3" /></NFormItem>
      </NForm>
    </NModal>
  </div>
</template>
