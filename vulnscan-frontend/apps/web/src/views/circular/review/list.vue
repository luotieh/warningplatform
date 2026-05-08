<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';
import { NButton, NCard, NDataTable, NTag, NModal, NRadioGroup, NRadio, NFormItem, NInput, useMessage } from 'naive-ui';
import { getReviewList, reviewCircular, type CircularItem, CircularStatusLabels, CircularStatusTypes } from '#/api/circular';

defineOptions({ name: 'CircularReviewList' });

const message = useMessage();
const loading = ref(false);
const data = ref<CircularItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const showModal = ref(false);
const currentId = ref('');
const reviewForm = ref({ review: 'approve', instructions: '' });

const columns = computed(() => [
  { title: '通报编号', key: 'code', width: 160 },
  { title: '标题', key: 'title', minWidth: 200 },
  { title: '状态', key: 'status', width: 100, render: (row: CircularItem) => h(NTag, { size: 'small', type: (CircularStatusTypes[row.status]||'default') as any, bordered: false }, () => CircularStatusLabels[row.status] ?? row.status) },
  { title: '所属组织', key: 'organize', width: 140 },
  { title: '创建时间', key: 'created_at', width: 170 },
  { title: '操作', key: 'actions', width: 100, fixed: 'right' as const, render: (row: CircularItem) => h(NButton, { size: 'tiny', type: 'primary', onClick: () => { currentId.value = row.id; showModal.value = true; } }, () => '审核') },
]);

async function fetchData() {
  loading.value = true;
  try { const r = await getReviewList({ index: page.value, size: pageSize.value }); data.value = r.items; total.value = r.total; }
  finally { loading.value = false; }
}

async function handleReview() {
  try { await reviewCircular(currentId.value, reviewForm.value); message.success('审核完成'); showModal.value = false; reviewForm.value = { review: 'approve', instructions: '' }; await fetchData(); }
  catch (e: any) { message.error(e?.message || '审核失败'); }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NCard title="处置审核" size="small">
      <NDataTable :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped
        :pagination="{ page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20,50,100], onUpdatePage:(p:number)=>{page=p;fetchData()}, onUpdatePageSize:(s:number)=>{pageSize=s;page=1;fetchData()} }" />
    </NCard>
    <NModal v-model:show="showModal" preset="dialog" title="审核通报" positive-text="确认" negative-text="取消" @positive-click="handleReview">
      <NFormItem label="审核结果">
        <NRadioGroup v-model:value="reviewForm.review">
          <NRadio value="approve">通过</NRadio>
          <NRadio value="reject">驳回</NRadio>
        </NRadioGroup>
      </NFormItem>
      <NFormItem label="审核意见"><NInput v-model:value="reviewForm.instructions" type="textarea" placeholder="请输入审核意见" :rows="3" /></NFormItem>
    </NModal>
  </div>
</template>
