<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';
import { NButton, NCard, NDataTable, NTag, NModal, NForm, NFormItem, useMessage } from 'naive-ui';
import { getDistributeList, distributeCircular, type CircularItem, CircularStatusLabels, CircularStatusTypes } from '#/api/circular';

defineOptions({ name: 'CircularDistributeList' });

const message = useMessage();
const loading = ref(false);
const data = ref<CircularItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const showModal = ref(false);
const currentId = ref('');
const distForm = ref({ target_organize: '', processing_deadline: '', requirements: '' });

const columns = computed(() => [
  { title: '通报编号', key: 'code', width: 160 },
  { title: '标题', key: 'title', minWidth: 200 },
  { title: '状态', key: 'status', width: 100, render: (row: CircularItem) => h(NTag, { size: 'small', type: (CircularStatusTypes[row.status]||'default') as any, bordered: false }, () => CircularStatusLabels[row.status] ?? row.status) },
  { title: '所属组织', key: 'organize', width: 140 },
  { title: '创建时间', key: 'created_at', width: 170 },
  { title: '操作', key: 'actions', width: 100, fixed: 'right' as const, render: (row: CircularItem) => h(NButton, { size: 'tiny', type: 'primary', onClick: () => { currentId.value = row.id; showModal.value = true; } }, () => '派发') },
]);

async function fetchData() {
  loading.value = true;
  try { const r = await getDistributeList({ index: page.value, size: pageSize.value }); data.value = r.items; total.value = r.total; }
  finally { loading.value = false; }
}

async function handleDistribute() {
  if (!distForm.value.target_organize) { message.warning('请输入目标组织'); return; }
  try {
    await distributeCircular({ circular_id: currentId.value, ...distForm.value });
    message.success('派发成功'); showModal.value = false; distForm.value = { target_organize: '', processing_deadline: '', requirements: '' }; await fetchData();
  } catch (e: any) { message.error(e?.message || '派发失败'); }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NCard title="通报派发" size="small">
      <NDataTable :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped
        :pagination="{ page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20,50,100], onUpdatePage:(p:number)=>{page=p;fetchData()}, onUpdatePageSize:(s:number)=>{pageSize=s;page=1;fetchData()} }" />
    </NCard>
    <NModal v-model:show="showModal" preset="dialog" title="派发通报" positive-text="确认派发" negative-text="取消" @positive-click="handleDistribute">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="目标组织" required><NInput v-model:value="distForm.target_organize" placeholder="请输入目标组织" /></NFormItem>
        <NFormItem label="处置期限"><NInput v-model:value="distForm.processing_deadline" placeholder="YYYY-MM-DD" /></NFormItem>
        <NFormItem label="处置要求"><NInput v-model:value="distForm.requirements" type="textarea" placeholder="请输入处置要求" :rows="3" /></NFormItem>
      </NForm>
    </NModal>
  </div>
</template>
