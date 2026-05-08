<script lang="ts" setup>
import { h, onMounted, reactive, ref } from 'vue';
import {
  NButton, NCard, NDataTable, NForm, NFormItem, NInput, NModal,
  NSelect, NSpace, NTag, useMessage,
} from 'naive-ui';
import { getLifecycleList, lifecycleTransition } from '#/api/assetmgr';

defineOptions({ name: 'AssetLifecycle' });

const message = useMessage();
const loading = ref(false);
const data = ref<any[]>([]);
const showModal = ref(false);
const transForm = reactive({ asset_id: '', to_state: '', remark: '' });

const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50],
  onChange: (p: number) => { pagination.page = p; fetchList(); },
  onUpdatePageSize: (ps: number) => { pagination.pageSize = ps; pagination.page = 1; fetchList(); },
});

const searchAssetId = ref('');

const stateMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  discovered: { label: '已发现', type: 'default' },
  confirmed: { label: '已确认', type: 'info' },
  registered: { label: '已登记', type: 'success' },
  operating: { label: '运行中', type: 'success' },
  decommission: { label: '退役中', type: 'warning' },
  offline: { label: '已下线', type: 'error' },
};

const stateOptions = Object.entries(stateMap).map(([k, v]) => ({ label: v.label, value: k }));

const columns = [
  { title: '资产ID', key: 'asset_id', width: 140, ellipsis: { tooltip: true } },
  {
    title: '原状态', key: 'from_state', width: 100,
    render: (row: any) => { const s = stateMap[row.from_state]; return s ? h(NTag, { size: 'small', type: s.type }, () => s.label) : row.from_state || '-'; },
  },
  {
    title: '新状态', key: 'to_state', width: 100,
    render: (row: any) => { const s = stateMap[row.to_state]; return s ? h(NTag, { size: 'small', type: s.type }, () => s.label) : row.to_state; },
  },
  { title: '操作人', key: 'operator', width: 120 },
  { title: '备注', key: 'remark', width: 200, ellipsis: { tooltip: true } },
  { title: '时间', key: 'created_at', width: 170 },
];

async function fetchList() {
  loading.value = true;
  try {
    const params: Record<string, any> = { page: pagination.page, page_size: pagination.pageSize };
    if (searchAssetId.value) params.asset_id = searchAssetId.value;
    const res = await getLifecycleList(params);
    const body = (res as any)?.data ?? res;
    data.value = body?.data ?? [];
    pagination.itemCount = body?.count ?? 0;
  } catch { message.error('获取生命周期记录失败'); }
  finally { loading.value = false; }
}

function onTransition() {
  Object.assign(transForm, { asset_id: '', to_state: '', remark: '' });
  showModal.value = true;
}

async function onSaveTransition() {
  if (!transForm.asset_id || !transForm.to_state) { message.warning('请填写资产ID和目标状态'); return; }
  try {
    await lifecycleTransition(transForm);
    message.success('状态变更成功');
    showModal.value = false;
    fetchList();
  } catch { message.error('变更失败'); }
}

onMounted(fetchList);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="资产生命周期" size="small">
      <template #header-extra>
        <NButton type="primary" size="small" @click="onTransition">状态变更</NButton>
      </template>
      <NForm inline label-placement="left" :show-feedback="false" style="margin-bottom: 16px">
        <NFormItem label="资产ID">
          <NInput v-model:value="searchAssetId" placeholder="资产ID" clearable style="width: 200px" @keyup.enter="fetchList" />
        </NFormItem>
        <NFormItem><NButton type="primary" @click="fetchList">查询</NButton></NFormItem>
      </NForm>
      <NDataTable :columns="columns" :data="data" :loading="loading" :pagination="pagination" :bordered="false" :scroll-x="860" size="small" striped remote />
    </NCard>

    <NModal v-model:show="showModal" preset="dialog" title="资产状态变更" style="width: 460px">
      <NForm label-placement="left" label-width="80" style="margin-top: 16px">
        <NFormItem label="资产ID" required><NInput v-model:value="transForm.asset_id" placeholder="资产ID" /></NFormItem>
        <NFormItem label="目标状态" required><NSelect v-model:value="transForm.to_state" :options="stateOptions" /></NFormItem>
        <NFormItem label="备注"><NInput v-model:value="transForm.remark" type="textarea" :rows="2" /></NFormItem>
      </NForm>
      <template #action>
        <NSpace><NButton @click="showModal = false">取消</NButton><NButton type="primary" @click="onSaveTransition">确认</NButton></NSpace>
      </template>
    </NModal>
  </div>
</template>
