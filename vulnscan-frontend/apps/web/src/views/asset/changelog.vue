<script lang="ts" setup>
import { h, onMounted, reactive, ref } from 'vue';
import { NButton, NCard, NDataTable, NForm, NFormItem, NInput, NSpace, NTag, useMessage } from 'naive-ui';
import { getChangeLogs } from '#/api/assetmgr';

defineOptions({ name: 'AssetChangeLog' });

const message = useMessage();
const loading = ref(false);
const data = ref<any[]>([]);

const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50],
  onChange: (p: number) => { pagination.page = p; fetchList(); },
  onUpdatePageSize: (ps: number) => { pagination.pageSize = ps; pagination.page = 1; fetchList(); },
});

const searchForm = reactive({ asset_id: '' });

const changeTypeMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  create: { label: '创建', type: 'success' },
  update: { label: '更新', type: 'info' },
  delete: { label: '删除', type: 'error' },
  state_change: { label: '状态变更', type: 'warning' },
};

const columns = [
  { title: '资产ID', key: 'asset_id', width: 140, ellipsis: { tooltip: true } },
  {
    title: '变更类型', key: 'change_type', width: 100,
    render: (row: any) => { const m = changeTypeMap[row.change_type]; return m ? h(NTag, { size: 'small', type: m.type }, () => m.label) : row.change_type; },
  },
  { title: '字段', key: 'field', width: 120 },
  { title: '旧值', key: 'old_value', width: 160, ellipsis: { tooltip: true } },
  { title: '新值', key: 'new_value', width: 160, ellipsis: { tooltip: true } },
  { title: '操作人', key: 'operator', width: 100 },
  { title: '来源', key: 'source', width: 80 },
  { title: '时间', key: 'created_at', width: 170 },
];

async function fetchList() {
  loading.value = true;
  try {
    const params: Record<string, any> = { page: pagination.page, page_size: pagination.pageSize, ...searchForm };
    const res = await getChangeLogs(params);
    const body = (res as any)?.data ?? res;
    data.value = body?.data ?? body?.items ?? [];
    pagination.itemCount = body?.count ?? 0;
  } catch { message.error('获取变更日志失败'); }
  finally { loading.value = false; }
}

onMounted(fetchList);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="变更日志" size="small">
      <NForm inline label-placement="left" :show-feedback="false" style="margin-bottom: 16px">
        <NFormItem label="资产ID"><NInput v-model:value="searchForm.asset_id" placeholder="资产ID" clearable style="width: 200px" /></NFormItem>
        <NFormItem><NSpace :size="8"><NButton type="primary" @click="fetchList">查询</NButton><NButton @click="searchForm.asset_id = ''; fetchList()">重置</NButton></NSpace></NFormItem>
      </NForm>
      <NDataTable :columns="columns" :data="data" :loading="loading" :pagination="pagination" :bordered="false" :scroll-x="1020" size="small" striped remote />
    </NCard>
  </div>
</template>
