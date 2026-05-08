<script lang="ts" setup>
import { h, onMounted, reactive, ref } from 'vue';
import {
  NButton, NCard, NDataTable, NForm, NFormItem, NPopconfirm,
  NSelect, NSpace, NTag, useMessage,
} from 'naive-ui';
import { ackAlert, getAlertList, resolveAlert } from '#/api/assetmgr';

defineOptions({ name: 'AssetAlert' });

const message = useMessage();
const loading = ref(false);
const data = ref<any[]>([]);

const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50],
  onChange: (p: number) => { pagination.page = p; fetchList(); },
  onUpdatePageSize: (ps: number) => { pagination.pageSize = ps; pagination.page = 1; fetchList(); },
});

const searchForm = reactive({ status: undefined as string | undefined, severity: undefined as string | undefined });

const severityMap: Record<string, { type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  critical: { type: 'error' }, high: { type: 'error' }, medium: { type: 'warning' }, low: { type: 'info' }, info: { type: 'default' },
};
const statusMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  open: { label: '待处理', type: 'error' }, acked: { label: '已确认', type: 'warning' }, resolved: { label: '已解决', type: 'success' },
};

const columns = [
  {
    title: '严重度', key: 'severity', width: 80,
    render: (row: any) => h(NTag, { type: severityMap[row.severity]?.type ?? 'default', size: 'small' }, () => row.severity),
  },
  { title: '标题', key: 'title', width: 200, ellipsis: { tooltip: true } },
  { title: '类型', key: 'alert_type', width: 100 },
  { title: '资产ID', key: 'asset_id', width: 140, ellipsis: { tooltip: true } },
  {
    title: '状态', key: 'status', width: 80,
    render: (row: any) => { const s = statusMap[row.status]; return s ? h(NTag, { size: 'small', type: s.type }, () => s.label) : row.status; },
  },
  { title: '来源', key: 'source', width: 80 },
  { title: '时间', key: 'created_at', width: 170 },
  {
    title: '操作', key: 'actions', width: 160, fixed: 'right' as const,
    render: (row: any) => h(NSpace, { size: 4 }, () => [
      row.status === 'open' ? h(NPopconfirm, { onPositiveClick: () => onAck(row.id) }, {
        trigger: () => h(NButton, { size: 'small', type: 'warning' }, () => '确认'),
        default: () => '确认该告警？',
      }) : null,
      row.status !== 'resolved' ? h(NPopconfirm, { onPositiveClick: () => onResolve(row.id) }, {
        trigger: () => h(NButton, { size: 'small', type: 'success' }, () => '解决'),
        default: () => '标记为已解决？',
      }) : null,
    ]),
  },
];

async function fetchList() {
  loading.value = true;
  try {
    const params: Record<string, any> = { page: pagination.page, page_size: pagination.pageSize, ...searchForm };
    const res = await getAlertList(params);
    const body = (res as any)?.data ?? res;
    data.value = body?.data ?? [];
    pagination.itemCount = body?.count ?? 0;
  } catch { message.error('获取告警失败'); }
  finally { loading.value = false; }
}

async function onAck(id: string) {
  try { await ackAlert(id); message.success('确认成功'); fetchList(); } catch { message.error('操作失败'); }
}

async function onResolve(id: string) {
  try { await resolveAlert(id); message.success('标记已解决'); fetchList(); } catch { message.error('操作失败'); }
}

onMounted(fetchList);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="安全告警" size="small">
      <NForm inline label-placement="left" :show-feedback="false" style="margin-bottom: 16px">
        <NFormItem label="状态">
          <NSelect v-model:value="searchForm.status" :options="Object.entries(statusMap).map(([k,v])=>({label:v.label,value:k}))" placeholder="全部" clearable style="width: 100px" />
        </NFormItem>
        <NFormItem label="严重度">
          <NSelect v-model:value="searchForm.severity" :options="['critical','high','medium','low','info'].map(s=>({label:s,value:s}))" placeholder="全部" clearable style="width: 100px" />
        </NFormItem>
        <NFormItem><NButton type="primary" @click="fetchList">查询</NButton></NFormItem>
      </NForm>
      <NDataTable :columns="columns" :data="data" :loading="loading" :pagination="pagination" :bordered="false" :scroll-x="1010" size="small" striped remote />
    </NCard>
  </div>
</template>
