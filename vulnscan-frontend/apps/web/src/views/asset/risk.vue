<script lang="ts" setup>
import { h, onMounted, reactive, ref } from 'vue';
import {
  NButton, NCard, NDataTable, NProgress, NSpace, NTag, useMessage,
} from 'naive-ui';
import { getRiskList, recalculateAllRisk } from '#/api/assetmgr';

defineOptions({ name: 'AssetRisk' });

const message = useMessage();
const loading = ref(false);
const data = ref<any[]>([]);

const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50],
  onChange: (p: number) => { pagination.page = p; fetchList(); },
  onUpdatePageSize: (ps: number) => { pagination.pageSize = ps; pagination.page = 1; fetchList(); },
});

function riskColor(score: number) {
  if (score >= 80) return 'error';
  if (score >= 50) return 'warning';
  if (score >= 20) return 'info';
  return 'success';
}

const columns = [
  { title: '资产ID', key: 'asset_id', width: 140, ellipsis: { tooltip: true } },
  {
    title: '总分', key: 'total_score', width: 160,
    render: (row: any) => h(NSpace, { align: 'center', size: 8 }, () => [
      h(NProgress, { type: 'line', percentage: row.total_score, status: riskColor(row.total_score), showIndicator: false, style: 'width: 80px' }),
      h('span', { style: 'font-weight: 600' }, `${row.total_score.toFixed(0)}`),
    ]),
  },
  { title: '漏洞分', key: 'vuln_score', width: 80 },
  { title: '暴露分', key: 'exposure_score', width: 80 },
  {
    title: '严重漏洞', key: 'critical_vulns', width: 90,
    render: (row: any) => row.critical_vulns > 0 ? h(NTag, { type: 'error', size: 'small' }, () => row.critical_vulns) : '0',
  },
  { title: '漏洞总数', key: 'vuln_count', width: 80 },
  { title: '开放端口', key: 'open_ports', width: 80 },
];

async function fetchList() {
  loading.value = true;
  try {
    const res = await getRiskList({ page: pagination.page, page_size: pagination.pageSize });
    const body = (res as any)?.data ?? res;
    data.value = body?.data ?? [];
    pagination.itemCount = body?.count ?? 0;
  } catch { message.error('获取风险列表失败'); }
  finally { loading.value = false; }
}

async function onRecalculateAll() {
  try {
    const res = await recalculateAllRisk();
    message.success(`重算完成，已处理 ${(res as any)?.data?.recalculated ?? 0} 个资产`);
    fetchList();
  } catch { message.error('重算失败'); }
}

onMounted(fetchList);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="风险评估" size="small">
      <template #header-extra>
        <NButton type="warning" size="small" @click="onRecalculateAll">全部重算</NButton>
      </template>
      <NDataTable :columns="columns" :data="data" :loading="loading" :pagination="pagination" :bordered="false" :scroll-x="780" size="small" striped remote />
    </NCard>
  </div>
</template>
