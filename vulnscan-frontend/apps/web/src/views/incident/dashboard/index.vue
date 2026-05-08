<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { NCard, NGrid, NGridItem, NStatistic, NDataTable, NSpin } from 'naive-ui';
import { getDashboardStats, getChartByType, getChartByTrend, getSLAOverview, type DashboardStats, type SLAOverview } from '#/api/incident';

defineOptions({ name: 'IncidentDashboard' });

const loading = ref(true);
const stats = ref<DashboardStats | null>(null);
const typeData = ref<any[]>([]);
const trendData = ref<any[]>([]);
const slaOverview = ref<SLAOverview | null>(null);

const typeColumns = [
  { title: '事件类型', key: 'type', minWidth: 150 },
  { title: '数量', key: 'count', width: 100 },
  { title: '占比', key: 'percentage', width: 100 },
];

const trendColumns = [
  { title: '时间', key: 'period', minWidth: 120 },
  { title: '新增', key: 'created', width: 80 },
  { title: '已关闭', key: 'closed', width: 80 },
  { title: '待处理', key: 'pending', width: 80 },
];

async function fetchData() {
  try {
    const [s, t, tr, sla] = await Promise.allSettled([getDashboardStats(), getChartByType(), getChartByTrend(), getSLAOverview()]);
    if (s.status === 'fulfilled') stats.value = s.value as any;
    if (t.status === 'fulfilled') typeData.value = (t.value as any) ?? [];
    if (tr.status === 'fulfilled') trendData.value = (tr.value as any) ?? [];
    if (sla.status === 'fulfilled') slaOverview.value = sla.value as any;
  } finally { loading.value = false; }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NSpin :show="loading">
      <NGrid :cols="5" :x-gap="12" style="margin-bottom:16px">
        <NGridItem><NCard size="small"><NStatistic label="事件总数" :value="stats?.total ?? 0" tabular-nums /></NCard></NGridItem>
        <NGridItem><NCard size="small"><NStatistic label="待审核" tabular-nums><template #prefix><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#f0a020;margin-right:4px" /></template>{{ stats?.pending_audit ?? 0 }}</NStatistic></NCard></NGridItem>
        <NGridItem><NCard size="small"><NStatistic label="整改中" tabular-nums><template #prefix><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#2080f0;margin-right:4px" /></template>{{ stats?.in_remediation ?? 0 }}</NStatistic></NCard></NGridItem>
        <NGridItem><NCard size="small"><NStatistic label="已关闭" tabular-nums><template #prefix><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#18a058;margin-right:4px" /></template>{{ stats?.closed ?? 0 }}</NStatistic></NCard></NGridItem>
        <NGridItem><NCard size="small"><NStatistic label="超期" tabular-nums><template #prefix><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#d03050;margin-right:4px" /></template>{{ stats?.overdue ?? 0 }}</NStatistic></NCard></NGridItem>
      </NGrid>

      <NGrid :cols="2" :x-gap="12" style="margin-bottom:16px">
        <NGridItem>
          <NCard title="事件类型分布" size="small">
            <NDataTable :columns="typeColumns" :data="typeData" :bordered="false" size="small" :max-height="300" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard title="事件趋势" size="small">
            <NDataTable :columns="trendColumns" :data="trendData" :bordered="false" size="small" :max-height="300" />
          </NCard>
        </NGridItem>
      </NGrid>

      <NCard title="SLA 概览" size="small" v-if="slaOverview">
        <NGrid :cols="4" :x-gap="12">
          <NGridItem><NStatistic label="SLA总数" :value="slaOverview.total" tabular-nums /></NGridItem>
          <NGridItem><NStatistic label="达标数" :value="slaOverview.within_sla" tabular-nums /></NGridItem>
          <NGridItem><NStatistic label="违约数" :value="slaOverview.breached" tabular-nums /></NGridItem>
          <NGridItem><NStatistic label="违约率" tabular-nums>{{ ((slaOverview.breach_rate ?? 0) * 100).toFixed(1) }}%</NStatistic></NGridItem>
        </NGrid>
      </NCard>
    </NSpin>
  </div>
</template>
