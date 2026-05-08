<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { NCard, NTabs, NTabPane, NDataTable, NStatistic, NGrid, NGridItem, NSpace, NButton, NSpin, useMessage } from 'naive-ui';
import { getRemediationStats, getOverdueList, getMultiDimAnalysis, getTrendPrediction, getAIAnalysis, generateReport } from '#/api/incident';

defineOptions({ name: 'IncidentReports' });

const message = useMessage();
const loading = ref(true);
const remStats = ref<any>(null);
const overdueData = ref<any[]>([]);
const analysisData = ref<any>(null);
const trendData = ref<any>(null);
const aiData = ref<any>(null);

const overdueColumns = [
  { title: '事件编号', key: 'incident_no', width: 160 },
  { title: '事件名称', key: 'name', minWidth: 200 },
  { title: '级别', key: 'level', width: 80 },
  { title: 'SLA期限', key: 'sla_deadline', width: 170 },
  { title: '超期天数', key: 'overdue_days', width: 100 },
];

async function fetchData() {
  try {
    const [r, o, a, t, ai] = await Promise.allSettled([getRemediationStats(), getOverdueList(), getMultiDimAnalysis(), getTrendPrediction(), getAIAnalysis()]);
    if (r.status === 'fulfilled') remStats.value = r.value;
    if (o.status === 'fulfilled') overdueData.value = (o.value as any) ?? [];
    if (a.status === 'fulfilled') analysisData.value = a.value;
    if (t.status === 'fulfilled') trendData.value = t.value;
    if (ai.status === 'fulfilled') aiData.value = ai.value;
  } finally { loading.value = false; }
}

async function handleGenReport() {
  try { await generateReport(); message.success('报表已生成'); } catch (e: any) { message.error(e?.message || '生成失败'); }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NSpin :show="loading">
      <NCard size="small">
        <template #header>
          <NSpace justify="space-between" align="center" style="width:100%">
            <span>报表中心</span>
            <NButton size="small" type="primary" @click="handleGenReport">生成报表</NButton>
          </NSpace>
        </template>
        <NTabs type="line" animated>
          <NTabPane name="remediation" tab="整改统计">
            <NGrid :cols="4" :x-gap="12" v-if="remStats" style="margin-bottom:16px">
              <NGridItem><NStatistic label="整改总数" :value="remStats?.total ?? 0" tabular-nums /></NGridItem>
              <NGridItem><NStatistic label="已完成" :value="remStats?.completed ?? 0" tabular-nums /></NGridItem>
              <NGridItem><NStatistic label="进行中" :value="remStats?.in_progress ?? 0" tabular-nums /></NGridItem>
              <NGridItem><NStatistic label="完成率" tabular-nums>{{ ((remStats?.completion_rate ?? 0) * 100).toFixed(1) }}%</NStatistic></NGridItem>
            </NGrid>
          </NTabPane>
          <NTabPane name="overdue" tab="超期列表">
            <NDataTable :columns="overdueColumns" :data="overdueData" :bordered="false" size="small" />
          </NTabPane>
          <NTabPane name="analysis" tab="多维分析">
            <pre v-if="analysisData" style="font-size:13px;background:#f8f8fa;padding:16px;border-radius:6px;overflow:auto">{{ JSON.stringify(analysisData, null, 2) }}</pre>
            <div v-else style="text-align:center;color:#999;padding:40px">暂无分析数据</div>
          </NTabPane>
          <NTabPane name="trend" tab="趋势预测">
            <pre v-if="trendData" style="font-size:13px;background:#f8f8fa;padding:16px;border-radius:6px;overflow:auto">{{ JSON.stringify(trendData, null, 2) }}</pre>
            <div v-else style="text-align:center;color:#999;padding:40px">暂无趋势数据</div>
          </NTabPane>
          <NTabPane name="ai" tab="AI 分析">
            <pre v-if="aiData" style="font-size:13px;background:#f8f8fa;padding:16px;border-radius:6px;overflow:auto">{{ JSON.stringify(aiData, null, 2) }}</pre>
            <div v-else style="text-align:center;color:#999;padding:40px">暂无AI分析数据</div>
          </NTabPane>
        </NTabs>
      </NCard>
    </NSpin>
  </div>
</template>
