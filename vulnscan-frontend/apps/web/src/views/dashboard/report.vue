<script lang="ts" setup>
import { ref, computed, h, onMounted } from 'vue';
import {
  NCard, NGrid, NGridItem, NButton, NSpace, NSelect, NInput,
  NStatistic, NTag, NDataTable, NModal, NForm, NFormItem,
  useMessage, NEmpty, NSpin, NDynamicTags, NCheckbox, NCheckboxGroup,
  NProgress, NDivider,
} from 'naive-ui';
import type { DataTableColumns } from 'naive-ui';
import { EchartsUI, useEcharts } from '@vben/plugins/echarts';
import type { EchartsUIType } from '@vben/plugins/echarts';
import {
  generateReport, getTaskReportJSON, getTaskReportURL,
  type ReportData, type ReportRequest, type VulnItem,
} from '#/api/report';
import { getRecentTasks } from '#/api/dashboard';

defineOptions({ name: 'DashboardReport' });

const message = useMessage();
const loading = ref(false);
const reportData = ref<ReportData | null>(null);
const tasks = ref<any[]>([]);

const sevPieRef = ref<EchartsUIType>();
const assetBarRef = ref<EchartsUIType>();
const { renderEcharts: renderSevPie } = useEcharts(sevPieRef);
const { renderEcharts: renderAssetBar } = useEcharts(assetBarRef);

const sevColors: Record<string, string> = {
  critical: '#e53e3e', high: '#dd6b20', medium: '#d69e2e', low: '#38a169', info: '#4299e1',
};
const sevLabels: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
};

onMounted(async () => {
  try {
    const res = await getRecentTasks({ page: 1, page_size: 50 });
    tasks.value = res.items;
  } catch {}
});

const taskOptions = computed(() => tasks.value.map((t: any) => ({
  label: `${t.name} (${t.status})`, value: t.id,
})));

const genFormVisible = ref(false);
const genForm = ref<ReportRequest>({
  title: '漏洞扫描报告',
  task_ids: [],
  format: 'json',
  severity: [],
});

function openGenForm() {
  genForm.value = { title: '漏洞扫描报告', task_ids: [], format: 'json', severity: [] };
  genFormVisible.value = true;
}

async function handleGenerate() {
  if (!genForm.value.task_ids.length) { message.warning('请选择至少一个任务'); return; }

  loading.value = true;
  genFormVisible.value = false;
  try {
    if (genForm.value.format === 'json') {
      const res = await generateReport(genForm.value) as unknown as ReportData;
      reportData.value = res;
      renderCharts(res);
      message.success('报告生成完成');
    } else {
      const url = getTaskReportURL(genForm.value.task_ids[0]!, genForm.value.format);
      window.open(url, '_blank');
      message.success('报告已下载');
    }
  } catch (e: any) {
    message.error('生成失败: ' + (e?.message || '未知错误'));
  } finally {
    loading.value = false;
  }
}

async function quickReport(taskId: string) {
  loading.value = true;
  try {
    const res = await getTaskReportJSON(taskId);
    reportData.value = res;
    renderCharts(res);
    message.success('快速报告已生成');
  } catch (e: any) {
    message.error('生成失败: ' + (e?.message || ''));
  } finally {
    loading.value = false;
  }
}

function renderCharts(data: ReportData) {
  const s = data.summary;
  renderSevPie({
    tooltip: { trigger: 'item' },
    legend: { bottom: 0, textStyle: { fontSize: 11 } },
    series: [{
      type: 'pie', radius: ['35%', '60%'], center: ['50%', '44%'],
      label: { show: true, formatter: '{b}\n{c}', fontSize: 11 },
      data: [
        { name: '严重', value: s.critical_count, itemStyle: { color: sevColors.critical } },
        { name: '高危', value: s.high_count, itemStyle: { color: sevColors.high } },
        { name: '中危', value: s.medium_count, itemStyle: { color: sevColors.medium } },
        { name: '低危', value: s.low_count, itemStyle: { color: sevColors.low } },
        { name: '信息', value: s.info_count, itemStyle: { color: sevColors.info } },
      ].filter(d => d.value > 0),
    }],
  });

  const assetMap = new Map<string, number>();
  for (const v of data.vulnerabilities ?? []) {
    assetMap.set(v.asset, (assetMap.get(v.asset) ?? 0) + 1);
  }
  const topAssets = [...assetMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);

  if (topAssets.length) {
    renderAssetBar({
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      grid: { left: 120, right: 20, top: 12, bottom: 20 },
      xAxis: { type: 'value', minInterval: 1 },
      yAxis: {
        type: 'category', data: topAssets.map(a => a[0]).reverse(),
        axisLabel: { fontSize: 10, width: 100, overflow: 'truncate' },
      },
      series: [{
        type: 'bar',
        data: topAssets.map(a => a[1]).reverse(),
        itemStyle: { borderRadius: [0, 4, 4, 0], color: '#dd6b20' },
      }],
    });
  }
}

function riskColor(s: number) {
  if (s >= 80) return 'error';
  if (s >= 50) return 'warning';
  return 'success';
}

const vulnColumns = computed<DataTableColumns<VulnItem>>(() => [
  {
    title: '漏洞标题', key: 'title', width: 250,
    ellipsis: { tooltip: true },
  },
  {
    title: '严重级别', key: 'severity', width: 100,
    render: (row) => h(NTag, { size: 'small', style: { background: (sevColors[row.severity] ?? '#999') + '22', color: sevColors[row.severity] ?? '#999', border: 'none' } }, () => sevLabels[row.severity] || row.severity),
  },
  { title: 'CVE', key: 'cve_id', width: 140 },
  { title: '资产', key: 'asset', width: 200, ellipsis: { tooltip: true } },
  {
    title: '状态', key: 'status', width: 80,
    render: (row) => h(NTag, { size: 'small', type: row.status === 'fixed' ? 'success' : 'default' }, () => row.status === 'fixed' ? '已修复' : row.status === 'ignored' ? '已忽略' : '待修复'),
  },
]);

function exportReport(format: string) {
  if (!genForm.value.task_ids.length && tasks.value.length) {
    genForm.value.task_ids = [tasks.value[0].id];
  }
  if (!genForm.value.task_ids.length) {
    message.warning('无可导出的任务');
    return;
  }
  const url = getTaskReportURL(genForm.value.task_ids[0]!, format);
  window.open(url, '_blank');
}
</script>

<template>
  <div class="p-4">
    <!-- Header -->
    <NCard size="small">
      <NSpace justify="space-between" align="center">
        <h3 style="margin:0;font-size:16px;font-weight:600">报告中心</h3>
        <NSpace :size="8">
          <NButton size="small" type="primary" @click="openGenForm">生成报告</NButton>
          <NSelect
            v-if="reportData" size="small" placeholder="导出报告" style="width:140px"
            :options="[
              { label: 'Markdown', value: 'markdown' },
              { label: 'CSV', value: 'csv' },
              { label: 'SARIF', value: 'sarif' },
            ]"
            @update:value="(v: string) => exportReport(v)"
          />
        </NSpace>
      </NSpace>
    </NCard>

    <!-- Quick Task Report -->
    <NCard title="快速生成任务报告" size="small" style="margin-top:16px" v-if="!reportData">
      <div v-if="tasks.length">
        <NDataTable
          :columns="[
            { title: '任务名称', key: 'name', ellipsis: { tooltip: true } },
            { title: '状态', key: 'status', width: 100 },
            { title: '目标数', key: 'total_targets', width: 80 },
            { title: '创建时间', key: 'created_at', width: 170 },
            { title: '操作', key: 'act', width: 120, render: (row: any) => h(NButton, { size: 'tiny', type: 'primary', onClick: () => quickReport(row.id) }, () => '生成报告') },
          ]" :data="tasks.slice(0, 10)" :bordered="false" size="small" :pagination="false"
        />
      </div>
      <NEmpty v-else description="暂无任务" />
    </NCard>

    <!-- Report Content -->
    <NSpin :show="loading">
      <div v-if="reportData" style="margin-top:16px">
        <!-- Summary KPIs -->
        <NCard :title="reportData.title" size="small">
          <template #header-extra>
            <span style="font-size:12px;color:var(--text-color-3)">生成时间: {{ new Date(reportData.generated_at).toLocaleString('zh-CN') }}</span>
          </template>
          <NGrid :cols="5" :x-gap="16">
            <NGridItem>
              <NStatistic label="漏洞总数" :value="reportData.summary.total_vulns" />
            </NGridItem>
            <NGridItem>
              <NStatistic label="严重" :value="reportData.summary.critical_count">
                <template #suffix><span style="color:#e53e3e">个</span></template>
              </NStatistic>
            </NGridItem>
            <NGridItem>
              <NStatistic label="高危" :value="reportData.summary.high_count">
                <template #suffix><span style="color:#dd6b20">个</span></template>
              </NStatistic>
            </NGridItem>
            <NGridItem>
              <NStatistic label="中危" :value="reportData.summary.medium_count">
                <template #suffix><span style="color:#d69e2e">个</span></template>
              </NStatistic>
            </NGridItem>
            <NGridItem>
              <div style="text-align:center">
                <div style="font-size:12px;color:var(--text-color-3);margin-bottom:4px">风险评分</div>
                <NProgress
                  type="circle" :percentage="Math.min(100, Math.round(reportData.summary.risk_score))"
                  :status="riskColor(reportData.summary.risk_score) as any"
                  :stroke-width="8" style="width:56px"
                />
              </div>
            </NGridItem>
          </NGrid>
        </NCard>

        <!-- Charts -->
        <NGrid :cols="2" :x-gap="16" style="margin-top:16px">
          <NGridItem>
            <NCard title="漏洞严重级别分布" size="small">
              <EchartsUI ref="sevPieRef" height="260px" />
            </NCard>
          </NGridItem>
          <NGridItem>
            <NCard title="受影响资产 TOP 10" size="small">
              <EchartsUI ref="assetBarRef" height="260px" />
            </NCard>
          </NGridItem>
        </NGrid>

        <!-- Vuln Table -->
        <NCard title="漏洞详情" size="small" style="margin-top:16px">
          <NDataTable
            :columns="vulnColumns" :data="reportData.vulnerabilities ?? []"
            :bordered="false" size="small" max-height="500"
            :pagination="{ pageSize: 20 }"
          />
        </NCard>
      </div>
    </NSpin>

    <!-- Generate Modal -->
    <NModal v-model:show="genFormVisible" preset="card" title="生成报告" style="width:560px">
      <NForm :model="genForm" label-placement="left" label-width="80">
        <NFormItem label="报告标题">
          <NInput v-model:value="genForm.title" />
        </NFormItem>
        <NFormItem label="关联任务">
          <NSelect v-model:value="genForm.task_ids" :options="taskOptions" multiple placeholder="选择任务" />
        </NFormItem>
        <NFormItem label="输出格式">
          <NSelect v-model:value="genForm.format" :options="[
            { label: 'JSON (在线预览)', value: 'json' },
            { label: 'Markdown (下载)', value: 'markdown' },
            { label: 'CSV (下载)', value: 'csv' },
            { label: 'SARIF (下载)', value: 'sarif' },
          ]" />
        </NFormItem>
        <NFormItem label="严重级别">
          <NCheckboxGroup v-model:value="genForm.severity">
            <NSpace>
              <NCheckbox value="critical">严重</NCheckbox>
              <NCheckbox value="high">高危</NCheckbox>
              <NCheckbox value="medium">中危</NCheckbox>
              <NCheckbox value="low">低危</NCheckbox>
              <NCheckbox value="info">信息</NCheckbox>
            </NSpace>
          </NCheckboxGroup>
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="genFormVisible = false">取消</NButton>
          <NButton type="primary" @click="handleGenerate">生成</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>
