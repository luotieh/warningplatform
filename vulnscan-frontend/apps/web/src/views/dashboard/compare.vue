<script lang="ts" setup>
import { ref, computed, h, onMounted } from 'vue';
import {
  NCard, NSelect, NButton, NSpace, NGrid, NGridItem, NStatistic,
  NDataTable, NTag, NTabs, NTabPane, useMessage, NSpin, NEmpty,
  NAlert,
} from 'naive-ui';
import type { DataTableColumns } from 'naive-ui';
import { EchartsUI, useEcharts } from '@vben/plugins/echarts';
import type { EchartsUIType } from '@vben/plugins/echarts';
import { compareTasks, type CompareResult, type VulnDiff } from '#/api/report';
import { getRecentTasks } from '#/api/dashboard';

defineOptions({ name: 'DashboardCompare' });

const message = useMessage();
const loading = ref(false);
const baseTaskId = ref('');
const compareTaskId = ref('');
const result = ref<CompareResult | null>(null);
const tasks = ref<any[]>([]);

const diffPieRef = ref<EchartsUIType>();
const { renderEcharts: renderDiffPie } = useEcharts(diffPieRef);

const sevColors: Record<string, string> = {
  critical: '#e53e3e', high: '#dd6b20', medium: '#d69e2e', low: '#38a169', info: '#4299e1',
};
const sevLabels: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
};

onMounted(async () => {
  try {
    const res = await getRecentTasks({ page: 1, page_size: 100 });
    tasks.value = res.items;
  } catch {}
});

const taskOptions = computed(() => tasks.value.map((t: any) => ({
  label: `${t.name} (${t.status} | ${new Date(t.created_at).toLocaleDateString('zh-CN')})`,
  value: t.id,
})));

async function handleCompare() {
  if (!baseTaskId.value || !compareTaskId.value) {
    message.warning('请选择两个任务');
    return;
  }
  if (baseTaskId.value === compareTaskId.value) {
    message.warning('不能对比相同任务');
    return;
  }

  loading.value = true;
  try {
    const res = await compareTasks(baseTaskId.value, compareTaskId.value);
    result.value = res as unknown as CompareResult;
    renderCharts(result.value);
    message.success('对比完成');
  } catch (e: any) {
    message.error('对比失败: ' + (e?.message || ''));
  } finally {
    loading.value = false;
  }
}

function renderCharts(data: CompareResult) {
  renderDiffPie({
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [{
      type: 'pie', radius: ['35%', '60%'], center: ['50%', '42%'],
      label: { show: true, formatter: '{b}\n{c}', fontSize: 11 },
      data: [
        { name: '新增漏洞', value: data.summary.new_count, itemStyle: { color: '#e53e3e' } },
        { name: '已修复', value: data.summary.fixed_count, itemStyle: { color: '#38a169' } },
        { name: '等级变化', value: data.summary.changed_count, itemStyle: { color: '#d69e2e' } },
        { name: '未变化', value: data.unchanged_count, itemStyle: { color: '#a0aec0' } },
      ].filter(d => d.value > 0),
    }],
  });
}

const diffColumns: DataTableColumns<VulnDiff> = [
  { title: '漏洞标题', key: 'title', width: 250, ellipsis: { tooltip: true } },
  {
    title: '严重级别', key: 'severity', width: 100,
    render: (row) => h(NTag, { size: 'small', style: { background: (sevColors[row.severity] ?? '#999') + '22', color: sevColors[row.severity] ?? '#999', border: 'none' } }, () => sevLabels[row.severity] || row.severity),
  },
  { title: '目标', key: 'target', width: 200, ellipsis: { tooltip: true } },
  {
    title: '变化类型', key: 'diff_type', width: 100,
    render: (row) => {
      const m: Record<string, { type: any; label: string }> = {
        new: { type: 'error', label: '新增' },
        fixed: { type: 'success', label: '已修复' },
        changed: { type: 'warning', label: '等级变化' },
      };
      const cfg = m[row.diff_type] ?? { type: 'default', label: row.diff_type };
      return h(NTag, { size: 'small', type: cfg.type }, () => cfg.label);
    },
  },
  {
    title: '原等级', key: 'old_severity', width: 100,
    render: (row) => row.old_severity
      ? h(NTag, { size: 'tiny', style: { background: (sevColors[row.old_severity] ?? '#999') + '22', color: sevColors[row.old_severity] ?? '#999', border: 'none' } }, () => sevLabels[row.old_severity] || row.old_severity)
      : '-',
  },
];

const allDiffs = computed<VulnDiff[]>(() => {
  if (!result.value) return [];
  return [
    ...(result.value.new_vulns ?? []),
    ...(result.value.fixed_vulns ?? []),
    ...(result.value.changed_vulns ?? []),
  ];
});
</script>

<template>
  <div class="p-4">
    <NCard title="扫描结果对比" size="small">
      <template #header-extra>
        <NSpace :size="8" align="center">
          <span style="font-size:12px;color:var(--text-color-3)">基准任务:</span>
          <NSelect v-model:value="baseTaskId" :options="taskOptions" size="small" style="width:280px" placeholder="选择基准任务" filterable />
          <span style="font-size:12px;color:var(--text-color-3)">对比任务:</span>
          <NSelect v-model:value="compareTaskId" :options="taskOptions" size="small" style="width:280px" placeholder="选择对比任务" filterable />
          <NButton size="small" type="primary" :loading="loading" @click="handleCompare">对比</NButton>
        </NSpace>
      </template>

      <NSpin :show="loading">
        <div v-if="result">
          <!-- Summary -->
          <NGrid :cols="6" :x-gap="12" style="margin-bottom:16px">
            <NGridItem>
              <NCard size="small" :bordered="false" style="background:var(--card-color)">
                <NStatistic label="基准漏洞数" :value="result.summary.base_total" />
              </NCard>
            </NGridItem>
            <NGridItem>
              <NCard size="small" :bordered="false" style="background:var(--card-color)">
                <NStatistic label="对比漏洞数" :value="result.summary.compare_total" />
              </NCard>
            </NGridItem>
            <NGridItem>
              <NCard size="small" :bordered="false" style="background:#e53e3e11">
                <NStatistic label="新增" :value="result.summary.new_count">
                  <template #suffix><span style="color:#e53e3e">个</span></template>
                </NStatistic>
              </NCard>
            </NGridItem>
            <NGridItem>
              <NCard size="small" :bordered="false" style="background:#38a16911">
                <NStatistic label="已修复" :value="result.summary.fixed_count">
                  <template #suffix><span style="color:#38a169">个</span></template>
                </NStatistic>
              </NCard>
            </NGridItem>
            <NGridItem>
              <NCard size="small" :bordered="false" style="background:#d69e2e11">
                <NStatistic label="等级变化" :value="result.summary.changed_count">
                  <template #suffix><span style="color:#d69e2e">个</span></template>
                </NStatistic>
              </NCard>
            </NGridItem>
            <NGridItem>
              <NCard size="small" :bordered="false" style="background:var(--card-color)">
                <NStatistic label="增减" :value="result.summary.delta">
                  <template #prefix><span v-if="result.summary.delta > 0" style="color:#e53e3e">+</span></template>
                </NStatistic>
              </NCard>
            </NGridItem>
          </NGrid>

          <NAlert v-if="result.summary.new_count > 0" type="error" :bordered="false" style="margin-bottom:12px">
            发现 {{ result.summary.new_count }} 个新增漏洞，请及时处理
          </NAlert>
          <NAlert v-if="result.summary.fixed_count > 0" type="success" :bordered="false" style="margin-bottom:12px">
            已修复 {{ result.summary.fixed_count }} 个漏洞
          </NAlert>

          <!-- Chart + Table -->
          <NGrid :cols="3" :x-gap="16">
            <NGridItem>
              <NCard title="差异分布" size="small">
                <EchartsUI ref="diffPieRef" height="260px" />
              </NCard>
            </NGridItem>
            <NGridItem :span="2">
              <NCard title="差异详情" size="small">
                <NTabs type="line" size="small">
                  <NTabPane name="all" :tab="`全部 (${allDiffs.length})`">
                    <NDataTable :columns="diffColumns" :data="allDiffs" size="small" :pagination="{ pageSize: 20 }" max-height="300" />
                  </NTabPane>
                  <NTabPane name="new" :tab="`新增 (${result.new_vulns?.length ?? 0})`">
                    <NDataTable :columns="diffColumns" :data="result.new_vulns ?? []" size="small" :pagination="{ pageSize: 20 }" max-height="300" />
                  </NTabPane>
                  <NTabPane name="fixed" :tab="`已修复 (${result.fixed_vulns?.length ?? 0})`">
                    <NDataTable :columns="diffColumns" :data="result.fixed_vulns ?? []" size="small" :pagination="{ pageSize: 20 }" max-height="300" />
                  </NTabPane>
                  <NTabPane name="changed" :tab="`等级变化 (${result.changed_vulns?.length ?? 0})`">
                    <NDataTable :columns="diffColumns" :data="result.changed_vulns ?? []" size="small" :pagination="{ pageSize: 20 }" max-height="300" />
                  </NTabPane>
                </NTabs>
              </NCard>
            </NGridItem>
          </NGrid>
        </div>
        <NEmpty v-else description="选择两个扫描任务进行结果对比" style="padding:80px 0" />
      </NSpin>
    </NCard>
  </div>
</template>
