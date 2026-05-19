<script lang="ts" setup>
import { computed, h, onMounted, ref } from 'vue';

import type { DataTableColumns } from 'naive-ui';
import {
  NButton,
  NCard,
  NDatePicker,
  NDataTable,
  NEmpty,
  NForm,
  NFormItem,
  NGrid,
  NGridItem,
  NSelect,
  NSpace,
  NSpin,
  NStatistic,
  NTag,
  useMessage,
} from 'naive-ui';

import {
  generateMonitorReport,
  getPathTaskList,
  type MonitorReportComplianceItem,
  type MonitorReportData,
  type MonitorPathTask,
} from '#/api/sitemonitor';

defineOptions({ name: 'MonitorReportCenter' });

type ReportFormState = {
  end_date: string;
  start_date: string;
  task_ids: string[];
};

type DimensionRow = {
  dimension: string;
  issueCount: number;
  issueRate: number;
  total: number;
};

const message = useMessage();
const loading = ref(false);
const tasks = ref<MonitorPathTask[]>([]);
const report = ref<MonitorReportData | null>(null);

function formatDate(date: Date) {
  const year = date.getFullYear();
  const month = `${date.getMonth() + 1}`.padStart(2, '0');
  const day = `${date.getDate()}`.padStart(2, '0');
  return `${year}-${month}-${day}`;
}

const today = new Date();
const sevenDaysAgo = new Date();
sevenDaysAgo.setDate(today.getDate() - 6);

const form = ref<ReportFormState>({
  start_date: formatDate(sevenDaysAgo),
  end_date: formatDate(today),
  task_ids: [],
});

const summary = computed(() => report.value?.Summary ?? {});
const slaStats = computed(() => report.value?.SLAStats ?? {});
const compliance = computed(() => report.value?.Compliance ?? {});
const taskReports = computed(() => report.value?.TaskReports ?? []);
const taskOptions = computed(() =>
  tasks.value.map((task) => ({
    label: task.name || task.url_override || task.path || task.id,
    value: task.id,
  })),
);

const dimensionRows = computed<DimensionRow[]>(() =>
  Object.entries(summary.value.DimStats ?? {}).map(([dimension, stat]) => ({
    dimension,
    issueCount: Number(stat?.Issues ?? 0),
    issueRate: Number(stat?.IssueRate ?? 0),
    total: Number(stat?.Total ?? 0),
  })),
);

const dimensionColumns: DataTableColumns<DimensionRow> = [
  { title: '监测维度', key: 'dimension', width: 140 },
  { title: '执行次数', key: 'total', width: 100, align: 'center' },
  { title: '发现问题', key: 'issueCount', width: 100, align: 'center' },
  {
    title: '问题率',
    key: 'issueRate',
    width: 100,
    align: 'center',
    render: (row) => `${row.issueRate.toFixed(1)}%`,
  },
];

const taskReportColumns: DataTableColumns<any> = [
  { title: '任务名称', key: 'TaskName', minWidth: 180, ellipsis: { tooltip: true } },
  { title: '目标地址', key: 'URL', minWidth: 220, ellipsis: { tooltip: true } },
  { title: '执行次数', key: 'Executions', width: 100, align: 'center' },
  { title: '问题次数', key: 'Issues', width: 100, align: 'center' },
  {
    title: '问题率',
    key: 'IssueRate',
    width: 100,
    align: 'center',
    render: (row) => `${Number(row.IssueRate ?? 0).toFixed(1)}%`,
  },
];

const complianceColumns: DataTableColumns<MonitorReportComplianceItem> = [
  { title: '类别', key: 'Category', width: 120 },
  { title: '检查项', key: 'Name', minWidth: 180, ellipsis: { tooltip: true } },
  {
    title: '状态',
    key: 'Status',
    width: 100,
    align: 'center',
    render: (row) => {
      const status = row.Status || 'unknown';
      const type =
        status === 'pass'
          ? 'success'
          : status === 'warn'
            ? 'warning'
            : status === 'fail'
              ? 'error'
              : 'default';
      const label =
        status === 'pass'
          ? '通过'
          : status === 'warn'
            ? '预警'
            : status === 'fail'
              ? '未通过'
              : status;
      return h(NTag, { size: 'small', type }, () => label);
    },
  },
  { title: '说明', key: 'Description', minWidth: 220, ellipsis: { tooltip: true } },
  { title: '建议', key: 'Suggestion', minWidth: 220, ellipsis: { tooltip: true } },
];

async function fetchTasks() {
  const result = await getPathTaskList({ index: 1, size: 200 });
  tasks.value = result.data ?? [];
}

async function handleGenerate() {
  loading.value = true;
  try {
    const result = await generateMonitorReport({
      start_date: form.value.start_date,
      end_date: form.value.end_date,
      task_ids: form.value.task_ids,
      format: 'json',
    });
    report.value = result;
    message.success('风险监测报告已生成');
  } catch (error: any) {
    message.error(`生成失败: ${error?.message || '未知错误'}`);
  } finally {
    loading.value = false;
  }
}

onMounted(async () => {
  try {
    await fetchTasks();
  } catch {
    tasks.value = [];
  }
});
</script>

<template>
  <div class="p-4">
    <NCard size="small">
      <NForm inline :model="form">
        <NSpace align="end" wrap justify="space-between" style="width: 100%">
          <NSpace wrap>
            <NFormItem label="开始日期">
              <NDatePicker
                v-model:formatted-value="form.start_date"
                type="date"
                value-format="yyyy-MM-dd"
                clearable
              />
            </NFormItem>
            <NFormItem label="结束日期">
              <NDatePicker
                v-model:formatted-value="form.end_date"
                type="date"
                value-format="yyyy-MM-dd"
                clearable
              />
            </NFormItem>
            <NFormItem label="监测任务">
              <NSelect
                v-model:value="form.task_ids"
                :options="taskOptions"
                multiple
                filterable
                clearable
                placeholder="为空则统计全部任务"
                style="width: 360px"
              />
            </NFormItem>
          </NSpace>
          <NButton type="primary" :loading="loading" @click="handleGenerate">
            生成风险监测报告
          </NButton>
        </NSpace>
      </NForm>
    </NCard>

    <NSpin :show="loading">
      <div v-if="report" style="margin-top: 16px">
        <NCard :title="report.Title || '风险监测报告'" size="small">
          <template #header-extra>
            <span style="font-size: 12px; color: var(--text-color-3)">
              统计周期: {{ report.Period || `${form.start_date} 至 ${form.end_date}` }}
            </span>
          </template>
          <NGrid :cols="5" :x-gap="16">
            <NGridItem>
              <NStatistic label="监测任务" :value="summary.TotalTasks ?? 0" />
            </NGridItem>
            <NGridItem>
              <NStatistic label="启用任务" :value="summary.EnabledTasks ?? 0" />
            </NGridItem>
            <NGridItem>
              <NStatistic label="执行总数" :value="summary.TotalExecutions ?? 0" />
            </NGridItem>
            <NGridItem>
              <NStatistic label="问题次数" :value="summary.IssueCount ?? 0" />
            </NGridItem>
            <NGridItem>
              <NStatistic label="问题率" :value="`${Number(summary.IssueRate ?? 0).toFixed(1)}%`" />
            </NGridItem>
          </NGrid>
        </NCard>

        <NGrid :cols="2" :x-gap="16" style="margin-top: 16px">
          <NGridItem>
            <NCard title="SLA 概览" size="small">
              <NGrid :cols="2" :x-gap="12" :y-gap="12">
                <NGridItem>
                  <NStatistic
                    label="可用率"
                    :value="`${Number(slaStats.AvailabilityRate ?? 0).toFixed(2)}%`"
                  />
                </NGridItem>
                <NGridItem>
                  <NStatistic
                    label="平均响应"
                    :value="`${Number(slaStats.AvgResponseMS ?? 0).toFixed(0)} ms`"
                  />
                </NGridItem>
                <NGridItem>
                  <NStatistic
                    label="P95 响应"
                    :value="`${Number(slaStats.P95ResponseMS ?? 0).toFixed(0)} ms`"
                  />
                </NGridItem>
                <NGridItem>
                  <NStatistic
                    label="中断时长"
                    :value="`${Number(slaStats.DowntimeMinutes ?? 0).toFixed(0)} 分钟`"
                  />
                </NGridItem>
              </NGrid>
              <div style="margin-top: 12px">
                <NTag :type="slaStats.MeetsSLA ? 'success' : 'warning'" size="small">
                  {{ slaStats.MeetsSLA ? '达到 SLA' : '未达到 SLA' }}
                </NTag>
                <span style="margin-left: 8px; color: var(--text-color-3); font-size: 12px">
                  目标值 {{ Number(slaStats.SLATarget ?? 99.9).toFixed(1) }}%
                </span>
              </div>
            </NCard>
          </NGridItem>
          <NGridItem>
            <NCard title="合规评估" size="small">
              <NGrid :cols="4" :x-gap="12">
                <NGridItem>
                  <NStatistic label="综合得分" :value="Number(compliance.Score ?? 0).toFixed(1)" />
                </NGridItem>
                <NGridItem>
                  <NStatistic label="通过项" :value="compliance.PassCount ?? 0" />
                </NGridItem>
                <NGridItem>
                  <NStatistic label="预警项" :value="compliance.WarnCount ?? 0" />
                </NGridItem>
                <NGridItem>
                  <NStatistic label="失败项" :value="compliance.FailCount ?? 0" />
                </NGridItem>
              </NGrid>
              <div style="margin-top: 12px">
                <NTag
                  :type="
                    compliance.Level === 'pass'
                      ? 'success'
                      : compliance.Level === 'warn'
                        ? 'warning'
                        : 'error'
                  "
                  size="small"
                >
                  {{
                    compliance.Level === 'pass'
                      ? '总体通过'
                      : compliance.Level === 'warn'
                        ? '存在预警'
                        : '存在不符合项'
                  }}
                </NTag>
              </div>
            </NCard>
          </NGridItem>
        </NGrid>

        <NCard title="维度统计" size="small" style="margin-top: 16px">
          <NDataTable :columns="dimensionColumns" :data="dimensionRows" :bordered="false" />
        </NCard>

        <NCard title="任务统计" size="small" style="margin-top: 16px">
          <NDataTable
            :columns="taskReportColumns"
            :data="taskReports"
            :bordered="false"
            max-height="420"
          />
        </NCard>

        <NCard title="合规明细" size="small" style="margin-top: 16px">
          <NDataTable
            :columns="complianceColumns"
            :data="compliance.Items ?? []"
            :bordered="false"
            max-height="420"
          />
        </NCard>
      </div>
      <NCard v-else size="small" style="margin-top: 16px">
        <NEmpty description="请选择时间范围并生成报告" />
      </NCard>
    </NSpin>
  </div>
</template>
