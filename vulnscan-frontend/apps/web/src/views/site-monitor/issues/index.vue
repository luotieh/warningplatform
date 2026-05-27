<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';
import type { MonitorExecution } from '#/api/sitemonitor';

import { computed, h, onMounted, reactive, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';

import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NDataTable,
  NDatePicker,
  NInput,
  NSelect,
  NSpace,
  NTag,
} from 'naive-ui';

import { useMessage } from 'naive-ui';

import {
  getExecutionList,
  updateDisposition,
} from '#/api/sitemonitor';
import { createIncident, type CreateIncidentReq } from '#/api/incident';
import { useMonitorRecordDetail } from '../composables/useMonitorRecordDetail';
import { buildMonitorIncidentDescription } from '../monitor-incident-description';

defineOptions({ name: 'MonitorIssues' });

const route = useRoute();
const router = useRouter();
const msg = useMessage();
const { openRecordDetail } = useMonitorRecordDetail();

const loading = ref(false);
const dataList = ref<MonitorExecution[]>([]);

const form = reactive({
  dimension: '',
  disposition: 'pending',
  has_issue: 'true',
  status: '',
  path_task_id: '',
  dateRange: null as null | [number, number],
});

const pagination = reactive({
  page: 1,
  pageSize: 20,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [15, 30, 50, 100],
});

const dimensionOptions = [
  { label: '全部维度', value: '' },
  { label: '可用性', value: 'availability' },
  { label: '篡改监测', value: 'tamper' },
  { label: '暗链监测', value: 'blacklink' },
  { label: '敏感词监测', value: 'sensitive_word' },
  { label: '敏感文件监测', value: 'sensitive_file' },
  { label: '域名劫持', value: 'domain_hijack' },
];

const dispositionOptions = [
  { label: '未处置', value: 'pending' },
  { label: '有效', value: 'valid' },
  { label: '无效', value: 'invalid' },
  { label: '误报', value: 'false_positive' },
  { label: '全部', value: '' },
];

const issueOptions = [
  { label: '有问题', value: 'true' },
  { label: '全部记录', value: '' },
];

const dispositionLabelMap: Record<string, string> = {
  false_positive: '误报',
  invalid: '无效',
  pending: '未处置',
  valid: '有效',
};

const dimensionLabel = (val: string) =>
  dimensionOptions.find((o) => o.value === val)?.label || val || '-';

function applyRouteQuery() {
  const q = route.query;
  if (q.dimension) form.dimension = String(q.dimension);
  if (q.disposition !== undefined) form.disposition = String(q.disposition);
  if (q.hasIssue !== undefined) form.has_issue = String(q.hasIssue);
  if (q.path_task_id) form.path_task_id = String(q.path_task_id);
}

async function onSearch() {
  loading.value = true;
  try {
    const params: Record<string, unknown> = {
      index: pagination.page,
      size: pagination.pageSize,
      dimension: form.dimension || undefined,
      disposition: form.disposition || undefined,
      has_issue: form.has_issue || undefined,
      status: form.status || undefined,
      path_task_id: form.path_task_id || undefined,
    };
    if (form.dateRange) {
      params.time_start = dayjs(form.dateRange[0]).toISOString();
      params.time_end = dayjs(form.dateRange[1]).toISOString();
    }
    const res = await getExecutionList(params as any);
    dataList.value = res.data || [];
    pagination.itemCount = (res as any).count || 0;
  } catch {
    dataList.value = [];
    pagination.itemCount = 0;
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  form.dimension = '';
  form.disposition = 'pending';
  form.has_issue = 'true';
  form.status = '';
  form.path_task_id = '';
  form.dateRange = null;
  pagination.page = 1;
  onSearch();
}

const goDetail = (row: MonitorExecution) =>
  openRecordDetail(row.id, { taskId: row.path_task_id });

async function setDisposition(row: MonitorExecution, disposition: string) {
  try {
    await updateDisposition(row.id, disposition);
    msg.success('处置状态已更新');
    onSearch();
  } catch (e: any) {
    msg.error(e?.message || '更新失败');
  }
}

const dimToIncidentType: Record<string, string> = {
  tamper: 'web_attack',
  blacklink: 'web_attack',
  sensitive_word: 'data_leak',
  sensitive_file: 'data_leak',
  domain_hijack: 'intrusion',
  availability: 'dos',
};
const dimToLevel: Record<string, number> = {
  tamper: 4,
  blacklink: 3,
  sensitive_word: 3,
  sensitive_file: 3,
  domain_hijack: 4,
  availability: 3,
};

function parseResultJson(row: MonitorExecution): any {
  if (!row.result_json) return null;
  try {
    return JSON.parse(row.result_json);
  } catch {
    return null;
  }
}

async function convertToIncident(row: MonitorExecution) {
  const req: CreateIncidentReq = {
    name: `[${dimensionLabel(row.dimension)}] ${row.url}`,
    level: dimToLevel[row.dimension] ?? 3,
    source: 1,
    report_time: row.created_at || undefined,
    asset: { domain_ip: row.url, asset_name: row.url },
    metadata: {
      incident_type: dimToIncidentType[row.dimension] ?? 'other',
      incident_description: buildMonitorIncidentDescription(
        {
          dimension: row.dimension,
          url: row.url,
          id: row.id,
          path_task_id: row.path_task_id,
          target_id: row.target_id,
          agent_id: row.agent_id,
          started_at: row.started_at || row.created_at,
        },
        parseResultJson(row),
        (t) => (t ? dayjs(t).format('YYYY-MM-DD HH:mm:ss') : '-'),
      ),
      incident_url: row.url,
      discovery_time: row.created_at || undefined,
    },
  };
  try {
    await createIncident(req);
    msg.success('已转为安全事件');
  } catch (e: any) {
    msg.error(e?.message || '转为事件失败');
  }
}

const columns = computed<DataTableColumns<MonitorExecution>>(() => [
  { key: 'url', title: 'URL', minWidth: 200, ellipsis: { tooltip: true } },
  {
    key: 'dimension',
    title: '维度',
    width: 110,
    render: (row) =>
      h(NTag, { size: 'small', bordered: false }, () => dimensionLabel(row.dimension)),
  },
  {
    key: 'occurrence_count',
    title: '次数',
    width: 70,
    render: (row) => {
      const count = row.occurrence_count ?? 1;
      if (count <= 1) return h('span', {}, '1');
      return h(NTag, { type: 'error', size: 'small', round: true, bordered: false }, () => `${count}`);
    },
  },
  {
    key: 'has_issue',
    title: '安全问题',
    width: 90,
    render: (row) =>
      h(
        NTag,
        { type: row.has_issue ? 'error' : 'success', size: 'small', bordered: false },
        () => (row.has_issue ? '有问题' : '正常'),
      ),
  },
  {
    key: 'disposition',
    title: '处置',
    width: 90,
    render: (row) => {
      const d = row.disposition || 'pending';
      return h(
        NTag,
        { type: d === 'pending' ? 'warning' : 'default', size: 'small', bordered: false },
        () => dispositionLabelMap[d] || d,
      );
    },
  },
  {
    key: 'first_seen_at',
    title: '首次发现',
    width: 150,
    render: (row) =>
      row.first_seen_at ? dayjs(row.first_seen_at).format('YYYY-MM-DD HH:mm') : '-',
  },
  {
    key: 'created_at',
    title: '最近发现',
    width: 150,
    render: (row) =>
      row.created_at ? dayjs(row.created_at).format('YYYY-MM-DD HH:mm') : '-',
  },
  {
    key: 'op',
    title: '操作',
    width: 280,
    fixed: 'right',
    render: (row) =>
      h(NSpace, { size: 4, wrap: false }, () => [
        h(NButton, { text: true, type: 'primary', size: 'small', onClick: () => goDetail(row) }, () => '详情'),
        h(NButton, { text: true, type: 'success', size: 'small', onClick: () => setDisposition(row, 'valid') }, () => '有效'),
        h(NButton, { text: true, size: 'small', onClick: () => setDisposition(row, 'false_positive') }, () => '误报'),
        h(NButton, { text: true, type: 'warning', size: 'small', onClick: () => convertToIncident(row) }, () => '转事件'),
      ]),
  },
]);

watch(
  () => route.query,
  () => {
    applyRouteQuery();
    onSearch();
  },
);

onMounted(() => {
  applyRouteQuery();
  onSearch();
});
</script>

<template>
  <Page
    title="问题处置"
    description="集中查看各监测维度待处置与有问题的执行记录，无需逐任务下钻"
  >
    <NCard size="small" class="mb-3">
      <NSpace align="center" wrap>
        <NSelect
          v-model:value="form.has_issue"
          :options="issueOptions"
          style="width: 120px"
        />
        <NSelect
          v-model:value="form.disposition"
          :options="dispositionOptions"
          style="width: 120px"
        />
        <NSelect
          v-model:value="form.dimension"
          placeholder="维度"
          clearable
          :options="dimensionOptions"
          style="width: 140px"
        />
        <NInput
          v-model:value="form.path_task_id"
          placeholder="路径任务 ID"
          clearable
          style="width: 180px"
        />
        <NDatePicker
          v-model:value="form.dateRange"
          type="datetimerange"
          clearable
          style="width: 320px"
        />
        <NButton type="primary" :loading="loading" @click="onSearch">查询</NButton>
        <NButton @click="resetForm">重置</NButton>
        <NButton @click="router.push('/monitor/targets')">网站监测</NButton>
      </NSpace>
    </NCard>

    <NCard title="监测问题列表">
      <template #header-extra>
        <NTag type="error" size="small" :bordered="false">
          共 {{ pagination.itemCount }} 条
        </NTag>
      </template>
      <NDataTable
        :columns="columns"
        :data="dataList"
        :loading="loading"
        :pagination="pagination"
        :row-key="(r: MonitorExecution) => r.id"
        remote
        size="small"
        @update:page="
          (p: number) => {
            pagination.page = p;
            onSearch();
          }
        "
        @update:page-size="
          (s: number) => {
            pagination.pageSize = s;
            pagination.page = 1;
            onSearch();
          }
        "
      />
    </NCard>
  </Page>
</template>
