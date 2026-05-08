<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import type { MonitorExecution } from '#/api/monitor';

import { computed, h, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';

import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NDataTable,
  NInput,
  NSelect,
  NSpace,
  NTag,
} from 'naive-ui';

import { useMessage } from 'naive-ui';

import { getExecutionList } from '#/api/monitor';
import { createIncident, type CreateIncidentReq } from '#/api/incident';

defineOptions({ name: 'MonitorExecutions' });

const router = useRouter();
const msg = useMessage();
const loading = ref(false);
const dataList = ref<MonitorExecution[]>([]);
const safeDataList = computed(() =>
  Array.isArray(dataList.value) ? dataList.value : [],
);

const form = reactive({ task_id: '', dimension: '', status: '' });

const pagination = reactive({
  page: 1,
  pageSize: 15,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [15, 30, 50, 100],
});

const dimensionOptions = [
  { label: '可用性', value: 'availability' },
  { label: '篡改监测', value: 'tamper' },
  { label: '暗链监测', value: 'blacklink' },
  { label: '敏感词监测', value: 'sensitive_word' },
  { label: '敏感文件监测', value: 'sensitive_file' },
  { label: '域名劫持', value: 'domain_hijack' },
];

const statusOptions = [
  { label: '等待中', value: 'pending' },
  { label: '运行中', value: 'running' },
  { label: '成功', value: 'success' },
  { label: '失败', value: 'failed' },
];

const dimensionLabel = (val: string) =>
  dimensionOptions.find((o) => o.value === val)?.label || val;

const statusTagType = (
  s: string,
): 'default' | 'error' | 'info' | 'success' | 'warning' => {
  if (s === 'success') return 'success';
  if (s === 'failed') return 'error';
  if (s === 'running') return 'warning';
  return 'info';
};

const statusLabel = (s: string) =>
  statusOptions.find((o) => o.value === s)?.label || s;

async function onSearch() {
  loading.value = true;
  try {
    const res = await getExecutionList({
      dimension: form.dimension,
      index: pagination.page,
      size: pagination.pageSize,
      status: form.status,
      task_id: form.task_id,
    });
    dataList.value = res.data || [];
    pagination.itemCount = (res as any).count || 0;
  } catch {
    dataList.value = [];
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  form.task_id = '';
  form.dimension = '';
  form.status = '';
  pagination.page = 1;
  onSearch();
}

const goDetail = (row: MonitorExecution) =>
  router.push(`/monitor/tasks/executions/detail/${row.id}`);

const dimToIncidentType: Record<string, string> = {
  tamper: 'web_attack', blacklink: 'web_attack',
  sensitive_word: 'data_leak', sensitive_file: 'data_leak',
  domain_hijack: 'intrusion', availability: 'dos',
};
const dimToLevel: Record<string, number> = {
  tamper: 4, blacklink: 3, sensitive_word: 3,
  sensitive_file: 3, domain_hijack: 4, availability: 3,
};

function buildDescFromRow(row: MonitorExecution): string {
  const parts: string[] = [];
  parts.push(`监测维度: ${dimensionLabel(row.dimension)}`);
  parts.push(`目标URL: ${row.url}`);
  if (row.created_at) parts.push(`检测时间: ${row.created_at}`);

  if (row.result_json) {
    try {
      const result = JSON.parse(row.result_json);
      if (row.dimension === 'tamper' && result.diffs?.length) {
        parts.push(`篡改变更: ${result.diffs.length}处`);
      } else if (row.dimension === 'blacklink') {
        const cnt = (result.blacklink_matches?.length || 0) + (result.backdoor_findings?.length || 0);
        if (cnt) parts.push(`暗链/后门: ${cnt}个`);
      } else if (row.dimension === 'sensitive_word' && result.matches?.length) {
        parts.push(`敏感词命中: ${result.matches.length}处`);
      } else if (row.dimension === 'sensitive_file') {
        const files = result.files || result.matches || [];
        if (files.length) parts.push(`敏感文件: ${files.length}个`);
      } else if (row.dimension === 'domain_hijack' && result.hijacked) {
        parts.push('检测到域名劫持');
      } else if (row.dimension === 'availability' && result.available === false) {
        parts.push(`站点不可用${result.status_code ? ' (HTTP ' + result.status_code + ')' : ''}`);
      }
    } catch { /* ignore */ }
  }
  return parts.join('\n');
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
      incident_description: buildDescFromRow(row),
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
  { key: 'id', title: '执行ID', width: 200, ellipsis: { tooltip: true } },
  { key: 'task_id', title: '任务ID', width: 200, ellipsis: { tooltip: true } },
  { key: 'url', title: 'URL', minWidth: 180, ellipsis: { tooltip: true } },
  {
    key: 'dimension',
    title: '维度',
    width: 120,
    render: (row) =>
      h(
        NTag,
        { size: 'small', bordered: false },
        { default: () => dimensionLabel(row.dimension) },
      ),
  },
  {
    key: 'status',
    title: '状态',
    width: 100,
    render: (row) =>
      h(
        NTag,
        { type: statusTagType(row.status), size: 'small', bordered: false },
        { default: () => statusLabel(row.status) },
      ),
  },
  {
    key: 'has_issue',
    title: '安全问题',
    width: 100,
    render: (row) =>
      h(
        NTag,
        {
          type: row.has_issue ? 'error' : 'success',
          size: 'small',
          bordered: false,
        },
        { default: () => (row.has_issue ? '发现' : '无') },
      ),
  },
  { key: 'agent_id', title: 'Agent', width: 140, ellipsis: { tooltip: true } },
  {
    key: 'created_at',
    title: '创建时间',
    width: 160,
    render: (row) =>
      row.created_at
        ? dayjs(row.created_at).format('YYYY-MM-DD HH:mm:ss')
        : '-',
  },
  {
    key: 'op',
    title: '操作',
    width: 140,
    fixed: 'right',
    render: (row) =>
      h(NSpace, { size: 4 }, () => {
        const btns = [
          h(NButton, { text: true, type: 'primary', size: 'small', onClick: () => goDetail(row) }, () => '详情'),
        ];
        if (row.has_issue) {
          btns.push(h(NButton, { text: true, type: 'warning', size: 'small', onClick: () => convertToIncident(row) }, () => '转事件'));
        }
        return btns;
      }),
  },
]);

onMounted(() => onSearch());
</script>

<template>
  <Page title="执行记录" description="所有维度的监测执行结果">
    <NCard size="small" class="mb-3">
      <NSpace align="center">
        <span>任务ID</span>
        <NInput
          v-model:value="form.task_id"
          placeholder="请输入任务ID"
          clearable
          style="width: 200px"
        />
        <span>维度</span>
        <NSelect
          v-model:value="form.dimension"
          placeholder="请选择"
          clearable
          :options="dimensionOptions"
          style="width: 160px"
        />
        <span>状态</span>
        <NSelect
          v-model:value="form.status"
          placeholder="请选择"
          clearable
          :options="statusOptions"
          style="width: 120px"
        />
        <NButton type="primary" :loading="loading" @click="onSearch">
          搜索
        </NButton>
        <NButton @click="resetForm">重置</NButton>
      </NSpace>
    </NCard>

    <NCard title="执行结果">
      <template #header-extra>
        <NButton size="small" @click="onSearch">刷新</NButton>
      </template>
      <NDataTable
        :columns="columns"
        :data="safeDataList"
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
