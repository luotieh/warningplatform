<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import type { MonitorExecution, MonitorTask } from '#/api/sitemonitor';

import { computed, h, onMounted, reactive, ref } from 'vue';

import { Page } from '@vben/common-ui';

import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NCollapse,
  NCollapseItem,
  NDataTable,
  NDatePicker,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NRadio,
  NRadioGroup,
  NSelect,
  NSpace,
  NSpin,
  NTag,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  batchDeleteExecutions,
  deleteExecution,
  getExecutionDetail,
  getExecutionList,
  getTaskExecutionStats,
  getTaskList,
  runTask,
  updateDisposition,
} from '#/api/sitemonitor';

import AvailabilityDetail from '../executions/components/AvailabilityDetail.vue';
import BlacklinkDetail from '../executions/components/BlacklinkDetail.vue';
import DomainHijackDetail from '../executions/components/DomainHijackDetail.vue';
import SensitiveFileDetail from '../executions/components/SensitiveFileDetail.vue';
import SensitiveWordDetail from '../executions/components/SensitiveWordDetail.vue';
import TamperDetail from '../executions/components/TamperDetail.vue';

defineOptions({ name: 'MonitorLedger' });

type TagType = 'default' | 'error' | 'info' | 'primary' | 'success' | 'warning';

const execStatusType = (s: string): TagType => {
  if (s === 'success') return 'success';
  if (s === 'failed') return 'error';
  if (s === 'running') return 'warning';
  return 'info';
};

const loading = ref(false);
const dataList = ref<MonitorTask[]>([]);
const safeDataList = computed(() =>
  Array.isArray(dataList.value) ? dataList.value : [],
);
const form = reactive({ enabled: '', name: '' });
const pagination = reactive({
  page: 1,
  pageCount: 1,
  pageSize: 15,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 15, 20, 50],
});

// 维度元数据
const dimensions = [
  { key: 'availability', label: '可用性' },
  { key: 'domain_hijack', label: '域名劫持' },
  { key: 'tamper', label: '篡改' },
  { key: 'sensitive_word', label: '敏感词' },
  { key: 'sensitive_file', label: '敏感文件' },
  { key: 'blacklink', label: '黑链/挂马' },
];
const dimLabelMap: Record<string, string> = {
  availability: '可用性',
  blacklink: '暗链监测',
  domain_hijack: '域名劫持',
  sensitive_file: '敏感文件',
  sensitive_word: '敏感词',
  tamper: '篡改监测',
};

const statsMap = ref<
  Record<
    string,
    Record<
      string,
      {
        total: number;
        issue_count: number;
        pending_count?: number;
        valid_count?: number;
      }
    >
  >
>({});

async function onSearch() {
  loading.value = true;
  try {
    const [taskRes, statsRes] = await Promise.all([
      getTaskList({
        enabled: form.enabled,
        index: pagination.page,
        name: form.name,
        size: pagination.pageSize,
      }),
      getTaskExecutionStats(),
    ]);
    dataList.value = taskRes.data || [];
    pagination.itemCount = (taskRes as any).count || 0;
    statsMap.value = (statsRes as any)?.data ?? statsRes ?? {};
  } finally {
    loading.value = false;
  }
}

async function handleRun(row: MonitorTask) {
  try {
    await runTask(row.id, []);
    message.success('已触发监测');
  } catch (e: any) {
    message.error(e?.msg || '监测失败');
  }
}

const execStatusLabel = (s: string) =>
  ({
    failed: '失败',
    pending: '等待中',
    running: '运行中',
    success: '成功',
  })[s as 'failed' | 'pending' | 'running' | 'success'] ?? s;

const fmtTime = (t: string) =>
  t ? dayjs(t).format('YYYY-MM-DD HH:mm:ss') : '-';

// ── 维度统计单元格渲染 ──
function dimStatRender(dimKey: string) {
  return (row: MonitorTask) => {
    const cfg = (row as any)[`config_${dimKey}`];
    if (!cfg?.enabled) return h('span', { style: { color: '#c0c4cc' } }, '-');
    const stat = statsMap.value[row.id]?.[dimKey];
    const total = stat?.total ?? 0;
    const pendingCount = stat?.pending_count ?? 0;
    const validCount = stat?.valid_count ?? 0;
    return h(
      'div',
      {
        style: {
          alignItems: 'center',
          display: 'flex',
          gap: '2px',
          justifyContent: 'center',
        },
      },
      [
        h(
          'span',
          {
            style: {
              color: pendingCount > 0 ? '#f56c6c' : '#909399',
              cursor: 'pointer',
              fontWeight: 500,
            },
            title: '点击查看未处置的问题记录',
            onClick: (e: Event) => {
              e.stopPropagation();
              openRecordsWithFilter(row, dimKey, 'true', 'pending');
            },
          },
          String(pendingCount),
        ),
        h('span', { style: { color: '#dcdfe6', margin: '0 1px' } }, '/'),
        h(
          'span',
          {
            style: {
              color: validCount > 0 ? '#e6a23c' : '#909399',
              cursor: 'pointer',
              fontWeight: 500,
            },
            title: '点击查看有效问题记录',
            onClick: (e: Event) => {
              e.stopPropagation();
              openRecordsWithFilter(row, dimKey, 'true', 'valid');
            },
          },
          String(validCount),
        ),
        h('span', { style: { color: '#dcdfe6', margin: '0 1px' } }, '/'),
        h(
          'span',
          {
            style: { color: '#409eff', cursor: 'pointer', fontWeight: 500 },
            title: '点击查看全部监测记录',
            onClick: (e: Event) => {
              e.stopPropagation();
              openRecordsWithFilter(row, dimKey, '', '');
            },
          },
          String(total),
        ),
      ],
    );
  };
}

// ── 主表格列 ──
const columns = computed<DataTableColumns<MonitorTask>>(() => [
  { key: 'index', title: '序号', width: 60, render: (_, i) => i + 1 },
  {
    key: 'target_homepage',
    title: '首页(URL)',
    minWidth: 200,
    ellipsis: { tooltip: true },
  },
  {
    key: 'task_name',
    title: '系统名称',
    minWidth: 130,
    ellipsis: { tooltip: true },
  },
  {
    key: 'target_ips',
    title: 'IP',
    minWidth: 130,
    ellipsis: { tooltip: true },
    render: (row) => row.target_ips || '-',
  },
  {
    title: '未处置 / 问题 / 总检测',
    align: 'center',
    key: 'stats',
    children: dimensions.map((dim) => ({
      key: `stat_${dim.key}`,
      title: dim.label,
      width: 120,
      align: 'center' as const,
      render: dimStatRender(dim.key),
    })),
  } as any,
  {
    key: 'enabled',
    title: '状态',
    width: 70,
    align: 'center',
    render: (row) =>
      h(
        'span',
        {
          style: {
            color: row.enabled ? '#67c23a' : '#909399',
            fontWeight: 500,
          },
        },
        row.enabled ? '启用' : '停止',
      ),
  },
  {
    key: 'op',
    title: '操作',
    width: 140,
    fixed: 'right',
    align: 'center',
    render: (row) =>
      h(NSpace, { size: 'small' }, () => [
        h(
          NPopconfirm,
          {
            onPositiveClick: () => handleRun(row),
          },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, type: 'primary', size: 'small' },
                { default: () => '监测' },
              ),
            default: () => '确认进行一次全维度监测？',
          },
        ),
        h(
          NButton,
          {
            text: true,
            type: 'info',
            size: 'small',
            onClick: () => openRecordsDrawer(row),
          },
          { default: () => '记录' },
        ),
      ]),
  },
]);

// ── 监测记录弹窗 ──
const recordsTask = ref<MonitorTask | null>(null);
const recordsVisible = ref(false);
const recordsLoading = ref(false);
const recordsList = ref<MonitorExecution[]>([]);
const safeRecordsList = computed(() =>
  Array.isArray(recordsList.value) ? recordsList.value : [],
);
const recordsPagination = reactive({
  page: 1,
  pageSize: 15,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 15, 20, 50],
});
const recordsFilter = reactive<{
  dimension: string;
  hasIssue: string;
  disposition: string;
  dateRange: [number, number] | null;
}>({ dateRange: null, dimension: '', disposition: '', hasIssue: '' });

const dimensionOpts = dimensions.map((d) => ({ label: d.label, value: d.key }));
const issueOpts = [
  { label: '有问题', value: 'true' },
  { label: '正常', value: 'false' },
];
const dispositionOptions = [
  { label: '未处置', value: 'pending' },
  { label: '有效', value: 'valid' },
  { label: '无效', value: 'invalid' },
  { label: '误报', value: 'false_positive' },
];
const dispositionLabelMap: Record<string, string> = {
  false_positive: '误报',
  invalid: '无效',
  pending: '未处置',
  valid: '有效',
};

function openRecordsWithFilter(
  row: MonitorTask,
  dimension: string,
  hasIssue: string,
  disposition = '',
) {
  recordsTask.value = row;
  recordsFilter.dimension = dimension;
  recordsFilter.hasIssue = hasIssue;
  recordsFilter.disposition = disposition;
  recordsFilter.dateRange = null;
  recordsPagination.page = 1;
  recordsVisible.value = true;
  loadRecords();
}

function openRecordsDrawer(row: MonitorTask) {
  openRecordsWithFilter(row, '', '');
}

async function loadRecords() {
  if (!recordsTask.value) return;
  recordsLoading.value = true;
  try {
    const params: any = {
      index: recordsPagination.page,
      size: recordsPagination.pageSize,
      task_id: recordsTask.value.id,
    };
    if (recordsFilter.dimension) params.dimension = recordsFilter.dimension;
    if (recordsFilter.hasIssue) params.has_issue = recordsFilter.hasIssue;
    if (recordsFilter.disposition)
      params.disposition = recordsFilter.disposition;
    if (recordsFilter.dateRange?.[0])
      params.time_start = dayjs(recordsFilter.dateRange[0]).format(
        'YYYY-MM-DD HH:mm:ss',
      );
    if (recordsFilter.dateRange?.[1])
      params.time_end = dayjs(recordsFilter.dateRange[1]).format(
        'YYYY-MM-DD HH:mm:ss',
      );
    const res = await getExecutionList(params);
    recordsList.value = res.data || [];
    recordsPagination.itemCount = (res as any).count || 0;
  } catch {
    recordsList.value = [];
  } finally {
    recordsLoading.value = false;
  }
}

const recordsColumns = computed<DataTableColumns<MonitorExecution>>(() => [
  { key: 'index', title: '序号', width: 60, align: 'center', render: (_, i) => i + 1 },
  {
    key: 'dimension',
    title: '维度',
    width: 100,
    align: 'center',
    render: (row) => dimLabelMap[row.dimension] || row.dimension || '-',
  },
  {
    key: 'status',
    title: '状态',
    width: 80,
    align: 'center',
    render: (row) => execStatusLabel(row.status),
  },
  {
    key: 'has_issue',
    title: '安全问题',
    width: 90,
    align: 'center',
    render: (row) =>
      h(
        'span',
        {
          style: {
            color: row.has_issue ? '#f56c6c' : '#67c23a',
            fontWeight: 500,
          },
        },
        row.has_issue ? '⚠ 问题' : '正常',
      ),
  },
  {
    key: 'disposition',
    title: '处置',
    width: 80,
    align: 'center',
    render: (row) => {
      const d = row.disposition || 'pending';
      const colorMap: Record<string, string> = {
        false_positive: '#909399',
        invalid: '#909399',
        pending: '#e6a23c',
        valid: '#67c23a',
      };
      return h(
        'span',
        { style: { color: colorMap[d] || '#909399', fontWeight: 500 } },
        dispositionLabelMap[d] || d,
      );
    },
  },
  { key: 'url', title: 'URL', minWidth: 180, ellipsis: { tooltip: true } },
  {
    key: 'created_at',
    title: '创建时间',
    width: 160,
    align: 'center',
    render: (row) => fmtTime(row.created_at),
  },
  {
    key: 'op',
    title: '操作',
    width: 200,
    fixed: 'right',
    align: 'center',
    render: (row) =>
      h(NSpace, { size: 'small' }, () => [
        row.has_issue
          ? h(
              NButton,
              {
                text: true,
                type: 'warning',
                size: 'small',
                onClick: () => openDispDialog(row),
              },
              { default: () => '处置' },
            )
          : null,
        h(
          NButton,
          {
            text: true,
            type: 'primary',
            size: 'small',
            onClick: () => openDetailDrawer(row),
          },
          { default: () => '详情' },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDeleteExecution(row) },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, type: 'error', size: 'small' },
                { default: () => '删除' },
              ),
            default: () => '确认删除该条记录及相关证据文件？',
          },
        ),
      ]),
  },
]);

async function handleDeleteExecution(row: MonitorExecution) {
  try {
    await deleteExecution(row.id);
    message.success('删除成功');
    loadRecords();
    onSearch();
  } catch (e: any) {
    message.error(e?.msg || '删除失败');
  }
}

function handleDeleteAllExecutions() {
  if (!recordsPagination.itemCount) {
    message.warning('当前列表无记录');
    return;
  }
  dialog.error({
    title: '危险操作',
    content: `确认删除任务「${recordsTask.value?.task_name}」当前筛选结果共 ${recordsPagination.itemCount} 条？同时清除相关证据文件，不可恢复！`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const params: any = {
          index: 1,
          size: 500,
          task_id: recordsTask.value!.id,
        };
        if (recordsFilter.dimension) params.dimension = recordsFilter.dimension;
        if (recordsFilter.hasIssue) params.has_issue = recordsFilter.hasIssue;
        if (recordsFilter.dateRange?.[0])
          params.time_start = dayjs(recordsFilter.dateRange[0]).format(
            'YYYY-MM-DD HH:mm:ss',
          );
        if (recordsFilter.dateRange?.[1])
          params.time_end = dayjs(recordsFilter.dateRange[1]).format(
            'YYYY-MM-DD HH:mm:ss',
          );
        const res = await getExecutionList(params);
        const ids = (res.data || []).map((r: MonitorExecution) => r.id);
        if (ids.length === 0) return;
        await batchDeleteExecutions(ids);
        message.success(`已删除 ${ids.length} 条记录`);
        loadRecords();
        onSearch();
      } catch (e: any) {
        message.error(e?.msg || '批量删除失败');
      }
    },
  });
}

// ── 处置弹窗 ──
const dispDialogVisible = ref(false);
const dispTarget = ref<MonitorExecution | null>(null);
const dispForm = reactive({ disposition: '', remark: '' });
const dispLoading = ref(false);

function openDispDialog(row: MonitorExecution) {
  dispTarget.value = row;
  dispForm.disposition = row.disposition || 'pending';
  dispForm.remark = row.disposition_remark || '';
  dispDialogVisible.value = true;
}

async function submitDisposition() {
  if (!dispTarget.value) return;
  if (!dispForm.disposition) {
    message.warning('请选择处置状态');
    return;
  }
  dispLoading.value = true;
  try {
    await updateDisposition(
      dispTarget.value.id,
      dispForm.disposition,
      dispForm.remark,
    );
    message.success('处置成功');
    dispDialogVisible.value = false;
    loadRecords();
    onSearch();
  } catch (e: any) {
    message.error(e?.msg || '处置失败');
  } finally {
    dispLoading.value = false;
  }
}

// ── 详情抽屉 ──
const detailVisible = ref(false);
const detailLoading = ref(false);
const detailData = ref<any>(null);
const detailExecId = ref('');

const detailParsedResult = computed(() => {
  if (!detailData.value?.result_json) return null;
  try {
    return JSON.parse(detailData.value.result_json);
  } catch {
    return null;
  }
});

async function openDetailDrawer(row: MonitorExecution) {
  detailData.value = null;
  detailExecId.value = row.id;
  detailVisible.value = true;
  detailLoading.value = true;
  try {
    const res: any = await getExecutionDetail(row.id);
    detailData.value = res?.data ?? res;
  } catch (e: any) {
    message.error(e?.msg || '加载详情失败');
  } finally {
    detailLoading.value = false;
  }
}

onMounted(() => onSearch());
</script>

<template>
  <Page title="监测台账" description="按系统/维度查看监测结果概况与处置记录">
    <!-- 搜索栏 -->
    <NCard size="small" class="mb-3">
      <NSpace align="center">
        <span>系统名称</span>
        <NInput
          v-model:value="form.name"
          placeholder="请输入系统名称"
          clearable
          style="width: 200px"
        />
        <span>状态</span>
        <NSelect
          v-model:value="form.enabled"
          placeholder="全部"
          clearable
          style="width: 120px"
          :options="[
            { label: '启用', value: 'true' },
            { label: '停止', value: 'false' },
          ]"
        />
        <NButton
          type="primary"
          @click="
            () => {
              pagination.page = 1;
              onSearch();
            }
          "
        >
          查询
        </NButton>
        <NButton
          @click="
            () => {
              form.name = '';
              form.enabled = '';
              pagination.page = 1;
              onSearch();
            }
          "
        >
          重置
        </NButton>
      </NSpace>
    </NCard>

    <!-- 主表格 -->
    <NCard>
      <template #header-extra>
        <NButton size="small" @click="onSearch">刷新</NButton>
      </template>
      <NDataTable
        :columns="columns"
        :data="safeDataList"
        :loading="loading"
        :pagination="pagination"
        :row-key="(r: MonitorTask) => r.id"
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

    <!-- 监测记录弹窗 -->
    <NModal
      v-model:show="recordsVisible"
      preset="card"
      :title="`监测记录 — ${recordsTask?.task_name || ''}`"
      style="width: 1200px"
      :bordered="false"
    >
      <NSpace align="center" class="mb-3" :wrap-item="false" wrap>
        <NSelect
          v-model:value="recordsFilter.dimension"
          placeholder="维度"
          clearable
          style="width: 130px"
          :options="dimensionOpts"
        />
        <NSelect
          v-model:value="recordsFilter.hasIssue"
          placeholder="安全问题"
          clearable
          style="width: 110px"
          :options="issueOpts"
        />
        <NSelect
          v-model:value="recordsFilter.disposition"
          placeholder="处置状态"
          clearable
          style="width: 110px"
          :options="dispositionOptions"
        />
        <NDatePicker
          v-model:value="recordsFilter.dateRange"
          type="datetimerange"
          clearable
          style="width: 360px"
        />
        <NButton
          type="primary"
          @click="
            () => {
              recordsPagination.page = 1;
              loadRecords();
            }
          "
        >
          查询
        </NButton>
        <NButton
          @click="
            () => {
              recordsFilter.dimension = '';
              recordsFilter.hasIssue = '';
              recordsFilter.disposition = '';
              recordsFilter.dateRange = null;
              recordsPagination.page = 1;
              loadRecords();
            }
          "
        >
          重置
        </NButton>
        <NButton type="error" @click="handleDeleteAllExecutions">
          全部删除
        </NButton>
        <NButton circle size="small" @click="loadRecords">↻</NButton>
      </NSpace>

      <NDataTable
        :columns="recordsColumns"
        :data="safeRecordsList"
        :loading="recordsLoading"
        :pagination="recordsPagination"
        :row-key="(r: MonitorExecution) => r.id"
        remote
        size="small"
        @update:page="
          (p: number) => {
            recordsPagination.page = p;
            loadRecords();
          }
        "
        @update:page-size="
          (s: number) => {
            recordsPagination.pageSize = s;
            recordsPagination.page = 1;
            loadRecords();
          }
        "
      />
    </NModal>

    <!-- 详情抽屉 -->
    <NDrawer v-model:show="detailVisible" :width="900" placement="right">
      <NDrawerContent
        :title="
          detailData
            ? `监测详情 — ${dimLabelMap[detailData.dimension] || detailData.dimension}`
            : '监测详情'
        "
        closable
      >
        <NSpin :show="detailLoading">
          <template v-if="detailData">
            <NCard size="small" class="mb-3">
              <NDescriptions :column="2" bordered size="small">
                <NDescriptionsItem label="监测ID" :span="2">
                  <span class="font-mono text-xs">{{ detailData.id }}</span>
                </NDescriptionsItem>
                <NDescriptionsItem label="状态">
                  <NTag
                    :type="execStatusType(detailData.status)"
                    size="small"
                    :bordered="false"
                  >
                    {{ execStatusLabel(detailData.status) }}
                  </NTag>
                </NDescriptionsItem>
                <NDescriptionsItem label="安全问题">
                  <NTag
                    :type="detailData.has_issue ? 'error' : 'success'"
                    size="small"
                    :bordered="false"
                  >
                    {{ detailData.has_issue ? '⚠ 发现问题' : '无' }}
                  </NTag>
                </NDescriptionsItem>
                <NDescriptionsItem label="目标URL" :span="2">
                  <span class="font-mono break-all text-xs">
                    {{ detailData.url }}
                  </span>
                </NDescriptionsItem>
                <NDescriptionsItem label="开始时间">
                  {{ fmtTime(detailData.started_at) }}
                </NDescriptionsItem>
                <NDescriptionsItem label="结束时间">
                  {{ fmtTime(detailData.finished_at) }}
                </NDescriptionsItem>
                <NDescriptionsItem label="创建时间">
                  {{ fmtTime(detailData.created_at) }}
                </NDescriptionsItem>
                <NDescriptionsItem
                  v-if="detailData.error"
                  label="错误信息"
                  :span="2"
                >
                  <span class="text-error font-mono text-sm">
                    {{ detailData.error }}
                  </span>
                </NDescriptionsItem>
              </NDescriptions>
            </NCard>

            <template v-if="detailParsedResult">
              <AvailabilityDetail
                v-if="detailData.dimension === 'availability'"
                :result="detailParsedResult"
                class="mb-3"
              />
              <TamperDetail
                v-else-if="detailData.dimension === 'tamper'"
                :result="detailParsedResult"
                :execution-id="detailExecId"
                class="mb-3"
              />
              <BlacklinkDetail
                v-else-if="detailData.dimension === 'blacklink'"
                :result="detailParsedResult"
                class="mb-3"
              />
              <SensitiveWordDetail
                v-else-if="detailData.dimension === 'sensitive_word'"
                :result="detailParsedResult"
                class="mb-3"
              />
              <SensitiveFileDetail
                v-else-if="detailData.dimension === 'sensitive_file'"
                :result="detailParsedResult"
                class="mb-3"
              />
              <DomainHijackDetail
                v-else-if="detailData.dimension === 'domain_hijack'"
                :result="detailParsedResult"
                class="mb-3"
              />
            </template>

            <NCard
              v-else-if="detailData.status === 'failed'"
              size="small"
              class="mb-3"
            >
              <NEmpty description="监测失败，无结果数据">
                <template #extra>
                  <div class="text-error mt-2 text-sm">
                    {{ detailData.error || '监测异常，未返回结果' }}
                  </div>
                </template>
              </NEmpty>
            </NCard>

            <NCard
              v-if="detailData.result_json"
              size="small"
              class="mb-3"
            >
              <NCollapse>
                <NCollapseItem
                  title="原始 result_json（调试用）"
                  name="raw"
                >
                  <NInput
                    type="textarea"
                    :value="JSON.stringify(detailParsedResult, null, 2)"
                    readonly
                    :rows="16"
                    class="font-mono"
                  />
                </NCollapseItem>
              </NCollapse>
            </NCard>
          </template>
          <NEmpty v-else-if="!detailLoading" description="暂无数据" />
        </NSpin>
      </NDrawerContent>
    </NDrawer>

    <!-- 处置弹窗 -->
    <NModal
      v-model:show="dispDialogVisible"
      preset="card"
      title="问题处置"
      style="width: 480px"
    >
      <NForm label-placement="left" label-width="80">
        <NFormItem label="处置状态">
          <NRadioGroup v-model:value="dispForm.disposition">
            <NRadio value="valid">有效</NRadio>
            <NRadio value="invalid">无效</NRadio>
            <NRadio value="false_positive">误报</NRadio>
          </NRadioGroup>
        </NFormItem>
        <NFormItem label="处置备注">
          <NInput
            v-model:value="dispForm.remark"
            type="textarea"
            :rows="3"
            placeholder="请输入处置备注（可选）"
          />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="dispDialogVisible = false">取消</NButton>
          <NButton
            type="primary"
            :loading="dispLoading"
            @click="submitDisposition"
          >
            确认处置
          </NButton>
        </NSpace>
      </template>
    </NModal>
  </Page>
</template>
