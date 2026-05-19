<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';
import { computed, h, reactive, ref, watch } from 'vue';
import { useRoute } from 'vue-router';

import type { MonitorExecution, MonitorPathTask } from '#/api/sitemonitor';

import { Page } from '@vben/common-ui';
import { IconifyIcon } from '@vben/icons';

import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NDataTable,
  NDatePicker,
  NEmpty,
  NFormItem,
  NModal,
  NPopconfirm,
  NSelect,
  NSpace,
  NStatistic,
  NTabPane,
  NTabs,
  NTag,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  batchDeleteExecutions,
  deleteExecution,
  getExecutionList,
  getPathTaskDetail,
} from '#/api/sitemonitor';

import DimensionTrendPanel from './DimensionTrendPanel.vue';
import RecordDetailContent from './RecordDetailContent.vue';

defineOptions({ name: 'MonitorRecords' });

const route = useRoute();

const detailVisible = ref(false);
const detailRecordId = ref('');

const pathTaskId = computed(() =>
  String(route.params.pathTaskId ?? route.params.taskId ?? '').trim(),
);
const pathTask = ref<MonitorPathTask | null>(null);

const dimensions = [
  { key: 'all', label: '全部', icon: 'ri:layout-grid-line', color: '#6b7280' },
  { key: 'availability', label: '可用性', icon: 'ri:pulse-line', color: '#3b82f6' },
  { key: 'tamper', label: '篡改监测', icon: 'ri:shield-flash-line', color: '#ef4444' },
  { key: 'blacklink', label: '暗链监测', icon: 'ri:bug-line', color: '#f59e0b' },
  { key: 'sensitive_word', label: '敏感词', icon: 'ri:file-text-line', color: '#8b5cf6' },
  { key: 'sensitive_file', label: '敏感文件', icon: 'ri:folder-shield-2-line', color: '#14b8a6' },
  { key: 'domain_hijack', label: '域名劫持', icon: 'ri:globe-line', color: '#10b981' },
];

const activeDim = ref('all');

const dimLabelMap: Record<string, string> = Object.fromEntries(
  dimensions.map((d) => [d.key, d.label]),
);

const statusLabel = (v: string) =>
  ({
    failed: '失败',
    pending: '等待中',
    running: '运行中',
    success: '成功',
  })[v] ?? v;

const fmtTime = (v: string) => (v ? dayjs(v).format('YYYY-MM-DD HH:mm:ss') : '-');

type DimFilter = {
  hasIssue: string;
  disposition: string;
  status: string;
  dateRange: null | [number, number];
};

function createDimFilter(): DimFilter {
  return { hasIssue: '', disposition: '', status: '', dateRange: null };
}

const dimFilters = reactive<Record<string, DimFilter>>({});

function ensureDimFilter(key: string) {
  if (!dimFilters[key]) dimFilters[key] = createDimFilter();
  return dimFilters[key];
}

for (const d of dimensions) {
  ensureDimFilter(d.key);
}

const issueOpts = [
  { label: '有问题', value: 'true' },
  { label: '正常', value: 'false' },
];

const statusOpts = [
  { label: '成功', value: 'success' },
  { label: '失败', value: 'failed' },
  { label: '运行中', value: 'running' },
  { label: '等待中', value: 'pending' },
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

const dimDataMap = reactive<Record<string, MonitorExecution[]>>({});
const dimLoadingMap = reactive<Record<string, boolean>>({});
const dimStatsMap = reactive<
  Record<string, { total: number; success: number; failed: number; issueCount: number }>
>({});

const pagination = reactive({
  page: 1,
  pageSize: 15,
  showSizePicker: true,
  pageSizes: [10, 15, 20, 50],
});

const pageCountMap = reactive<Record<string, number>>({});

function applyRouteFilters() {
  const q = route.query;
  const dim = String(q.dimension ?? '').trim();
  if (dim && dimensions.some((d) => d.key === dim)) {
    activeDim.value = dim;
  }
  const f = ensureDimFilter(activeDim.value);
  f.hasIssue = String(q.hasIssue ?? '').trim();
  f.disposition = String(q.disposition ?? '').trim();
}

async function loadTaskInfo() {
  if (!pathTaskId.value) return;
  try {
    const res = await getPathTaskDetail(pathTaskId.value);
    pathTask.value = (res as any)?.data || res;
  } catch (e: any) {
    message.error(e?.msg || '加载路径任务失败');
  }
}


async function loadData(dimKey: string) {
  if (!pathTaskId.value) return;

  const targetDim = dimKey === 'all' ? '' : dimKey;
  dimLoadingMap[dimKey] = true;

  try {
    const params: any = {
      index: pagination.page,
      size: pagination.pageSize,
      path_task_id: pathTaskId.value,
    };

    if (targetDim) params.dimension = targetDim;
    const ff = ensureDimFilter(dimKey);
    if (ff.hasIssue) params.has_issue = ff.hasIssue;
    if (ff.disposition) params.disposition = ff.disposition;
    if (ff.status) params.status = ff.status;
    if (ff.dateRange?.[0])
      params.time_start = dayjs(ff.dateRange[0]).format('YYYY-MM-DD HH:mm:ss');
    if (ff.dateRange?.[1])
      params.time_end = dayjs(ff.dateRange[1]).format('YYYY-MM-DD HH:mm:ss');

    const res = await getExecutionList(params);
    const items = res.data || [];
    const count = (res as any).count || 0;
    dimDataMap[dimKey] = items;
    pageCountMap[dimKey] = count;

    dimStatsMap[dimKey] = {
      total: count,
      success: items.filter((r) => r.status === 'success').length,
      failed: items.filter((r) => r.status === 'failed').length,
      issueCount: items.filter((r) => r.has_issue).length,
    };
  } catch (e: any) {
    dimDataMap[dimKey] = [];
    dimStatsMap[dimKey] = { total: 0, success: 0, failed: 0, issueCount: 0 };
    message.error(e?.msg || '加载数据失败');
  } finally {
    dimLoadingMap[dimKey] = false;
  }
}

async function loadAllDimStats() {
  if (!pathTaskId.value) return;
  const dimKeys = dimensions.map((d) => d.key);
  await Promise.all(
    dimKeys.map(async (dimKey) => {
      const targetDim = dimKey === 'all' ? '' : dimKey;
      try {
        const params: any = {
          index: 1,
          size: 1,
          path_task_id: pathTaskId.value,
        };
        if (targetDim) params.dimension = targetDim;
        const res = await getExecutionList(params);
        const count = (res as any).count || 0;
        if (!dimStatsMap[dimKey] || dimKey !== activeDim.value) {
          dimStatsMap[dimKey] = {
            total: count,
            success: 0,
            failed: 0,
            issueCount: 0,
          };
        }
        pageCountMap[dimKey] = pageCountMap[dimKey] || count;
      } catch {
        // ignore
      }
    }),
  );
}

function handleFilterChange(dimKey?: string) {
  pagination.page = 1;
  const dim = dimKey || activeDim.value;
  loadData(dim);
  loadAllDimStats();
}

function resetDimFilter(dimKey: string) {
  const f = ensureDimFilter(dimKey);
  f.hasIssue = '';
  f.disposition = '';
  f.status = '';
  f.dateRange = null;
  handleFilterChange(dimKey);
}

function handlePageChange(p: number) {
  pagination.page = p;
  loadData(activeDim.value);
}

function handlePageSizeChange(s: number) {
  pagination.pageSize = s;
  pagination.page = 1;
  loadData(activeDim.value);
}

function handleTabChange(dim: string) {
  pagination.page = 1;
  loadData(dim);
}

function openDetail(row: MonitorExecution) {
  detailRecordId.value = row.id;
  detailVisible.value = true;
}

function closeDetail() {
  detailVisible.value = false;
}

async function handleDelete(row: MonitorExecution) {
  try {
    await deleteExecution(row.id);
    message.success('删除成功');
    loadData(activeDim.value);
    loadAllDimStats();
  } catch (e: any) {
    message.error(e?.msg || '删除失败');
  }
}

function handleBatchDelete() {
  const data = dimDataMap[activeDim.value] || [];
  if (data.length === 0) {
    message.warning('当前列表无记录');
    return;
  }

  dialog.error({
    title: '危险操作',
    content: `确认删除当前页面 ${data.length} 条记录？同时清除相关证据文件，不可恢复！`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const ids = data.map((r) => r.id);
        await batchDeleteExecutions(ids);
        message.success(`已删除 ${ids.length} 条记录`);
        loadData(activeDim.value);
        loadAllDimStats();
      } catch (e: any) {
        message.error(e?.msg || '批量删除失败');
      }
    },
  });
}

const baseColumns: DataTableColumns<MonitorExecution> = [
  { key: 'index', title: '序号', width: 60, align: 'center', render: (_, i) => i + 1 },
  {
    key: 'dimension',
    title: '维度',
    width: 100,
    align: 'center',
    render: (row) => {
      const dim = dimensions.find((d) => d.key === row.dimension);
      return h(
        'span',
        { style: { color: dim?.color || '#6b7280', fontWeight: 500 } },
        dimLabelMap[row.dimension] || row.dimension || '-',
      );
    },
  },
  {
    key: 'status',
    title: '状态',
    width: 80,
    align: 'center',
    render: (row) => {
      const type =
        row.status === 'success'
          ? 'success'
          : row.status === 'failed'
            ? 'error'
            : row.status === 'running'
              ? 'warning'
              : 'info';
      return h(NTag, { type, size: 'small', bordered: false }, () => statusLabel(row.status));
    },
  },
  {
    key: 'has_issue',
    title: '安全问题',
    width: 90,
    align: 'center',
    render: (row) =>
      h(
        NTag,
        {
          type: row.has_issue ? 'error' : 'success',
          size: 'small',
          bordered: false,
        },
        () => (row.has_issue ? '⚠ 问题' : '正常'),
      ),
  },
  {
    key: 'disposition',
    title: '处置',
    width: 80,
    align: 'center',
    render: (row) => {
      const d = row.disposition || 'pending';
      const typeMap: Record<string, 'default' | 'warning' | 'success'> = {
        false_positive: 'default',
        invalid: 'default',
        pending: 'warning',
        valid: 'success',
      };
      return h(
        NTag,
        { type: typeMap[d] || 'default', size: 'small', bordered: false },
        () => dispositionLabelMap[d] || d,
      );
    },
  },
  { key: 'url', title: 'URL', minWidth: 200, ellipsis: { tooltip: true }, align: 'center' },
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
    width: 120,
    fixed: 'right',
    align: 'center',
    render: (row) =>
      h(NSpace, { size: 8, justify: 'center' }, () => [
        h(
          NButton,
          {
            text: true,
            size: 'small',
            type: 'primary',
            onClick: () => openDetail(row),
          },
          { default: () => '详情' },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDelete(row) },
          {
            trigger: () =>
              h(
                NButton,
                {
                  text: true,
                  size: 'small',
                  type: 'error',
                },
                { default: () => '删除' },
              ),
            default: () => '确认删除该条记录及相关证据文件？',
          },
        ),
      ]),
  },
];

const tableColumns = computed(() => {
  if (activeDim.value === 'all') {
    return baseColumns;
  }
  return baseColumns.filter((c) => c.key !== 'dimension');
});

function dimStats(key: string) {
  return dimStatsMap[key] ?? { total: 0, success: 0, failed: 0, issueCount: 0 };
}

watch(
  () => route.params.pathTaskId ?? route.params.taskId,
  () => {
    if (!pathTaskId.value) return;
    applyRouteFilters();
    pagination.page = 1;
    loadTaskInfo();
    loadData(activeDim.value);
    loadAllDimStats();
  },
  { immediate: true },
);
</script>

<template>
  <Page
    :title="`监测记录${pathTask?.name ? ` — ${pathTask.name}` : ''}`"
    description="按监测维度查看路径任务执行记录"
  >
    <template #extra>
      <NButton size="small" @click="() => { loadData(activeDim); loadAllDimStats(); }">
        <IconifyIcon icon="ri:refresh-line" class="text-sm" />
        刷新
      </NButton>
    </template>

    <NCard class="records-main-card" content-style="padding: 0">
      <NTabs
        v-model:value="activeDim"
        type="line"
        animated
        display-directive="if"
        class="records-dimension-tabs"
        @update:value="handleTabChange"
      >
      <NTabPane v-for="item in dimensions" :key="item.key" :name="item.key">
        <template #tab>
          <div
            class="record-tab-label"
            :class="{ 'record-tab-label--active': activeDim === item.key }"
            :style="{ '--dim-color': item.color }"
          >
            <IconifyIcon :icon="item.icon" class="record-tab-icon" />
            <span>{{ item.label }}</span>
            <NTag
              size="tiny"
              round
              :bordered="false"
              :type="dimStatsMap[item.key]?.issueCount ? 'error' : 'default'"
              class="record-tab-count"
            >
              {{ dimStatsMap[item.key]?.total ?? 0 }}
            </NTag>
          </div>
        </template>

        <div class="dimension-record-panel">
          <div class="dimension-card-header" :style="{ '--dim-color': item.color }">
              <div class="dimension-card-title">
                <span class="dimension-card-icon">
                  <IconifyIcon :icon="item.icon" />
                </span>
                <div>
                  <div class="dimension-card-name">{{ item.label }}</div>
                  <div class="dimension-card-desc">
                    {{ item.key === 'all' ? '汇总各维度执行记录' : `${item.label}监测执行记录` }}
                  </div>
                </div>
              </div>
              <NSpace :size="16" class="dimension-card-stats">
                <NStatistic label="记录数" tabular-nums>
                  <span class="stat-num">{{ dimStats(item.key).total }}</span>
                </NStatistic>
                <NStatistic label="成功" tabular-nums>
                  <span class="stat-num stat-success">{{ dimStats(item.key).success }}</span>
                </NStatistic>
                <NStatistic label="失败" tabular-nums>
                  <span class="stat-num stat-failed">{{ dimStats(item.key).failed }}</span>
                </NStatistic>
                <NStatistic label="安全问题" tabular-nums>
                  <span
                    class="stat-num"
                    :class="dimStats(item.key).issueCount > 0 ? 'stat-issue' : 'stat-ok'"
                  >
                    {{ dimStats(item.key).issueCount }}
                  </span>
                </NStatistic>
              </NSpace>
          </div>

          <div class="records-filter-bar mb-4">
            <NSpace align="center" wrap>
              <NFormItem label="执行" label-width="40">
                <NSelect v-model:value="dimFilters[item.key]!.status" placeholder="全部" clearable size="small" style="width: 110px" :options="statusOpts" />
              </NFormItem>
              <NFormItem label="安全" label-width="40">
                <NSelect v-model:value="dimFilters[item.key]!.hasIssue" placeholder="全部" clearable size="small" style="width: 110px" :options="issueOpts" />
              </NFormItem>
              <NFormItem label="处置" label-width="40">
                <NSelect v-model:value="dimFilters[item.key]!.disposition" placeholder="全部" clearable size="small" style="width: 110px" :options="dispositionOptions" />
              </NFormItem>
              <NFormItem label="时间" label-width="40">
                <NDatePicker v-model:value="dimFilters[item.key]!.dateRange" type="datetimerange" clearable size="small" style="width: 340px" />
              </NFormItem>
              <NSpace :size="8">
                <NButton type="primary" size="small" @click="handleFilterChange(item.key)">查询</NButton>
                <NButton size="small" @click="resetDimFilter(item.key)">重置</NButton>
              </NSpace>
            </NSpace>
          </div>
          <DimensionTrendPanel v-if="pathTaskId" :path-task-id="pathTaskId" :dimension="item.key" :dim-label="item.label" :dim-color="item.color" :filters="dimFilters[item.key]!" />
          <div class="table-toolbar mb-3">
            <span class="text-muted-foreground text-sm">
              共 {{ pageCountMap[item.key] ?? 0 }} 条记录
            </span>
            <NButton
              v-if="activeDim === item.key && (dimDataMap[item.key]?.length ?? 0) > 0"
              type="error"
              size="small"
              @click="handleBatchDelete"
            >
              批量删除当前页
            </NButton>
          </div>

          <NDataTable
            :columns="tableColumns"
            :data="dimDataMap[item.key] || []"
            :loading="dimLoadingMap[item.key]"
            :pagination="{
              ...pagination,
              itemCount: pageCountMap[item.key] || 0,
            }"
            :row-key="(r: MonitorExecution) => r.id"
            remote
            size="small"
            @update:page="handlePageChange"
            @update:page-size="handlePageSizeChange"
          >
            <template #empty>
              <NEmpty :description="`暂无${item.label}监测记录`" />
            </template>
          </NDataTable>
        </div>
      </NTabPane>
      </NTabs>
    </NCard>

    <NModal
      v-model:show="detailVisible"
      preset="card"
      title="监测记录详情"
      :bordered="false"
      :segmented="{ content: true }"
      class="record-detail-modal"
      style="width: 92vw; max-width: 1100px"
      @after-leave="detailRecordId = ''"
    >
      <div class="record-detail-modal-body">
        <RecordDetailContent
          v-if="detailRecordId"
          :record-id="detailRecordId"
          @close="closeDetail"
        />
      </div>
    </NModal>
  </Page>
</template>

<style scoped>
.records-main-card {
  border-radius: 10px;
  overflow: hidden;
}

.records-filter-bar {
  padding: 12px 14px;
  background: var(--n-color-embedded);
  border-radius: 8px;
}

.records-dimension-tabs :deep(.n-tabs-nav) {
  padding: 0 16px;
  margin-bottom: 0;
}

.records-dimension-tabs :deep(.n-tabs-tab-pad) {
  border-bottom: 1px solid var(--n-border-color);
}

.records-dimension-tabs :deep(.n-tab-pane) {
  padding: 0;
}

.dimension-record-panel {
  padding: 16px 20px 20px;
}

.record-tab-label {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 4px;
  color: var(--n-text-color-2);
  transition: color 0.2s;
}

.record-tab-label--active {
  color: var(--dim-color);
  font-weight: 600;
}

.record-tab-icon {
  font-size: 15px;
}

.record-tab-count {
  min-width: 22px;
  justify-content: center;
}

.dimension-card-header {
  display: flex;
  margin-bottom: 16px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--n-border-color);
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  width: 100%;
}

.dimension-card-title {
  display: flex;
  align-items: center;
  gap: 12px;
}

.dimension-card-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  border-radius: 10px;
  font-size: 20px;
  color: var(--dim-color);
  background: color-mix(in srgb, var(--dim-color) 12%, transparent);
}

.dimension-card-name {
  font-size: 15px;
  font-weight: 600;
  color: var(--n-text-color);
}

.dimension-card-desc {
  margin-top: 2px;
  font-size: 12px;
  color: var(--n-text-color-3);
}

.dimension-card-stats {
  flex-wrap: wrap;
}

.dimension-card-stats :deep(.n-statistic-label) {
  font-size: 12px;
}

.stat-num {
  font-size: 18px;
  font-weight: 600;
}

.stat-success {
  color: #22c55e;
}

.stat-failed {
  color: #ef4444;
}

.stat-issue {
  color: #ef4444;
}

.stat-ok {
  color: #22c55e;
}

.records-filter-bar {
  padding: 12px 14px;
  background: var(--n-color-embedded);
  border-radius: 8px;
}

.records-filter-bar :deep(.n-form-item) {
  margin-bottom: 0;
}

.availability-panel {
  padding: 14px;
  background: var(--n-color-embedded);
  border-radius: 8px;
}

.table-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.record-detail-modal-body {
  max-height: min(78vh, 820px);
  overflow-y: auto;
  padding-right: 4px;
}
</style>

