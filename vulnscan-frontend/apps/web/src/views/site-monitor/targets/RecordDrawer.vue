<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import type { MonitorExecution, MonitorPathTask } from '#/api/sitemonitor';

import { computed, h, reactive, ref, watch } from 'vue';

import { IconifyIcon } from '@vben/icons';

import dayjs from 'dayjs';
import {
  NButton,
  NDataTable,
  NDrawer,
  NDrawerContent,
  NEmpty,
  NModal,
  NSelect,
  NSpace,
  NTabPane,
  NTabs,
  NTag,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import {
  getExecutionList,
  getPathTaskDetail,
} from '#/api/sitemonitor';
import { useErrorHandler } from '#/composables/useErrorHandler';
import DimensionTrendPanel from '../records/DimensionTrendPanel.vue';
import RecordDetailContent from '../records/RecordDetailContent.vue';

const props = defineProps<{
  show: boolean;
  pathTaskId: string;
}>();
const emit = defineEmits<{
  (e: 'update:show', val: boolean): void;
}>();

const { handleError } = useErrorHandler();

const drawerShow = computed({
  get: () => props.show,
  set: (v) => emit('update:show', v),
});

const dimensions = [
  { key: 'all', label: '全部', icon: 'ri:apps-line', color: '#6366f1' },
  { key: 'availability', label: '可用性', icon: 'ri:pulse-line', color: '#3b82f6' },
  { key: 'tamper', label: '篡改监测', icon: 'ri:shield-flash-line', color: '#ef4444' },
  { key: 'blacklink', label: '暗链监测', icon: 'ri:bug-line', color: '#f59e0b' },
  { key: 'sensitive_word', label: '敏感词', icon: 'ri:file-text-line', color: '#8b5cf6' },
  { key: 'sensitive_file', label: '敏感文件', icon: 'ri:folder-shield-2-line', color: '#14b8a6' },
  { key: 'domain_hijack', label: '域名劫持', icon: 'ri:globe-line', color: '#10b981' },
];

const activeDim = ref('all');
const pathTask = ref<MonitorPathTask | null>(null);
const records = ref<MonitorExecution[]>([]);
const loading = ref(false);
const pagination = reactive({
  page: 1,
  pageSize: 15,
  itemCount: 0,
  pageSizes: [15, 30, 50],
  showSizePicker: true,
});

const statusOpts = [
  { label: '成功', value: 'success' },
  { label: '失败', value: 'failed' },
];
const issueOpts = [
  { label: '有问题', value: 'true' },
  { label: '无问题', value: 'false' },
];
const filterStatus = ref<string | null>(null);
const filterHasIssue = ref<string | null>(null);

async function loadTaskInfo() {
  if (!props.pathTaskId) return;
  try {
    const res = await getPathTaskDetail(props.pathTaskId);
    pathTask.value = (res as any)?.data ?? res;
  } catch {
    // ignore
  }
}

async function loadData() {
  if (!props.pathTaskId) return;
  loading.value = true;
  try {
    const params: Record<string, any> = {
      path_task_id: props.pathTaskId,
      page: pagination.page,
      page_size: pagination.pageSize,
    };
    if (activeDim.value !== 'all') params.dimension = activeDim.value;
    if (filterStatus.value) params.status = filterStatus.value;
    if (filterHasIssue.value) params.has_issue = filterHasIssue.value;

    const res = await getExecutionList(params);
    records.value = res.data || [];
    pagination.itemCount = (res as any).count || 0;
  } catch (e) {
    handleError(e, '加载记录失败');
    records.value = [];
  } finally {
    loading.value = false;
  }
}

const dimLabelMap: Record<string, string> = Object.fromEntries(
  dimensions.map((d) => [d.key, d.label]),
);

const sevMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  low: { label: '低', type: 'info' },
  medium: { label: '中', type: 'warning' },
  high: { label: '高', type: 'error' },
  critical: { label: '严重', type: 'error' },
};

const columns: DataTableColumns<MonitorExecution> = [
  {
    key: 'dimension',
    title: '维度',
    width: 100,
    render: (row) =>
      h(NTag, { size: 'small', bordered: false }, { default: () => dimLabelMap[row.dimension] || row.dimension }),
  },
  {
    key: 'status',
    title: '状态',
    width: 90,
    render: (row) => {
      const map: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
        pending: { label: '等待中', type: 'default' },
        running: { label: '执行中', type: 'info' },
        success: { label: '成功', type: 'success' },
        failed: { label: '失败', type: 'error' },
      };
      const s = map[row.status] || { label: row.status, type: 'default' };
      return h(NTag, { size: 'small', type: s.type, bordered: false }, { default: () => s.label });
    },
  },
  {
    key: 'has_issue',
    title: '安全',
    width: 90,
    render: (row) => {
      if (row.status === 'pending' || row.status === 'running') return h('span', { class: 'text-gray-400' }, '-');
      if (row.status !== 'success') return h('span', { class: 'text-gray-400' }, '-');
      return h(NTag, { size: 'small', type: row.has_issue ? 'error' : 'success', bordered: false }, { default: () => row.has_issue ? '发现问题' : '安全' });
    },
  },
  {
    key: 'severity',
    title: '严重程度',
    width: 90,
    render: (row) => {
      if (!row.has_issue || !row.severity || row.status !== 'success') return h('span', { class: 'text-gray-400' }, '-');
      const s = sevMap[row.severity];
      return s ? h(NTag, { size: 'small', type: s.type, bordered: false }, { default: () => s.label }) : row.severity;
    },
  },
  {
    key: 'created_at',
    title: '时间',
    width: 170,
    render: (row) => (row.created_at ? dayjs(row.created_at).format('YYYY-MM-DD HH:mm:ss') : '-'),
  },
  {
    key: 'op',
    title: '操作',
    width: 70,
    fixed: 'right',
    render: (row) =>
      h(NButton, { text: true, size: 'small', type: 'primary', onClick: () => openDetail(row) }, { default: () => '详情' }),
  },
];

const tableColumns = computed(() => {
  if (activeDim.value !== 'all') return columns.filter((c) => c.key !== 'dimension');
  return columns;
});

const detailVisible = ref(false);
const detailRecordId = ref('');

function openDetail(row: MonitorExecution) {
  detailRecordId.value = row.id;
  detailVisible.value = true;
}

function closeDetail() {
  detailVisible.value = false;
}

function handleTabChange(dim: string) {
  activeDim.value = dim;
  pagination.page = 1;
  loadData();
}

function handleFilter() {
  pagination.page = 1;
  loadData();
}

function resetFilter() {
  filterStatus.value = null;
  filterHasIssue.value = null;
  pagination.page = 1;
  loadData();
}

watch(
  () => props.pathTaskId,
  (id) => {
    if (id) {
      activeDim.value = 'all';
      pagination.page = 1;
      loadTaskInfo();
      loadData();
    }
  },
);

watch(
  () => props.show,
  (show) => {
    if (show && props.pathTaskId) {
      loadTaskInfo();
      loadData();
    }
  },
);
</script>

<template>
  <NDrawer v-model:show="drawerShow" :width="920" placement="right">
    <NDrawerContent
      :title="`监测记录${pathTask?.name ? ` — ${pathTask.name}` : ''}`"
      closable
      :body-content-style="{ padding: '0' }"
    >
      <div class="p-4">
        <NTabs
          v-model:value="activeDim"
          type="line"
          size="small"
          @update:value="handleTabChange"
        >
          <NTabPane
            v-for="item in dimensions"
            :key="item.key"
            :name="item.key"
          >
            <template #tab>
              <NSpace :size="4" align="center">
                <IconifyIcon :icon="item.icon" :style="{ color: item.color }" />
                <span>{{ item.label }}</span>
              </NSpace>
            </template>
          </NTabPane>
        </NTabs>

        <DimensionTrendPanel
          v-if="pathTaskId"
          :path-task-id="pathTaskId"
          :dimension="activeDim"
          :dim-label="dimensions.find(d => d.key === activeDim)?.label || ''"
          :dim-color="dimensions.find(d => d.key === activeDim)?.color || '#6366f1'"
          :filters="{ hasIssue: filterHasIssue || '', disposition: '', status: filterStatus || '', dateRange: null }"
          class="mb-3 mt-2"
        />

        <NSpace align="center" class="mb-3" :size="8" wrap>
          <NSelect
            v-model:value="filterStatus"
            placeholder="执行状态"
            clearable
            size="small"
            style="width: 110px"
            :options="statusOpts"
          />
          <NSelect
            v-model:value="filterHasIssue"
            placeholder="安全状态"
            clearable
            size="small"
            style="width: 110px"
            :options="issueOpts"
          />
          <NButton type="primary" size="small" @click="handleFilter">查询</NButton>
          <NButton size="small" @click="resetFilter">重置</NButton>
          <span class="text-xs text-gray-400 ml-2">
            共 {{ pagination.itemCount }} 条
          </span>
        </NSpace>

        <NDataTable
          :columns="tableColumns"
          :data="records"
          :loading="loading"
          :pagination="pagination"
          :row-key="(r: MonitorExecution) => r.id"
          remote
          size="small"
          @update:page="
            (p: number) => {
              pagination.page = p;
              loadData();
            }
          "
          @update:page-size="
            (s: number) => {
              pagination.pageSize = s;
              pagination.page = 1;
              loadData();
            }
          "
        >
          <template #empty>
            <NEmpty description="暂无监测记录" />
          </template>
        </NDataTable>
      </div>

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
    </NDrawerContent>
  </NDrawer>
</template>

<style scoped>
.record-detail-modal-body {
  max-height: min(78vh, 820px);
  overflow-y: auto;
  padding-right: 4px;
}
</style>
