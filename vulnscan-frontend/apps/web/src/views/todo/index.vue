<script lang="ts" setup>
import { computed, h, onMounted, ref, watch } from 'vue';
import { useRouter } from 'vue-router';
import {
  NBadge, NButton, NCard, NDataTable, NDatePicker, NDescriptions,
  NDescriptionsItem, NDrawer, NDrawerContent, NEmpty, NInput,
  NModal, NSelect, NSpace, NStatistic, NTabPane, NTabs, NTag,
  useMessage,
} from 'naive-ui';
import {
  createTodo, deleteTodo, getTodoList, getTodoStats,
  type TodoItem, type TodoStats, updateTodo, updateTodoStatus,
} from '#/api/message';
import { useNaiveTablePagination } from '#/composables/useNaiveTablePagination';

defineOptions({ name: 'MyTodo' });

const router = useRouter();
const message = useMessage();

const loading = ref(false);
const data = ref<TodoItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const stats = ref<TodoStats | null>(null);
const activeTab = ref('all');
const keyword = ref('');
const statusFilter = ref<string | null>(null);

const showCreate = ref(false);
const showDetail = ref(false);
const detailRow = ref<TodoItem | null>(null);
const detailSaving = ref(false);

const createForm = ref({
  title: '',
  description: '',
  type: 'task',
  priority: 3,
  dueAt: null as null | number,
});

const detailForm = ref({
  title: '',
  feedback: '',
  priority: 3,
  dueAt: null as null | number,
});

const STATUS_MAP: Record<string, { label: string; type: string }> = {
  pending: { label: '待处理', type: 'default' },
  in_progress: { label: '进行中', type: 'info' },
  completed: { label: '已完成', type: 'success' },
  cancelled: { label: '已取消', type: 'warning' },
};

const PRIORITY_MAP: Record<number, { label: string; type: string }> = {
  1: { label: '低', type: 'default' },
  2: { label: '中', type: 'info' },
  3: { label: '高', type: 'warning' },
  4: { label: '紧急', type: 'error' },
};

const SOURCE_MAP: Record<string, { label: string; type: string }> = {
  manual: { label: '手动', type: 'default' },
  workflow: { label: '工作流', type: 'info' },
  system: { label: '系统', type: 'warning' },
};

const TYPE_MAP: Record<string, string> = {
  task: '任务',
  approval: '审批',
  reminder: '提醒',
};

const statusOptions = Object.entries(STATUS_MAP).map(([k, v]) => ({ label: v.label, value: k }));
const priorityOptions = Object.entries(PRIORITY_MAP).map(([k, v]) => ({ label: v.label, value: Number(k) }));

const canEditDetail = computed(
  () => !!detailRow.value
    && detailRow.value.source !== 'workflow'
    && detailRow.value.status !== 'completed'
    && detailRow.value.status !== 'cancelled',
);

const sourceFilter = computed(() => {
  if (activeTab.value === 'all') return undefined;
  return activeTab.value;
});

const columns = computed(() => [
  {
    title: '标题', key: 'title', minWidth: 200,
    render: (row: TodoItem) => {
      if (row.source === 'workflow' && row.source_url) {
        return h('a', {
          style: 'color:#2080f0;cursor:pointer',
          onClick: () => router.push(row.source_url),
        }, row.title);
      }
      return row.title;
    },
  },
  {
    title: '来源', key: 'source', width: 90, align: 'center' as const,
    render: (row: TodoItem) => {
      const m = SOURCE_MAP[row.source];
      return m ? h(NTag, { size: 'small', type: m.type as any, bordered: false }, () => m.label) : row.source;
    },
  },
  {
    title: '类型', key: 'type', width: 80, align: 'center' as const,
    render: (row: TodoItem) => TYPE_MAP[row.type] ?? row.type,
  },
  {
    title: '优先级', key: 'priority', width: 80, align: 'center' as const,
    render: (row: TodoItem) => {
      const m = PRIORITY_MAP[row.priority];
      return m ? h(NTag, { size: 'small', type: m.type as any, bordered: false }, () => m.label) : String(row.priority);
    },
  },
  {
    title: '状态', key: 'status', width: 100, align: 'center' as const,
    render: (row: TodoItem) => {
      const m = STATUS_MAP[row.status];
      return m ? h(NTag, { size: 'small', type: m.type as any, bordered: false }, () => m.label) : row.status;
    },
  },
  {
    title: '创建者', key: 'creator_name', width: 110,
    render: (row: TodoItem) => row.creator_name || row.creator_id || '-',
  },
  {
    title: '截止时间', key: 'due_date', width: 170,
    render: (row: TodoItem) => row.due_date ? formatTime(row.due_date) : '-',
  },
  {
    title: '创建时间', key: 'created_at', width: 170,
    render: (row: TodoItem) => formatTime(row.created_at),
  },
  {
    title: '操作', key: 'actions', width: 260, fixed: 'right' as const,
    render: (row: TodoItem) => h(NSpace, { size: 4 }, () => {
      const items: any[] = [
        h(NButton, { size: 'tiny', text: true, onClick: () => openDetail(row) }, () => '详情'),
      ];
      if (row.source === 'workflow' && row.source_url && (row.status === 'pending' || row.status === 'in_progress')) {
        items.push(h(NButton, { size: 'tiny', type: 'primary', text: true, onClick: () => handleProcessWorkflow(row) }, () => '处理'));
      }
      if (row.source !== 'workflow' && row.status === 'pending') {
        items.push(h(NButton, { size: 'tiny', type: 'primary', text: true, onClick: () => handleStart(row) }, () => '开始'));
      }
      if (row.source !== 'workflow' && row.status === 'in_progress') {
        items.push(h(NButton, { size: 'tiny', type: 'success', text: true, onClick: () => handleComplete(row) }, () => '完成'));
      }
      if (row.status === 'pending' || row.status === 'in_progress') {
        items.push(h(NButton, { size: 'tiny', type: 'warning', text: true, onClick: () => handleCancel(row) }, () => '取消'));
      }
      if (row.source !== 'workflow' && (row.status === 'completed' || row.status === 'cancelled')) {
        items.push(h(NButton, { size: 'tiny', type: 'error', text: true, onClick: () => handleDelete(row) }, () => '删除'));
      }
      return items;
    }),
  },
]);

function formatTime(t?: string | null) {
  if (!t) return '-';
  try { return new Date(t).toLocaleString('zh-CN'); }
  catch { return t; }
}

async function fetchData() {
  loading.value = true;
  try {
    const params: Record<string, any> = {
      page: page.value,
      page_size: pageSize.value,
      source: sourceFilter.value,
    };
    if (keyword.value) params.keyword = keyword.value;
    if (statusFilter.value) params.status = statusFilter.value;
    const r = await getTodoList(params);
    data.value = r.items;
    total.value = r.total;
  } finally {
    loading.value = false;
  }
}

const { pagination } = useNaiveTablePagination({ page, pageSize, total, onFetch: fetchData });

async function refreshStats() {
  try {
    stats.value = await getTodoStats();
  } catch { stats.value = null; }
}

function openDetail(row: TodoItem) {
  detailRow.value = { ...row };
  detailForm.value = {
    title: row.title || '',
    feedback: (row as any).feedback || '',
    priority: row.priority ?? 3,
    dueAt: row.due_date ? new Date(row.due_date).getTime() : null,
  };
  showDetail.value = true;
}

async function handleProcessWorkflow(row: TodoItem) {
  if (row.status === 'pending') {
    try {
      await updateTodoStatus(row.id, 'in_progress');
    } catch { /* continue to navigate */ }
  }
  if (row.source_url) router.push(row.source_url);
}

async function handleStart(row: TodoItem) {
  try {
    await updateTodoStatus(row.id, 'in_progress');
    message.success('已开始处理');
    fetchData();
    refreshStats();
  } catch (e: any) { message.error(e?.message || '操作失败'); }
}

async function handleComplete(row: TodoItem) {
  try {
    await updateTodoStatus(row.id, 'completed');
    message.success('已标记完成');
    if (detailRow.value?.id === row.id) {
      detailRow.value = { ...detailRow.value, status: 'completed', completed_at: new Date().toISOString() };
    }
    fetchData();
    refreshStats();
  } catch (e: any) { message.error(e?.message || '操作失败'); }
}

async function handleCancel(row: TodoItem) {
  try {
    await updateTodoStatus(row.id, 'cancelled');
    message.success('已取消');
    if (detailRow.value?.id === row.id) {
      detailRow.value = { ...detailRow.value, status: 'cancelled' };
    }
    fetchData();
    refreshStats();
  } catch (e: any) { message.error(e?.message || '操作失败'); }
}

async function handleDelete(row: TodoItem) {
  try {
    await deleteTodo(row.id);
    message.success('已删除');
    fetchData();
    refreshStats();
  } catch (e: any) { message.error(e?.message || '删除失败'); }
}

async function handleSaveDetail() {
  if (!detailRow.value) return;
  const title = detailForm.value.title.trim();
  if (!title) { message.warning('请输入待办标题'); return; }
  detailSaving.value = true;
  try {
    const dueDate = detailForm.value.dueAt ? new Date(detailForm.value.dueAt).toISOString() : null;
    await updateTodo(detailRow.value.id, {
      title,
      feedback: detailForm.value.feedback.trim(),
      priority: detailForm.value.priority,
      due_date: dueDate,
    } as any);
    detailRow.value = {
      ...detailRow.value,
      title,
      priority: detailForm.value.priority,
      due_date: dueDate,
    };
    message.success('待办详情已更新');
    fetchData();
    refreshStats();
  } catch (e: any) { message.error(e?.message || '保存失败'); }
  finally { detailSaving.value = false; }
}

function resetCreateForm() {
  createForm.value = { title: '', description: '', type: 'task', priority: 3, dueAt: null };
}

async function handleCreate() {
  if (!createForm.value.title.trim()) { message.warning('请输入待办标题'); return; }
  try {
    await createTodo({
      title: createForm.value.title.trim(),
      description: createForm.value.description.trim(),
      type: createForm.value.type,
      priority: createForm.value.priority,
      due_date: createForm.value.dueAt ? new Date(createForm.value.dueAt).toISOString() : null,
    } as Partial<TodoItem>);
    message.success('创建成功');
    showCreate.value = false;
    resetCreateForm();
    fetchData();
    refreshStats();
  } catch (e: any) { message.error(e?.message || '创建失败'); }
}

watch(showCreate, (v) => { if (!v) resetCreateForm(); });
watch(showDetail, (v) => { if (!v) { detailRow.value = null; detailSaving.value = false; } });

onMounted(() => {
  fetchData();
  refreshStats();
});
</script>

<template>
  <div style="padding:16px">
    <NCard title="我的待办" size="small">
      <template #header-extra>
        <NSpace align="center" :size="20">
          <template v-if="stats">
            <NBadge :value="stats.pending" :max="999" :offset="[-6, 0]">
              <NStatistic label="待处理" :value="stats.pending" />
            </NBadge>
            <NStatistic label="进行中" :value="stats.in_progress" />
            <NStatistic label="已完成" :value="stats.completed" />
            <NBadge v-if="stats.overdue > 0" :value="stats.overdue" type="error" :offset="[-6, 0]">
              <NStatistic label="已逾期" :value="stats.overdue" />
            </NBadge>
          </template>
          <NButton size="small" type="primary" @click="showCreate = true">新建待办</NButton>
        </NSpace>
      </template>

      <NTabs v-model:value="activeTab" type="line" @update:value="() => { page = 1; fetchData(); }">
        <NTabPane name="all" tab="全部" />
        <NTabPane name="workflow" tab="工作流" />
        <NTabPane name="manual" tab="手动" />
        <NTabPane name="system" tab="系统" />
      </NTabs>

      <NSpace style="margin:12px 0" :size="8">
        <NSelect
          v-model:value="statusFilter"
          :options="statusOptions"
          placeholder="状态"
          size="small"
          style="width:120px"
          clearable
          @update:value="() => { page = 1; fetchData(); }"
        />
        <NInput
          v-model:value="keyword"
          placeholder="搜索..."
          size="small"
          clearable
          style="width:200px"
          @keyup.enter="() => { page = 1; fetchData(); }"
          @clear="() => { page = 1; fetchData(); }"
        />
        <NButton size="small" @click="() => { page = 1; fetchData(); }">搜索</NButton>
      </NSpace>

      <NDataTable
        :columns="columns"
        :data="data"
        :loading="loading"
        :bordered="false"
        size="small"
        striped
        remote
        :scroll-x="1200"
        :row-key="(row: TodoItem) => row.id"
        :pagination="pagination"
      />
    </NCard>

    <!-- 详情抽屉 -->
    <NDrawer v-model:show="showDetail" :width="520" placement="right">
      <NDrawerContent :title="detailRow ? `待办详情 #${detailRow.id}` : '待办详情'" closable>
        <template v-if="detailRow">
          <NDescriptions bordered :column="2" size="small" style="margin-bottom:16px">
            <NDescriptionsItem label="状态">
              <NTag :type="(STATUS_MAP[detailRow.status]?.type ?? 'default') as any" size="small">
                {{ STATUS_MAP[detailRow.status]?.label ?? detailRow.status }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="来源">
              <NTag :type="(SOURCE_MAP[detailRow.source]?.type ?? 'default') as any" size="small">
                {{ SOURCE_MAP[detailRow.source]?.label ?? detailRow.source }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="类型">
              {{ TYPE_MAP[detailRow.type] ?? detailRow.type }}
            </NDescriptionsItem>
            <NDescriptionsItem label="优先级">
              <NTag :type="(PRIORITY_MAP[detailRow.priority]?.type ?? 'default') as any" size="small">
                {{ PRIORITY_MAP[detailRow.priority]?.label ?? detailRow.priority }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="创建者">
              {{ detailRow.creator_name || detailRow.creator_id || '-' }}
            </NDescriptionsItem>
            <NDescriptionsItem label="截止时间">
              {{ formatTime(detailRow.due_date) }}
            </NDescriptionsItem>
            <NDescriptionsItem label="创建时间">
              {{ formatTime(detailRow.created_at) }}
            </NDescriptionsItem>
            <NDescriptionsItem label="完成时间">
              {{ formatTime(detailRow.completed_at) }}
            </NDescriptionsItem>
          </NDescriptions>

          <NCard :bordered="false" size="small" title="基本信息" style="margin-bottom:12px">
            <div style="margin-bottom:10px">
              <div style="margin-bottom:4px;font-weight:500;font-size:13px">标题</div>
              <NInput v-model:value="detailForm.title" :readonly="!canEditDetail" />
            </div>
            <div style="margin-bottom:10px">
              <div style="margin-bottom:4px;font-weight:500;font-size:13px">优先级</div>
              <NSelect v-model:value="detailForm.priority" :options="priorityOptions" :disabled="!canEditDetail" />
            </div>
            <div>
              <div style="margin-bottom:4px;font-weight:500;font-size:13px">截止时间</div>
              <NDatePicker
                v-model:value="detailForm.dueAt"
                type="datetime"
                clearable
                style="width:100%"
                :disabled="!canEditDetail"
              />
            </div>
          </NCard>

          <NCard :bordered="false" size="small" title="待办说明" style="margin-bottom:12px">
            <NInput :value="detailRow.description || '-'" type="textarea" :autosize="{ minRows: 3, maxRows: 5 }" readonly />
          </NCard>

          <NCard :bordered="false" size="small" title="处理说明">
            <NInput
              v-model:value="detailForm.feedback"
              type="textarea"
              :autosize="{ minRows: 4, maxRows: 8 }"
              :readonly="!canEditDetail"
              placeholder="记录当前处理进展、跟进说明或完成结论"
            />
          </NCard>
        </template>

        <template #footer>
          <NSpace justify="end">
            <NButton
              v-if="detailRow && detailRow.source !== 'workflow' && detailRow.status === 'pending'"
              type="primary"
              @click="detailRow && handleStart(detailRow)"
            >开始处理</NButton>
            <NButton
              v-if="detailRow && detailRow.source !== 'workflow' && detailRow.status === 'in_progress'"
              type="success"
              @click="detailRow && handleComplete(detailRow)"
            >完成</NButton>
            <NButton
              v-if="detailRow && (detailRow.status === 'pending' || detailRow.status === 'in_progress')"
              type="warning"
              @click="detailRow && handleCancel(detailRow)"
            >取消</NButton>
            <NButton
              v-if="detailRow && detailRow.source === 'workflow' && detailRow.source_url"
              type="primary"
              @click="detailRow && handleProcessWorkflow(detailRow)"
            >前往处理</NButton>
            <NButton
              v-if="canEditDetail"
              type="primary"
              secondary
              :loading="detailSaving"
              @click="handleSaveDetail"
            >保存说明</NButton>
          </NSpace>
        </template>
      </NDrawerContent>
    </NDrawer>

    <!-- 新建弹窗 -->
    <NModal
      v-model:show="showCreate"
      preset="dialog"
      title="新建待办"
      positive-text="创建"
      negative-text="取消"
      style="width:520px"
      @positive-click="handleCreate"
    >
      <div style="display:flex;flex-direction:column;gap:12px;padding-top:8px">
        <div>
          <div style="margin-bottom:4px;font-weight:500">标题 *</div>
          <NInput v-model:value="createForm.title" placeholder="请输入待办标题" />
        </div>
        <div>
          <div style="margin-bottom:4px;font-weight:500">描述</div>
          <NInput v-model:value="createForm.description" type="textarea" :autosize="{ minRows: 3, maxRows: 5 }" placeholder="可选，补充待办说明" />
        </div>
        <div>
          <div style="margin-bottom:4px;font-weight:500">优先级</div>
          <NSelect v-model:value="createForm.priority" :options="priorityOptions" placeholder="请选择优先级" />
        </div>
        <div>
          <div style="margin-bottom:4px;font-weight:500">截止时间</div>
          <NDatePicker v-model:value="createForm.dueAt" type="datetime" clearable style="width:100%" placeholder="可选，设置截止时间" />
        </div>
      </div>
    </NModal>
  </div>
</template>
