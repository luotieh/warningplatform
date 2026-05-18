<script lang="ts" setup>
import { computed, h, onMounted, onUnmounted, ref } from 'vue';

import {
  NButton,
  NCard,
  NDataTable,
  NInput,
  NModal,
  NForm,
  NFormItem,
  NSelect,
  NSpace,
  NTag,
  NProgress,
  NPopconfirm,
  useMessage,
  type DataTableRowKey,
} from 'naive-ui';
import { useRouter } from 'vue-router';

import {
  getTaskList,
  createTask,
  cancelTask,
  deleteTask,
  rerunTask,
  getScanEnginePresets,
  type ScanTask,
  type ScanEnginePreset,
} from '#/api/task';
import { getTemplateList, type ScanTemplate } from '#/api/template';
import { taskStatusLabels, taskStatusTypes } from '#/constants/status';
import ModuleConfigPanel from '../components/module-config-panel.vue';
import {
  appendExecutorNodeParams,
  EXECUTOR_LOCAL_ID,
  useScanExecutorNodes,
} from '../scan-executor';

defineOptions({ name: 'ScanTaskList' });

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const data = ref<ScanTask[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const checkedRowKeys = ref<DataTableRowKey[]>([]);
let refreshTimer: ReturnType<typeof setInterval> | null = null;

const showCreate = ref(false);
const creating = ref(false);
const showAdvanced = ref(false);
const showModuleConfig = ref(false);
const moduleConfigs = ref<Record<string, Record<string, any>>>({});
const templates = ref<ScanTemplate[]>([]);
const enginePresets = ref<ScanEnginePreset[]>([]);
const selectedTemplateId = ref('');
const scanExecutor = useScanExecutorNodes();

const form = ref<{
  name: string;
  targets: string;
  template_id: string;
  priority: number;
  verification_level: string;
  engine_preset: string;
  executor_node_ids: string[];
}>({
  name: '',
  targets: '',
  template_id: '',
  priority: 5,
  verification_level: 'both',
  engine_preset: '',
  executor_node_ids: [EXECUTOR_LOCAL_ID],
});

const verificationOptions = [
  { label: '全部 — 原理验证+实际利用', value: 'both' },
  { label: '原理验证 — 仅检测漏洞模式，不实际利用', value: 'principle' },
  { label: '实际利用 — 确认漏洞可被利用', value: 'exploit' },
];

const priorityOptions = [
  { label: '最高 (1)', value: 1 },
  { label: '高 (3)', value: 3 },
  { label: '普通 (5)', value: 5 },
  { label: '低 (7)', value: 7 },
  { label: '最低 (10)', value: 10 },
];

function formatTime(raw?: string) {
  if (!raw) return '-';
  const d = new Date(raw);
  if (isNaN(d.getTime())) return raw;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const columns = [
  { type: 'selection' as const, width: 40 },
  {
    title: '任务名称',
    key: 'name',
    minWidth: 140,
    ellipsis: { tooltip: true },
    render: (row: ScanTask) =>
      h('a', {
        style: 'color: var(--primary-color); cursor: pointer; font-weight: 500',
        onClick: () => router.push(`/scan/task/${row.id}`),
      }, row.name),
  },
  {
    title: '目标数',
    key: 'total_targets',
    width: 70,
    align: 'center' as const,
  },
  {
    title: '存活/端口',
    key: 'alive_hosts',
    width: 90,
    align: 'center' as const,
    render: (row: ScanTask) => {
      const alive = row.alive_hosts ?? 0;
      const ports = row.open_ports ?? 0;
      return h('span', { style: 'font-size: 12px' }, `${alive} / ${ports}`);
    },
  },
  {
    title: '任务进度',
    key: 'progress',
    width: 160,
    render: (row: ScanTask) => {
      const pct = Math.round(row.progress ?? 0);
      const color = row.status === 'failed' ? '#e88080' : row.status === 'completed' ? '#48bb78' : undefined;
      return h(NProgress, {
        type: 'line',
        percentage: pct,
        indicatorPlacement: 'inside',
        height: 18,
        color,
        railColor: row.status === 'failed' ? '#fce4e4' : undefined,
      });
    },
  },
  {
    title: '状态',
    key: 'status',
    width: 80,
    render: (row: ScanTask) => {
      const label = taskStatusLabels[row.status] || row.status;
      const type = taskStatusTypes[row.status] || 'default';
      return h(NTag, { type: type as any, size: 'small' }, () => label);
    },
  },
  {
    title: '创建时间',
    key: 'created_at',
    width: 170,
    render: (row: ScanTask) => h('span', { style: 'font-size: 13px; white-space: nowrap' }, formatTime(row.created_at)),
  },
  {
    title: '结束时间',
    key: 'finished_at',
    width: 170,
    render: (row: ScanTask) => h('span', { style: 'font-size: 13px; white-space: nowrap' }, formatTime(row.finished_at)),
  },
  {
    title: '操作',
    key: 'actions',
    width: 200,
    fixed: 'right' as const,
    render: (row: ScanTask) => {
      const btns: any[] = [];

      btns.push(h(NButton, {
        size: 'tiny',
        type: 'primary',
        text: true,
        onClick: () => router.push(`/scan/task/${row.id}`),
      }, () => row.status === 'completed' || row.status === 'failed' ? '结果' : '查看'));

      if (row.status === 'running' || row.status === 'queued') {
        btns.push(h(NPopconfirm, { onPositiveClick: () => handleCancel(row.id) }, {
          trigger: () => h(NButton, { size: 'tiny', type: 'warning', text: true }, () => '取消'),
          default: () => '确定取消此任务？',
        }));
      }

      if (canRerunRow(row)) {
        btns.push(
          h(
            NButton,
            {
              size: 'tiny',
              type: 'info',
              text: true,
              onClick: () => handleRerunRow(row.id),
            },
            () => '重跑',
          ),
        );
      }

      if (row.status !== 'running' && row.status !== 'queued') {
        btns.push(h(NPopconfirm, { onPositiveClick: () => handleDeleteRow(row.id) }, {
          trigger: () => h(NButton, { size: 'tiny', type: 'error', text: true }, () => '删除'),
          default: () => '确定删除此任务？',
        }));
      }

      return h(NSpace, { size: 8 }, () => btns);
    },
  },
];

function openCreateModal() {
  form.value.executor_node_ids = [EXECUTOR_LOCAL_ID];
  void scanExecutor.loadExecutorNodeOptions();
  showCreate.value = true;
}

async function fetchData() {
  loading.value = true;
  try {
    const result = await getTaskList({
      page: page.value,
      page_size: pageSize.value,
      keyword: keyword.value || undefined,
    });
    data.value = result.items ?? [];
    total.value = result.total ?? 0;
  } finally {
    loading.value = false;
  }
}

async function handleCreate() {
  if (!form.value.template_id) {
    message.warning('请选择扫描模板');
    return;
  }
  if (!form.value.targets.trim()) {
    message.warning('请输入扫描目标');
    return;
  }
  creating.value = true;
  try {
    const targets = form.value.targets.split(/[\n,;]+/).map((t) => t.trim()).filter(Boolean);
    const payload: Record<string, any> = {
      name: form.value.name || `扫描-${new Date().toLocaleString()}`,
      targets,
      template_id: form.value.template_id,
      priority: form.value.priority,
    };
    const params: Record<string, any> = {};
    if (Object.keys(moduleConfigs.value).length > 0) {
      params.module_configs = moduleConfigs.value;
    }
    if (form.value.verification_level !== 'both') {
      params.verification_level = form.value.verification_level;
    }
    if (form.value.engine_preset) {
      params.engine_preset = form.value.engine_preset;
    }
    appendExecutorNodeParams(params, form.value.executor_node_ids);
    payload.executor_node_ids = form.value.executor_node_ids;
    if (Object.keys(params).length > 0) {
      payload.parameters = params;
    }
    await createTask(payload as Parameters<typeof createTask>[0]);
    message.success('任务创建成功');
    showCreate.value = false;
    showAdvanced.value = false;
    selectedTemplateId.value = '';
    form.value = {
      name: '',
      targets: '',
      template_id: '',
      priority: 5,
      verification_level: 'both',
      engine_preset: '',
      executor_node_ids: [EXECUTOR_LOCAL_ID],
    };
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '创建失败');
  } finally {
    creating.value = false;
  }
}

async function handleCancel(id: string) {
  try {
    await cancelTask(id);
    message.success('任务已取消');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '取消失败');
  }
}

async function handleDeleteRow(id: string) {
  try {
    await deleteTask(id);
    message.success('删除成功');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}

function canRerunRow(row: ScanTask) {
  return (
    row.status !== 'running' &&
    row.status !== 'queued' &&
    row.status !== 'splitting' &&
    row.status !== 'pending'
  );
}

async function handleRerunRow(id: string) {
  try {
    const res = await rerunTask(id);
    message.success('已提交重新运行');
    if (res?.task_id) {
      router.push(`/scan/task/${res.task_id}`);
    } else {
      await fetchData();
    }
  } catch (e: any) {
    message.error(e?.message || '重新运行失败');
  }
}

async function handleBatchDelete() {
  if (checkedRowKeys.value.length === 0) {
    message.warning('请先选择任务');
    return;
  }
  for (const id of checkedRowKeys.value) {
    try {
      await deleteTask(id as string);
    } catch { /* continue */ }
  }
  checkedRowKeys.value = [];
  message.success('批量删除完成');
  await fetchData();
}

async function loadTemplates() {
  try {
    const res = await getTemplateList({ page: 1, page_size: 100 });
    templates.value = res.items.filter(t => t.enabled);
  } catch {}
}

async function loadEnginePresets() {
  try {
    enginePresets.value = await getScanEnginePresets();
  } catch {
    enginePresets.value = [];
  }
}

const templateOptions = computed(() =>
  templates.value.map(t => ({ label: `${t.name} ${t.builtin ? '(内置)' : ''}`, value: t.id })),
);

const enginePresetOptions = computed(() => [
  { label: '不使用预设', value: '' },
  ...enginePresets.value.map((p) => ({
    label: `${p.name} — ${p.description}`,
    value: p.name,
  })),
]);

const selectedTemplate = computed(() =>
  templates.value.find(t => t.id === selectedTemplateId.value),
);

function handleTemplateSelect(id: string) {
  selectedTemplateId.value = id;
  form.value.template_id = id;
  if (!id) return;
  const tmpl = templates.value.find(t => t.id === id);
  if (!tmpl) return;
  form.value.name = tmpl.name + ' - ' + new Date().toLocaleDateString('zh-CN');
}

onMounted(() => {
  fetchData();
  loadTemplates();
  loadEnginePresets();
  refreshTimer = setInterval(() => {
    if (data.value.some((t) => t.status === 'running' || t.status === 'queued')) {
      fetchData();
    }
  }, 5000);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
});
</script>

<template>
  <div class="task-list-page">
    <NCard size="small">
      <!-- Toolbar -->
      <div class="toolbar">
        <div class="toolbar-left">
          <NButton type="primary" @click="openCreateModal">
            <template #icon><span style="font-size: 16px; line-height: 1">+</span></template>
            新建任务
          </NButton>
          <NPopconfirm @positive-click="handleBatchDelete">
            <template #trigger>
              <NButton :disabled="checkedRowKeys.length === 0">
                删除{{ checkedRowKeys.length > 0 ? ` (${checkedRowKeys.length})` : '' }}
              </NButton>
            </template>
            确定删除选中的 {{ checkedRowKeys.length }} 个任务？
          </NPopconfirm>
          <NButton quaternary @click="fetchData">
            <template #icon><span style="font-size: 14px">&#8635;</span></template>
          </NButton>
        </div>
        <div class="toolbar-right">
          <NInput
            v-model:value="keyword"
            placeholder="搜索任务名称..."
            style="width: 260px"
            clearable
            @keyup.enter="fetchData"
            @clear="fetchData"
          />
        </div>
      </div>

      <NDataTable
        :columns="columns"
        :data="data"
        :loading="loading"
        :bordered="false"
        size="small"
        striped
        :scroll-x="1120"
        :row-key="(row: ScanTask) => row.id"
        v-model:checked-row-keys="checkedRowKeys"
        :pagination="{
          page: page,
          pageSize: pageSize,
          itemCount: total,
          showSizePicker: true,
          pageSizes: [20, 50, 100],
          prefix: ({ itemCount }) => `共 ${itemCount} 条`,
          onUpdatePage: (p: number) => { page = p; fetchData(); },
          onUpdatePageSize: (s: number) => { pageSize = s; page = 1; fetchData(); },
        }"
      />
    </NCard>

    <!-- Create Task Modal -->
    <NModal v-model:show="showCreate" preset="card" style="width: 680px; border-radius: 12px" :mask-closable="false">
      <template #header>
        <div class="modal-header">
          <span class="modal-title">创建扫描任务</span>
          <span class="modal-subtitle">配置目标和扫描策略</span>
        </div>
      </template>

      <NForm label-placement="left" label-width="80" style="margin-top: 4px">
        <!-- Template -->
        <NFormItem label="扫描模板">
          <NSelect v-model:value="selectedTemplateId" :options="templateOptions" placeholder="选择扫描模板" @update:value="handleTemplateSelect" />
        </NFormItem>

        <!-- Stage Preview -->
        <div v-if="selectedTemplate?.stages?.length" style="margin:-8px 0 12px;padding:8px 12px;background:var(--card-color);border-radius:6px;border:1px solid var(--border-color)">
          <div style="font-size:12px;color:var(--text-color-3);margin-bottom:4px">执行阶段预览</div>
          <NSpace :size="4" wrap>
            <NTag v-for="(s, i) in selectedTemplate.stages" :key="i" size="small" :bordered="false" type="info">
              {{ s.name }}
            </NTag>
          </NSpace>
        </div>

        <!-- Task Name -->
        <NFormItem label="任务名称">
          <NInput v-model:value="form.name" placeholder="留空将自动生成名称" />
        </NFormItem>

        <NFormItem label="执行节点" required>
          <NSelect
            v-model:value="form.executor_node_ids"
            :options="scanExecutor.executorNodeOptions.value"
            :loading="scanExecutor.executorNodesLoading.value"
            multiple
            filterable
            placeholder="默认在本机执行引擎运行"
            :max-tag-count="2"
          />
        </NFormItem>

        <!-- Targets -->
        <NFormItem label="扫描目标">
          <NInput
            v-model:value="form.targets"
            type="textarea"
            placeholder="每行一个目标，支持 IP / 域名 / CIDR / URL&#10;示例: 192.168.1.0/24&#10;      example.com&#10;      https://api.example.com"
            :rows="5"
            style="font-family: 'SF Mono', Consolas, monospace; font-size: 13px"
          />
        </NFormItem>

        <!-- Advanced Toggle -->
        <div class="advanced-toggle" @click="showAdvanced = !showAdvanced">
          <span class="advanced-arrow" :class="{ expanded: showAdvanced }">&#9654;</span>
          <span>高级选项</span>
        </div>

        <template v-if="showAdvanced">
          <div style="display: flex; gap: 16px; margin-top: 12px">
            <NFormItem label="优先级" style="flex: 1">
              <NSelect v-model:value="form.priority" :options="priorityOptions" />
            </NFormItem>
            <NFormItem label="验证级别" style="flex: 1">
              <NSelect v-model:value="form.verification_level" :options="verificationOptions" />
            </NFormItem>
          </div>
          <NFormItem label="引擎预设" style="margin-top: 4px">
            <NSelect
              v-model:value="form.engine_preset"
              :options="enginePresetOptions"
              placeholder="可选：合并默认 Nuclei/调度相关参数"
              filterable
              clearable
            />
          </NFormItem>
        </template>

        <!-- Module Config -->
        <div class="module-config-link">
          <NButton text type="primary" size="small" @click="showModuleConfig = true">
            模块参数微调
          </NButton>
          <NTag v-if="Object.keys(moduleConfigs).length > 0" size="small" type="success" round :bordered="false">
            {{ Object.keys(moduleConfigs).length }} 个模块已配置
          </NTag>
        </div>
      </NForm>

      <template #action>
        <NSpace justify="end" :size="12">
          <NButton @click="showCreate = false">取消</NButton>
          <NButton type="primary" :loading="creating" @click="handleCreate">
            开始扫描
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <ModuleConfigPanel
      v-model:show="showModuleConfig"
      :module-configs="moduleConfigs"
      @save="(configs: Record<string, Record<string, any>>) => moduleConfigs = configs"
    />
  </div>
</template>

<style scoped>
.task-list-page {
  padding: 20px 24px;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 12px;
}

.toolbar-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.toolbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.modal-header {
  display: flex;
  flex-direction: column;
}

.modal-title {
  font-size: 17px;
  font-weight: 600;
}

.modal-subtitle {
  font-size: 12px;
  color: #999;
  margin-top: 2px;
  font-weight: 400;
}

.advanced-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  font-size: 13px;
  color: #666;
  user-select: none;
  padding: 6px 0;
  transition: color 0.15s;
}
.advanced-toggle:hover {
  color: #1890ff;
}

.advanced-arrow {
  display: inline-block;
  font-size: 10px;
  transition: transform 0.2s;
}
.advanced-arrow.expanded {
  transform: rotate(90deg);
}

.form-hint {
  font-size: 12px;
  color: #999;
  margin-top: -8px;
  margin-bottom: 12px;
  padding-left: 80px;
}

.module-config-link {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 8px;
  padding-top: 12px;
  border-top: 1px dashed #f0f0f0;
}
</style>
