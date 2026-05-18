<script setup lang="ts">
import { ref, computed, h, onMounted } from 'vue';
import {
  NCard, NDataTable, NButton, NSpace, NTag, NModal, NForm,
  NFormItem, NInput, NSelect, NInputNumber, NSwitch, NPopconfirm,
  useMessage, NDescriptions, NDescriptionsItem, NDrawer, NDrawerContent,
} from 'naive-ui';
import type { DataTableColumns } from 'naive-ui';
import {
  getScheduleList, createSchedule, updateSchedule,
  deleteSchedule, toggleSchedule, runScheduleNow,
  type ScanSchedule,
} from '#/api/schedule';
import { getTemplateList, type ScanTemplate } from '#/api/template';
import { getScanEnginePresets, type ScanEnginePreset } from '#/api/task';

const message = useMessage();
const loading = ref(false);
const data = ref<ScanSchedule[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const templates = ref<ScanTemplate[]>([]);
const enginePresets = ref<ScanEnginePreset[]>([]);

async function fetchData() {
  loading.value = true;
  try {
    const res = await getScheduleList({ page: page.value, page_size: pageSize.value, keyword: keyword.value });
    data.value = res.items;
    total.value = res.total;
  } finally {
    loading.value = false;
  }
}

async function loadTemplates() {
  try {
    const res = await getTemplateList({ page: 1, page_size: 100 });
    templates.value = res.items.filter(t => t.enabled);
  } catch {}
}

onMounted(() => { fetchData(); loadTemplates(); loadEnginePresets(); });

async function loadEnginePresets() {
  try {
    enginePresets.value = await getScanEnginePresets();
  } catch {
    enginePresets.value = [];
  }
}

const templateOptions = computed(() =>
  templates.value.map(t => ({ label: `${t.name}${t.builtin ? ' (内置)' : ''}`, value: t.id })),
);

const enginePresetOptions = computed(() => [
  { label: '不使用预设', value: '' },
  ...enginePresets.value.map((p) => ({
    label: `${p.name} — ${p.description}`,
    value: p.name,
  })),
]);

const scheduleTypeOptions = [
  { label: 'Cron 表达式', value: 'cron' },
  { label: '固定间隔', value: 'interval' },
  { label: '每天', value: 'daily' },
  { label: '每周', value: 'weekly' },
  { label: '每月', value: 'monthly' },
];

const weekdayOptions = [
  { label: '周一', value: 1 },
  { label: '周二', value: 2 },
  { label: '周三', value: 3 },
  { label: '周四', value: 4 },
  { label: '周五', value: 5 },
  { label: '周六', value: 6 },
  { label: '周日', value: 0 },
];

const scheduleTypeLabel: Record<string, string> = {
  cron: 'Cron',
  interval: '固定间隔',
  daily: '每天',
  weekly: '每周',
  monthly: '每月',
};

function fmtTime(t: string | null) {
  if (!t) return '-';
  return new Date(t).toLocaleString('zh-CN');
}

function getTemplateName(id: string): string {
  const t = templates.value.find(tmpl => tmpl.id === id);
  return t?.name || id || '-';
}

const columns = computed<DataTableColumns<ScanSchedule>>(() => [
  { title: '名称', key: 'name', width: 180, ellipsis: { tooltip: true } },
  {
    title: '调度类型', key: 'schedule_type', width: 100,
    render: (row) => h(NTag, { size: 'small', bordered: false }, () => scheduleTypeLabel[row.schedule_type] || row.schedule_type),
  },
  {
    title: '状态', key: 'enabled', width: 80,
    render: (row) => h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small' }, () => row.enabled ? '启用' : '停用'),
  },
  {
    title: '扫描模板', key: 'template_id', width: 130, ellipsis: { tooltip: true },
    render: (row) => getTemplateName(row.template_id),
  },
  {
    title: '目标数', key: 'targets', width: 70, align: 'center' as const,
    render: (row) => (row.targets?.length ?? 0).toString(),
  },
  { title: '已执行', key: 'run_count', width: 70, align: 'center' as const },
  {
    title: '上次运行', key: 'last_run_at', width: 160,
    render: (row) => h('span', { style: 'font-size:13px;white-space:nowrap' }, fmtTime(row.last_run_at)),
  },
  {
    title: '下次运行', key: 'next_run_at', width: 160,
    render: (row) => h('span', { style: 'font-size:13px;white-space:nowrap' }, fmtTime(row.next_run_at)),
  },
  {
    title: '操作', key: 'actions', width: 220, fixed: 'right',
    render: (row) => h(NSpace, { size: 8 }, () => [
      h(NButton, { size: 'tiny', text: true, type: 'info', onClick: () => openDetail(row) }, () => '详情'),
      h(NButton, { size: 'tiny', text: true, onClick: () => openEditor(row) }, () => '编辑'),
      h(NButton, {
        size: 'tiny', text: true, type: row.enabled ? 'warning' : 'success',
        onClick: () => handleToggle(row),
      }, () => row.enabled ? '停用' : '启用'),
      h(NButton, { size: 'tiny', text: true, type: 'primary', onClick: () => handleRunNow(row) }, () => '立即执行'),
      h(NPopconfirm, { onPositiveClick: () => handleDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '删除'),
        default: () => '确定删除该调度？',
      }),
    ]),
  },
]);

async function handleToggle(row: ScanSchedule) {
  await toggleSchedule(row.id, !row.enabled);
  message.success(row.enabled ? '已停用' : '已启用');
  fetchData();
}

async function handleRunNow(row: ScanSchedule) {
  const res: any = await runScheduleNow(row.id);
  message.success(`已创建任务 ${res?.task_id ?? ''}`);
  fetchData();
}

async function handleDelete(id: string) {
  await deleteSchedule(id);
  message.success('已删除');
  fetchData();
}

// ---- Editor Modal ----
const editorVisible = ref(false);
const editingId = ref('');
const form = ref({
  name: '',
  description: '',
  template_id: '',
  targets: '',
  schedule_type: 'daily',
  cron_expr: '',
  interval_min: 60,
  weekday: 1,
  day_of_month: 1,
  run_time: '02:00',
  enabled: true,
  engine_preset: '',
});

function openEditor(row?: ScanSchedule) {
  if (row) {
    editingId.value = row.id;
    form.value = {
      name: row.name,
      description: row.description || '',
      template_id: row.template_id || '',
      targets: (row.targets || []).join('\n'),
      schedule_type: row.schedule_type || 'daily',
      cron_expr: row.cron_expr || '',
      interval_min: row.interval_min || 60,
      weekday: row.config?.weekday ?? 1,
      day_of_month: row.config?.day_of_month ?? 1,
      run_time: row.config?.run_time ?? '02:00',
      enabled: row.enabled,
      engine_preset: typeof row.config?.engine_preset === 'string' ? row.config.engine_preset : '',
    };
  } else {
    editingId.value = '';
    form.value = {
      name: '', description: '', template_id: '', targets: '',
      schedule_type: 'daily', cron_expr: '', interval_min: 60,
      weekday: 1, day_of_month: 1, run_time: '02:00', enabled: true,
      engine_preset: '',
    };
  }
  editorVisible.value = true;
}

function handleTemplateSelect(id: string) {
  form.value.template_id = id;
  if (!form.value.name && id) {
    const tmpl = templates.value.find(t => t.id === id);
    if (tmpl) form.value.name = `${tmpl.name} - 定时`;
  }
}

async function handleSave() {
  if (!form.value.template_id) { message.warning('请选择扫描模板'); return; }
  if (!form.value.targets.trim()) { message.warning('请输入至少一个目标'); return; }
  if (form.value.schedule_type === 'cron' && !form.value.cron_expr.trim()) {
    message.warning('请输入 Cron 表达式'); return;
  }

  const targets = form.value.targets.split(/[\n,;]+/).map(t => t.trim()).filter(Boolean);
  const payload: Record<string, any> = {
    name: form.value.name || `调度-${new Date().toLocaleDateString('zh-CN')}`,
    description: form.value.description,
    template_id: form.value.template_id,
    targets,
    schedule_type: form.value.schedule_type,
    enabled: form.value.enabled,
  };

  const scanConfig: Record<string, any> = {};
  if (form.value.engine_preset) {
    scanConfig.engine_preset = form.value.engine_preset;
  }

  if (form.value.schedule_type === 'cron') {
    payload.cron_expr = form.value.cron_expr;
    if (Object.keys(scanConfig).length) {
      payload.config = scanConfig;
    }
  } else if (form.value.schedule_type === 'interval') {
    payload.interval_min = form.value.interval_min;
    if (Object.keys(scanConfig).length) {
      payload.config = scanConfig;
    }
  } else {
    payload.config = {
      run_time: form.value.run_time,
      weekday: form.value.weekday,
      day_of_month: form.value.day_of_month,
      ...scanConfig,
    };
  }

  if (editingId.value) {
    await updateSchedule(editingId.value, payload);
    message.success('已更新');
  } else {
    await createSchedule(payload);
    message.success('已创建');
  }
  editorVisible.value = false;
  fetchData();
}

// ---- Detail Drawer ----
const detailVisible = ref(false);
const detailItem = ref<ScanSchedule | null>(null);

function openDetail(row: ScanSchedule) {
  detailItem.value = row;
  detailVisible.value = true;
}
</script>

<template>
  <div class="schedule-page">
    <NCard size="small">
      <div class="toolbar">
        <div class="toolbar-left">
          <NButton type="primary" @click="openEditor()">
            <template #icon><span style="font-size:16px;line-height:1">+</span></template>
            新建调度
          </NButton>
          <NButton quaternary @click="fetchData">
            <template #icon><span style="font-size:14px">&#8635;</span></template>
          </NButton>
        </div>
        <div class="toolbar-right">
          <NInput
            v-model:value="keyword"
            placeholder="搜索调度名称..."
            style="width:240px"
            clearable
            @keyup.enter="fetchData"
            @clear="fetchData"
          />
        </div>
      </div>

      <NDataTable
        :columns="columns" :data="data" :loading="loading" size="small"
        :bordered="false" striped :scroll-x="1200"
        :pagination="{
          page, pageSize, itemCount: total, showSizePicker: true,
          pageSizes: [20, 50, 100],
          prefix: ({ itemCount }: any) => `共 ${itemCount} 条`,
          onUpdatePage: (p: number) => { page = p; fetchData(); },
          onUpdatePageSize: (s: number) => { pageSize = s; page = 1; fetchData(); },
        }"
      />
    </NCard>

    <!-- Editor Modal -->
    <NModal v-model:show="editorVisible" preset="card" style="width:640px;border-radius:12px" :mask-closable="false">
      <template #header>
        <div class="modal-header">
          <span class="modal-title">{{ editingId ? '编辑调度' : '新建定时调度' }}</span>
          <span class="modal-subtitle">配置周期性扫描计划</span>
        </div>
      </template>

      <NForm label-placement="left" label-width="80" style="margin-top:4px">
        <NFormItem label="扫描模板">
          <NSelect
            v-model:value="form.template_id"
            :options="templateOptions"
            placeholder="选择扫描模板"
            @update:value="handleTemplateSelect"
          />
        </NFormItem>

        <NFormItem label="调度名称">
          <NInput v-model:value="form.name" placeholder="留空将自动生成名称" />
        </NFormItem>

        <NFormItem label="扫描目标">
          <NInput
            v-model:value="form.targets"
            type="textarea"
            placeholder="每行一个目标，支持 IP / 域名 / CIDR / URL&#10;示例: 192.168.1.0/24&#10;      example.com"
            :rows="4"
            style="font-family:'SF Mono',Consolas,monospace;font-size:13px"
          />
        </NFormItem>

        <NFormItem label="引擎预设">
          <NSelect
            v-model:value="form.engine_preset"
            :options="enginePresetOptions"
            placeholder="可选：触发扫描时写入任务 parameters"
            filterable
            clearable
            style="width:100%"
          />
        </NFormItem>

        <NFormItem label="调度类型">
          <NSelect v-model:value="form.schedule_type" :options="scheduleTypeOptions" style="width:200px" />
        </NFormItem>

        <NFormItem v-if="form.schedule_type === 'cron'" label="Cron 表达式">
          <NInput v-model:value="form.cron_expr" placeholder="0 2 * * *  (分 时 日 月 周)" style="width:280px" />
        </NFormItem>

        <NFormItem v-if="form.schedule_type === 'interval'" label="间隔(分钟)">
          <NInputNumber v-model:value="form.interval_min" :min="5" :max="10080" style="width:200px" />
        </NFormItem>

        <NFormItem v-if="form.schedule_type === 'daily'" label="执行时间">
          <NInput v-model:value="form.run_time" placeholder="HH:mm" style="width:120px" />
        </NFormItem>

        <template v-if="form.schedule_type === 'weekly'">
          <NFormItem label="星期">
            <NSelect v-model:value="form.weekday" :options="weekdayOptions" style="width:120px" />
          </NFormItem>
          <NFormItem label="执行时间">
            <NInput v-model:value="form.run_time" placeholder="HH:mm" style="width:120px" />
          </NFormItem>
        </template>

        <template v-if="form.schedule_type === 'monthly'">
          <NFormItem label="日期">
            <NInputNumber v-model:value="form.day_of_month" :min="1" :max="28" style="width:120px" />
          </NFormItem>
          <NFormItem label="执行时间">
            <NInput v-model:value="form.run_time" placeholder="HH:mm" style="width:120px" />
          </NFormItem>
        </template>

        <NFormItem label="描述">
          <NInput v-model:value="form.description" type="textarea" :rows="2" placeholder="可选描述" />
        </NFormItem>

        <NFormItem label="立即启用">
          <NSwitch v-model:value="form.enabled" />
        </NFormItem>
      </NForm>

      <template #action>
        <NSpace justify="end" :size="12">
          <NButton @click="editorVisible = false">取消</NButton>
          <NButton type="primary" @click="handleSave">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Detail Drawer -->
    <NDrawer v-model:show="detailVisible" width="500">
      <NDrawerContent v-if="detailItem" title="调度详情">
        <NDescriptions label-placement="left" :column="1" bordered size="small">
          <NDescriptionsItem label="名称">{{ detailItem.name }}</NDescriptionsItem>
          <NDescriptionsItem label="描述">{{ detailItem.description || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="扫描模板">{{ getTemplateName(detailItem.template_id) }}</NDescriptionsItem>
          <NDescriptionsItem label="引擎预设">{{ detailItem.config?.engine_preset || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="调度类型">{{ scheduleTypeLabel[detailItem.schedule_type] || detailItem.schedule_type }}</NDescriptionsItem>
          <NDescriptionsItem v-if="detailItem.schedule_type === 'cron'" label="Cron 表达式">{{ detailItem.cron_expr }}</NDescriptionsItem>
          <NDescriptionsItem v-if="detailItem.schedule_type === 'interval'" label="间隔(分钟)">{{ detailItem.interval_min }}</NDescriptionsItem>
          <NDescriptionsItem label="目标">
            <NSpace :size="4" wrap>
              <NTag v-for="t in detailItem.targets" :key="t" size="small">{{ t }}</NTag>
            </NSpace>
          </NDescriptionsItem>
          <NDescriptionsItem label="状态">
            <NTag :type="detailItem.enabled ? 'success' : 'default'" size="small">{{ detailItem.enabled ? '已启用' : '已停用' }}</NTag>
          </NDescriptionsItem>
          <NDescriptionsItem label="已执行次数">{{ detailItem.run_count }}</NDescriptionsItem>
          <NDescriptionsItem label="上次运行">{{ fmtTime(detailItem.last_run_at) }}</NDescriptionsItem>
          <NDescriptionsItem label="下次运行">{{ fmtTime(detailItem.next_run_at) }}</NDescriptionsItem>
          <NDescriptionsItem label="创建时间">{{ fmtTime(detailItem.created_at) }}</NDescriptionsItem>
        </NDescriptions>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>

<style scoped>
.schedule-page {
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
</style>
