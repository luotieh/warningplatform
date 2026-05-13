<script setup lang="ts">
import { ref, computed, h, onMounted } from 'vue';
import {
  NCard, NDataTable, NButton, NSpace, NTag, NModal, NForm,
  NInput, NSelect, NInputNumber, NSwitch, NPopconfirm,
  NGrid, NFormItemGi, useMessage, NDynamicTags, NDescriptions,
  NDescriptionsItem, NDrawer, NDrawerContent,
} from 'naive-ui';
import type { DataTableColumns } from 'naive-ui';
import {
  getScheduleList, createSchedule, updateSchedule,
  deleteSchedule, toggleSchedule, runScheduleNow,
  type ScanSchedule,
} from '#/api/schedule';

const message = useMessage();
const loading = ref(false);
const data = ref<ScanSchedule[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');

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

onMounted(fetchData);

const scheduleTypeOptions = [
  { label: 'Cron 表达式', value: 'cron' },
  { label: '固定间隔', value: 'interval' },
  { label: '每天', value: 'daily' },
  { label: '每周', value: 'weekly' },
  { label: '每月', value: 'monthly' },
];

const profileOptions = [
  { label: '快速扫描', value: 'quick' },
  { label: '标准扫描', value: 'standard' },
  { label: '深度扫描', value: 'full' },
  { label: '仅发现', value: 'discover' },
  { label: '仅漏洞', value: 'vuln' },
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

const columns = computed<DataTableColumns<ScanSchedule>>(() => [
  { title: '名称', key: 'name', width: 180, ellipsis: { tooltip: true } },
  {
    title: '调度类型', key: 'schedule_type', width: 120,
    render: (row) => h(NTag, { size: 'small', bordered: false }, () => scheduleTypeLabel[row.schedule_type] || row.schedule_type),
  },
  {
    title: '状态', key: 'enabled', width: 80,
    render: (row) => h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small' }, () => row.enabled ? '已启用' : '已停用'),
  },
  { title: '模板', key: 'template_name', width: 120, ellipsis: { tooltip: true } },
  {
    title: '目标数', key: 'targets', width: 80,
    render: (row) => (row.targets?.length ?? 0).toString(),
  },
  { title: '已执行', key: 'run_count', width: 80 },
  {
    title: '上次运行', key: 'last_run_at', width: 160,
    render: (row) => fmtTime(row.last_run_at),
  },
  {
    title: '下次运行', key: 'next_run_at', width: 160,
    render: (row) => fmtTime(row.next_run_at),
  },
  {
    title: '操作', key: 'actions', width: 260, fixed: 'right',
    render: (row) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', quaternary: true, type: 'info', onClick: () => openDetail(row) }, () => '详情'),
      h(NButton, { size: 'tiny', quaternary: true, onClick: () => openEditor(row) }, () => '编辑'),
      h(NButton, {
        size: 'tiny', quaternary: true, type: row.enabled ? 'warning' : 'success',
        onClick: () => handleToggle(row),
      }, () => row.enabled ? '停用' : '启用'),
      h(NButton, { size: 'tiny', quaternary: true, type: 'primary', onClick: () => handleRunNow(row) }, () => '立即执行'),
      h(NPopconfirm, { onPositiveClick: () => handleDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'tiny', quaternary: true, type: 'error' }, () => '删除'),
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
const form = ref<Record<string, any>>({
  name: '', description: '', template_name: '', targets: [],
  schedule_type: 'daily', cron_expr: '', interval_min: 60,
  config: { profile: 'standard' }, enabled: true,
});

function openEditor(row?: ScanSchedule) {
  if (row) {
    editingId.value = row.id;
    form.value = {
      name: row.name, description: row.description,
      template_name: row.template_name, targets: [...(row.targets || [])],
      schedule_type: row.schedule_type, cron_expr: row.cron_expr,
      interval_min: row.interval_min, config: { ...row.config },
      enabled: row.enabled,
    };
  } else {
    editingId.value = '';
    form.value = {
      name: '', description: '', template_name: '', targets: [],
      schedule_type: 'daily', cron_expr: '', interval_min: 60,
      config: { profile: 'standard' }, enabled: true,
    };
  }
  editorVisible.value = true;
}

async function handleSave() {
  if (!form.value.name) { message.warning('请输入名称'); return; }
  if (!form.value.targets?.length) { message.warning('请输入至少一个目标'); return; }

  const payload = { ...form.value };
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
  <div class="p-4">
    <NCard title="定时调度" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NInput v-model:value="keyword" size="small" placeholder="搜索名称" clearable style="width:200px" @keyup.enter="fetchData" />
          <NButton size="small" @click="fetchData">搜索</NButton>
          <NButton size="small" type="primary" @click="openEditor()">新建调度</NButton>
        </NSpace>
      </template>
      <NDataTable
        :columns="columns" :data="data" :loading="loading" size="small"
        :scroll-x="1200" :pagination="{
          page, pageSize, itemCount: total, showSizePicker: true,
          pageSizes: [10, 20, 50],
          onUpdatePage: (p: number) => { page = p; fetchData(); },
          onUpdatePageSize: (s: number) => { pageSize = s; page = 1; fetchData(); },
        }"
      />
    </NCard>

    <!-- Editor Modal -->
    <NModal v-model:show="editorVisible" preset="card" :title="editingId ? '编辑调度' : '新建调度'" style="width:680px">
      <NForm :model="form" label-placement="left" label-width="100">
        <NGrid :cols="2" :x-gap="16">
          <NFormItemGi label="名称" span="2">
            <NInput v-model:value="form.name" placeholder="调度名称" />
          </NFormItemGi>
          <NFormItemGi label="描述" span="2">
            <NInput v-model:value="form.description" type="textarea" :rows="2" placeholder="可选描述" />
          </NFormItemGi>
          <NFormItemGi label="模板名称">
            <NInput v-model:value="form.template_name" placeholder="引用模板" />
          </NFormItemGi>
          <NFormItemGi label="扫描配置">
            <NSelect v-model:value="form.config.profile" :options="profileOptions" />
          </NFormItemGi>
          <NFormItemGi label="目标列表" span="2">
            <NDynamicTags v-model:value="form.targets" />
          </NFormItemGi>
          <NFormItemGi label="调度类型">
            <NSelect v-model:value="form.schedule_type" :options="scheduleTypeOptions" />
          </NFormItemGi>
          <NFormItemGi v-if="form.schedule_type === 'cron'" label="Cron 表达式">
            <NInput v-model:value="form.cron_expr" placeholder="0 2 * * *" />
          </NFormItemGi>
          <NFormItemGi v-if="form.schedule_type === 'interval'" label="间隔(分钟)">
            <NInputNumber v-model:value="form.interval_min" :min="1" style="width:100%" />
          </NFormItemGi>
          <NFormItemGi label="立即启用">
            <NSwitch v-model:value="form.enabled" />
          </NFormItemGi>
        </NGrid>
      </NForm>
      <template #footer>
        <NSpace justify="end">
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
          <NDescriptionsItem label="调度类型">{{ scheduleTypeLabel[detailItem.schedule_type] || detailItem.schedule_type }}</NDescriptionsItem>
          <NDescriptionsItem v-if="detailItem.schedule_type === 'cron'" label="Cron 表达式">{{ detailItem.cron_expr }}</NDescriptionsItem>
          <NDescriptionsItem v-if="detailItem.schedule_type === 'interval'" label="间隔(分钟)">{{ detailItem.interval_min }}</NDescriptionsItem>
          <NDescriptionsItem label="模板">{{ detailItem.template_name || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="目标">
            <NSpace :size="4">
              <NTag v-for="t in detailItem.targets" :key="t" size="small">{{ t }}</NTag>
            </NSpace>
          </NDescriptionsItem>
          <NDescriptionsItem label="扫描配置">{{ detailItem.config?.profile || '-' }}</NDescriptionsItem>
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
