<script setup lang="ts">
import { ref, h, onMounted } from 'vue';
import {
  NCard, NDataTable, NButton, NSpace, NTag, NModal, NForm,
  NFormItem, NInput, NSelect, NSwitch, NPopconfirm,
  useMessage,
} from 'naive-ui';
import type { DataTableColumns } from 'naive-ui';
import {
  getExclusionList, createExclusion, updateExclusion,
  deleteExclusion, toggleExclusion,
  type ScanExclusion,
} from '#/api/scan-exclusion';

const message = useMessage();
const loading = ref(false);
const data = ref<ScanExclusion[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);

async function fetchData() {
  loading.value = true;
  try {
    const res = await getExclusionList({ page: page.value, page_size: pageSize.value });
    data.value = res.items;
    total.value = res.total;
  } finally {
    loading.value = false;
  }
}

onMounted(fetchData);

const ruleTypeOptions = [
  { label: '目标地址', value: 'target' },
  { label: '端口', value: 'port' },
  { label: '路径', value: 'path' },
  { label: '模块', value: 'module' },
  { label: '发现类型', value: 'finding_type' },
];

const scopeOptions = [
  { label: '全局', value: 'global' },
];

const ruleTypeLabel: Record<string, string> = {
  target: '目标地址',
  port: '端口',
  path: '路径',
  module: '模块',
  finding_type: '发现类型',
};

const ruleTypeColor: Record<string, string> = {
  target: 'error',
  port: 'warning',
  path: 'info',
  module: 'success',
  finding_type: 'default',
};

function fmtTime(t: string | null) {
  if (!t) return '-';
  return new Date(t).toLocaleString('zh-CN');
}

const columns: DataTableColumns<ScanExclusion> = [
  { title: '名称', key: 'name', width: 180 },
  {
    title: '规则类型', key: 'rule_type', width: 110,
    render: (row) => h(NTag, { size: 'small', type: ruleTypeColor[row.rule_type] as any, bordered: false }, () => ruleTypeLabel[row.rule_type] || row.rule_type),
  },
  { title: '匹配值', key: 'match_value', ellipsis: { tooltip: true } },
  { title: '作用域', key: 'scope', width: 100 },
  {
    title: '状态', key: 'enabled', width: 80,
    render: (row) => h(NSwitch, {
      value: row.enabled,
      onUpdateValue: () => handleToggle(row),
    }),
  },
  { title: '命中', key: 'hit_count', width: 70 },
  { title: '创建时间', key: 'created_at', width: 170, render: (row) => fmtTime(row.created_at) },
  {
    title: '操作', key: 'actions', width: 150, fixed: 'right',
    render: (row) => h(NSpace, { size: 'small' }, () => [
      h(NButton, { size: 'tiny', quaternary: true, type: 'info', onClick: () => openEdit(row) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => handleDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'tiny', quaternary: true, type: 'error' }, () => '删除'),
        default: () => '确认删除此规则？',
      }),
    ]),
  },
];

const showModal = ref(false);
const modalMode = ref<'create' | 'edit'>('create');
const form = ref<Partial<ScanExclusion>>({});

function openCreate() {
  modalMode.value = 'create';
  form.value = { rule_type: 'target', scope: 'global', enabled: true };
  showModal.value = true;
}

function openEdit(row: ScanExclusion) {
  modalMode.value = 'edit';
  form.value = { ...row };
  showModal.value = true;
}

async function handleSubmit() {
  try {
    if (modalMode.value === 'create') {
      await createExclusion(form.value);
      message.success('创建成功');
    } else {
      await updateExclusion(form.value.id!, form.value);
      message.success('更新成功');
    }
    showModal.value = false;
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

async function handleToggle(row: ScanExclusion) {
  try {
    await toggleExclusion(row.id);
    row.enabled = !row.enabled;
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

async function handleDelete(id: string) {
  try {
    await deleteExclusion(id);
    message.success('已删除');
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}
</script>

<template>
  <div style="padding: 16px">
    <NCard title="扫描排除规则">
      <template #header-extra>
        <NButton type="primary" size="small" @click="openCreate">新建规则</NButton>
      </template>

      <NDataTable
        :columns="columns"
        :data="data"
        :loading="loading"
        :pagination="{
          page,
          pageSize,
          itemCount: total,
          onUpdatePage: (p: number) => { page = p; fetchData(); },
          onUpdatePageSize: (s: number) => { pageSize = s; page = 1; fetchData(); },
          showSizePicker: true,
          pageSizes: [10, 20, 50],
        }"
        :scroll-x="900"
        size="small"
        striped
      />
    </NCard>

    <NModal v-model:show="showModal" preset="card" :title="modalMode === 'create' ? '新建排除规则' : '编辑排除规则'" style="width: 520px">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="名称">
          <NInput v-model:value="form.name" placeholder="规则名称" />
        </NFormItem>
        <NFormItem label="规则类型">
          <NSelect v-model:value="form.rule_type" :options="ruleTypeOptions" />
        </NFormItem>
        <NFormItem label="匹配值">
          <NInput v-model:value="form.match_value" placeholder="支持通配符，如 192.168.1.* 或 *.internal.com" />
        </NFormItem>
        <NFormItem label="作用域">
          <NSelect v-model:value="form.scope" :options="scopeOptions" />
        </NFormItem>
        <NFormItem label="描述">
          <NInput v-model:value="form.description" type="textarea" :rows="2" placeholder="可选" />
        </NFormItem>
        <NFormItem>
          <NSpace>
            <NButton type="primary" @click="handleSubmit">确定</NButton>
            <NButton @click="showModal = false">取消</NButton>
          </NSpace>
        </NFormItem>
      </NForm>
    </NModal>
  </div>
</template>
