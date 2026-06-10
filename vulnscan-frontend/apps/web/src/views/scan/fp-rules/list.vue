<script setup lang="ts">
import { ref, h, onMounted } from 'vue';
import {
  NCard, NDataTable, NButton, NSpace, NTag, NModal, NForm,
  NFormItem, NInput, NSelect, NSwitch, NPopconfirm,
  useMessage,
} from 'naive-ui';
import type { DataTableColumns } from 'naive-ui';
import {
  getFPRuleList, createFPRule, updateFPRule,
  deleteFPRule, toggleFPRule,
  type FPRule,
} from '#/api/fp-rule';
import { useNaiveTablePagination } from '#/composables/useNaiveTablePagination';

const message = useMessage();
const loading = ref(false);
const data = ref<FPRule[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);

async function fetchData() {
  loading.value = true;
  try {
    const res = await getFPRuleList({ page: page.value, page_size: pageSize.value });
    data.value = res.items;
    total.value = res.total;
  } finally {
    loading.value = false;
  }
}

const { pagination } = useNaiveTablePagination({ page, pageSize, total, onFetch: fetchData });

onMounted(fetchData);

const matchTypeOptions = [
  { label: '指纹匹配', value: 'fingerprint' },
  { label: '目标匹配', value: 'target_type' },
  { label: '模块+类型', value: 'module_type' },
  { label: '标题正则', value: 'title_pattern' },
];

const matchTypeLabel: Record<string, string> = {
  fingerprint: '指纹匹配',
  target_type: '目标匹配',
  module_type: '模块+类型',
  title_pattern: '标题正则',
};

function fmtTime(t: string | null) {
  if (!t) return '-';
  return new Date(t).toLocaleString('zh-CN');
}

const columns: DataTableColumns<FPRule> = [
  { title: '名称', key: 'name', width: 200, ellipsis: { tooltip: true } },
  {
    title: '匹配类型', key: 'match_type', width: 110,
    render: (row) => h(NTag, { size: 'small', type: 'info', bordered: false }, () => matchTypeLabel[row.match_type] || row.match_type),
  },
  { title: '匹配值', key: 'match_value', ellipsis: { tooltip: true } },
  { title: '原因', key: 'reason', width: 180, ellipsis: { tooltip: true } },
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
const form = ref<Partial<FPRule>>({});

function openCreate() {
  modalMode.value = 'create';
  form.value = { match_type: 'fingerprint', enabled: true };
  showModal.value = true;
}

function openEdit(row: FPRule) {
  modalMode.value = 'edit';
  form.value = { ...row };
  showModal.value = true;
}

async function handleSubmit() {
  try {
    if (modalMode.value === 'create') {
      await createFPRule(form.value);
      message.success('创建成功');
    } else {
      await updateFPRule(form.value.id!, form.value);
      message.success('更新成功');
    }
    showModal.value = false;
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

async function handleToggle(row: FPRule) {
  try {
    await toggleFPRule(row.id);
    row.enabled = !row.enabled;
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

async function handleDelete(id: string) {
  try {
    await deleteFPRule(id);
    message.success('已删除');
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}
</script>

<template>
  <div style="padding: 16px">
    <NCard title="误报管理">
      <template #header-extra>
        <NButton type="primary" size="small" @click="openCreate">新建规则</NButton>
      </template>

      <NDataTable
        :columns="columns"
        :data="data"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="900"
        size="small"
        striped
        remote
      />
    </NCard>

    <NModal v-model:show="showModal" preset="card" :title="modalMode === 'create' ? '新建误报规则' : '编辑误报规则'" style="width: 520px">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="名称">
          <NInput v-model:value="form.name" placeholder="规则名称（可选）" />
        </NFormItem>
        <NFormItem label="匹配类型">
          <NSelect v-model:value="form.match_type" :options="matchTypeOptions" />
        </NFormItem>
        <NFormItem label="匹配值">
          <NInput v-model:value="form.match_value" placeholder="如 target:port:module:type" />
        </NFormItem>
        <NFormItem label="原因">
          <NInput v-model:value="form.reason" type="textarea" :rows="2" placeholder="标记为误报的原因" />
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
