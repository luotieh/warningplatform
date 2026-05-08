<script lang="ts" setup>
import type { DataTableColumns, DataTableRowKey } from 'naive-ui';

import type { FieldDef } from '#/api/monitor';

import { computed, h, ref, watch } from 'vue';

import {
  NButton,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NSelect,
  NSpace,
  NTag,
} from 'naive-ui';

import { message } from '#/adapter/naive';

const props = defineProps<{
  fields: FieldDef[];
  label: string;
  modelValue: Record<string, any>[];
  sectionKey: string;
}>();

const emit = defineEmits<{
  (e: 'update:modelValue', val: Record<string, any>[]): void;
}>();

const SEVERITY_OPTIONS = [
  { label: '严重', value: 'critical' },
  { label: '高', value: 'high' },
  { label: '中', value: 'medium' },
  { label: '低', value: 'low' },
];

const SEVERITY_LABEL_MAP: Record<string, string> = {
  critical: '严重',
  high: '高',
  low: '低',
  medium: '中',
};

const severityTagType = (
  v: string,
): 'default' | 'error' | 'info' | 'primary' | 'warning' => {
  if (v === 'critical') return 'error';
  if (v === 'high') return 'warning';
  if (v === 'medium') return 'primary';
  return 'info';
};

const severityLabel = (v: string) => SEVERITY_LABEL_MAP[v] || v || '-';

const localItems = ref<Record<string, any>[]>([]);

watch(
  () => props.modelValue,
  (val) => {
    localItems.value = val ? JSON.parse(JSON.stringify(val)) : [];
  },
  { deep: true, immediate: true },
);

const dialogVisible = ref(false);
const dialogTitle = ref('新增条目');
const editingIndex = ref(-1);
const formData = ref<Record<string, any>>({});

function initFormData() {
  const obj: Record<string, any> = {};
  for (const f of props.fields) {
    if (f.type === 'severity') obj[f.key] = 'medium';
    else if (f.type === 'risk') obj[f.key] = 'high';
    else obj[f.key] = '';
  }
  return obj;
}

function handleAdd() {
  dialogTitle.value = '新增条目';
  editingIndex.value = -1;
  formData.value = initFormData();
  dialogVisible.value = true;
}

function handleEdit(index: number) {
  dialogTitle.value = '编辑条目';
  editingIndex.value = index;
  formData.value = { ...localItems.value[index] };
  dialogVisible.value = true;
}

function handleSubmit() {
  for (const f of props.fields) {
    if (f.required && !String(formData.value[f.key] || '').trim()) {
      message.warning(`${f.label} 不能为空`);
      return;
    }
    if (f.type === 'regex' && formData.value[f.key]) {
      try {
        new RegExp(formData.value[f.key]);
      } catch {
        message.warning(`${f.label} 正则表达式无效`);
        return;
      }
    }
  }

  const newItems = [...localItems.value];
  if (editingIndex.value >= 0) {
    newItems[editingIndex.value] = { ...formData.value };
  } else {
    newItems.push({ ...formData.value });
  }
  localItems.value = newItems;
  emit('update:modelValue', newItems);
  dialogVisible.value = false;
}

function handleDelete(index: number) {
  const newItems = localItems.value.filter((_, i) => i !== index);
  localItems.value = newItems;
  emit('update:modelValue', newItems);
}

const selectedKeys = ref<DataTableRowKey[]>([]);

function handleBatchDelete() {
  if (selectedKeys.value.length === 0) return;
  const set = new Set(selectedKeys.value as number[]);
  const newItems = localItems.value.filter((_, i) => !set.has(i));
  localItems.value = newItems;
  selectedKeys.value = [];
  emit('update:modelValue', newItems);
}

const itemCount = computed(() => localItems.value.length);

const columns = computed<DataTableColumns<Record<string, any>>>(() => {
  const cols: DataTableColumns<Record<string, any>> = [
    { type: 'selection' },
    {
      key: '__index',
      title: '#',
      width: 55,
      align: 'center',
      render: (_row, index) => index + 1,
    },
  ];

  for (const field of props.fields) {
    if (field.type === 'severity' || field.type === 'risk') {
      cols.push({
        key: field.key,
        title: field.label,
        width: 100,
        align: 'center',
        render: (row) =>
          h(
            NTag,
            {
              type: severityTagType(row[field.key]),
              size: 'small',
              bordered: false,
            },
            { default: () => severityLabel(row[field.key]) },
          ),
      });
    } else {
      cols.push({
        key: field.key,
        title: field.label,
        minWidth: field.type === 'regex' ? 250 : 150,
        ellipsis: { tooltip: true },
      });
    }
  }

  cols.push({
    key: '__op',
    title: '操作',
    width: 130,
    align: 'center',
    fixed: 'right',
    render: (_row, index) =>
      h(NSpace, { size: 'small', justify: 'center' }, () => [
        h(
          NButton,
          {
            text: true,
            type: 'primary',
            size: 'small',
            onClick: () => handleEdit(index),
          },
          { default: () => '编辑' },
        ),
        h(
          NPopconfirm,
          { onPositiveClick: () => handleDelete(index) },
          {
            trigger: () =>
              h(
                NButton,
                { text: true, type: 'error', size: 'small' },
                { default: () => '删除' },
              ),
            default: () => '确认删除？',
          },
        ),
      ]),
  });

  return cols;
});

</script>

<template>
  <div>
    <NSpace justify="space-between" align="center" class="mb-3">
      <span class="text-muted-foreground text-sm">共 {{ itemCount }} 条</span>
      <NSpace>
        <NButton
          v-if="selectedKeys.length > 0"
          type="error"
          size="small"
          @click="handleBatchDelete"
        >
          批量删除 ({{ selectedKeys.length }})
        </NButton>
        <NButton type="primary" size="small" @click="handleAdd">
          新增条目
        </NButton>
      </NSpace>
    </NSpace>

    <NDataTable
      :columns="columns"
      :data="localItems"
      :max-height="500"
      :row-key="(row: Record<string, any>) => localItems.indexOf(row)"
      size="small"
      striped
      @update:checked-row-keys="(keys: DataTableRowKey[]) => (selectedKeys = keys)"
    />

    <NModal
      v-model:show="dialogVisible"
      preset="card"
      :title="dialogTitle"
      style="width: 550px"
    >
      <NForm
        :model="formData"
        label-placement="left"
        :label-width="100"
      >
        <NFormItem
          v-for="field in fields"
          :key="field.key"
          :label="field.label"
          :required="field.required"
        >
          <NSelect
            v-if="field.type === 'severity' || field.type === 'risk'"
            v-model:value="formData[field.key]"
            :options="SEVERITY_OPTIONS"
          />
          <NInput
            v-else-if="field.type === 'regex'"
            v-model:value="formData[field.key]"
            type="textarea"
            :rows="2"
            :placeholder="`请输入${field.label}`"
            class="font-mono"
          />
          <NInput
            v-else
            v-model:value="formData[field.key]"
            :placeholder="`请输入${field.label}`"
          />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="dialogVisible = false">取消</NButton>
          <NButton type="primary" @click="handleSubmit">确定</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>
