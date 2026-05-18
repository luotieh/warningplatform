<script setup lang="ts">
import { h, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import type { DataTableColumns } from 'naive-ui';
import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NSelect,
  NSpace,
  NSwitch,
  NTag,
  useMessage,
} from 'naive-ui';

import type { DynamicFormTemplate } from '#/api/formdesign';
import {
  createDynamicFormTemplate,
  deleteDynamicFormTemplate,
  getDynamicFormTemplates,
  normalizePagedResponse,
  updateDynamicFormTemplate,
} from '#/api/formdesign';

defineOptions({ name: 'FormTemplates' });

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const saving = ref(false);
const showModal = ref(false);
const editingId = ref('');
const templates = ref<DynamicFormTemplate[]>([]);

const businessOptions = [
  { label: '资产', value: 'asset' },
  { label: '通报 / 事件', value: 'incident' },
  { label: '通报（历史）', value: 'circular' },
  { label: '通用', value: 'general' },
];

const searchForm = reactive({
  business: undefined as string | undefined,
  enabled: undefined as string | undefined,
  keyword: '',
  object_type: '',
});

const formState = reactive({
  business: 'asset',
  code: '',
  description: '',
  enabled: true,
  is_default: false,
  name: '',
  object_type: '',
});

const pagination = reactive({
  itemCount: 0,
  onChange: (page: number) => {
    pagination.page = page;
    fetchTemplates();
  },
  onUpdatePageSize: (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.page = 1;
    fetchTemplates();
  },
  page: 1,
  pageSize: 20,
  pageSizes: [10, 20, 50, 100],
  showSizePicker: true,
});

function businessLabel(value: string) {
  return businessOptions.find(item => item.value === value)?.label ?? value;
}

async function fetchTemplates() {
  loading.value = true;
  try {
    const res = await getDynamicFormTemplates({
      business: searchForm.business,
      enabled: searchForm.enabled,
      keyword: searchForm.keyword,
      object_type: searchForm.object_type,
      page: pagination.page,
      page_size: pagination.pageSize,
    });
    const normalized = normalizePagedResponse<DynamicFormTemplate>(res);
    templates.value = normalized.items;
    pagination.itemCount = normalized.total;
  } catch {
    message.error('加载表单模板失败');
  } finally {
    loading.value = false;
  }
}

function onSearch() {
  pagination.page = 1;
  fetchTemplates();
}

function onReset() {
  Object.assign(searchForm, {
    business: undefined,
    enabled: undefined,
    keyword: '',
    object_type: '',
  });
  onSearch();
}

function openCreate() {
  editingId.value = '';
  Object.assign(formState, {
    business: 'asset',
    code: '',
    description: '',
    enabled: true,
    is_default: false,
    name: '',
    object_type: '',
  });
  showModal.value = true;
}

function openEdit(row: DynamicFormTemplate) {
  editingId.value = row.id;
  Object.assign(formState, {
    business: row.business,
    code: row.code,
    description: row.description || '',
    enabled: row.enabled,
    is_default: row.is_default,
    name: row.name,
    object_type: row.object_type || '',
  });
  showModal.value = true;
}

async function saveTemplate() {
  if (!formState.name || !formState.business) {
    message.warning('请填写模板名称和业务归属');
    return;
  }
  saving.value = true;
  try {
    const payload = {
      ...formState,
      schema: editingId.value ? undefined : { rule: [] },
      version: 1,
    };
    if (editingId.value) {
      await updateDynamicFormTemplate(editingId.value, payload);
      message.success('模板已更新');
    } else {
      const created = await createDynamicFormTemplate(payload);
      message.success('模板已创建');
      if (created?.id) {
        router.push({ name: 'FormDesigner', params: { id: created.id } });
      }
    }
    showModal.value = false;
    await fetchTemplates();
  } catch {
    message.error('保存表单模板失败');
  } finally {
    saving.value = false;
  }
}

async function removeTemplate(row: DynamicFormTemplate) {
  try {
    await deleteDynamicFormTemplate(row.id);
    message.success('模板已删除');
    await fetchTemplates();
  } catch {
    message.error('删除表单模板失败');
  }
}

function openDesigner(row: DynamicFormTemplate) {
  router.push({ name: 'FormDesigner', params: { id: row.id } });
}

const columns: DataTableColumns<DynamicFormTemplate> = [
  {
    key: 'name',
    minWidth: 220,
    title: '模板',
    render: row => h('div', { class: 'template-name-cell' }, [
      h('div', { class: 'template-title' }, row.name),
      h('div', { class: 'template-code' }, row.code || '-'),
    ]),
  },
  {
    key: 'business',
    title: '业务',
    width: 110,
    render: row => h(NTag, { bordered: false, size: 'small', type: row.business === 'asset' ? 'info' : 'warning' }, () => businessLabel(row.business)),
  },
  { key: 'object_type', minWidth: 140, title: '对象类型', render: row => row.object_type || '-' },
  {
    align: 'center',
    key: 'enabled',
    title: '启用',
    width: 90,
    render: row => h(NTag, { bordered: false, size: 'small', type: row.enabled ? 'success' : 'default' }, () => row.enabled ? '启用' : '停用'),
  },
  {
    align: 'center',
    key: 'is_default',
    title: '默认',
    width: 90,
    render: row => row.is_default ? h(NTag, { bordered: false, size: 'small', type: 'success' }, () => '默认') : '-',
  },
  { key: 'updated_at', minWidth: 170, title: '更新时间', render: row => row.updated_at?.replace('T', ' ').slice(0, 19) || '-' },
  {
    fixed: 'right',
    key: 'actions',
    title: '操作',
    width: 220,
    render: row => h(NSpace, { size: 6 }, () => [
      h(NButton, { size: 'small', onClick: () => openDesigner(row) }, () => '设计'),
      h(NButton, { size: 'small', onClick: () => openEdit(row) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => removeTemplate(row) }, {
        default: () => `确认删除表单模板「${row.name}」？`,
        trigger: () => h(NButton, { size: 'small', type: 'error' }, () => '删除'),
      }),
    ]),
  },
];

onMounted(fetchTemplates);
</script>

<template>
  <div class="form-templates-page">
    <NCard size="small" title="表单模板">
      <template #header-extra>
        <NSpace :size="8">
          <NButton size="small" @click="fetchTemplates">刷新</NButton>
          <NButton size="small" type="primary" @click="openCreate">新建模板</NButton>
        </NSpace>
      </template>

      <NForm class="template-filter" inline label-placement="left" :show-feedback="false">
        <NFormItem label="关键字">
          <NInput v-model:value="searchForm.keyword" clearable placeholder="名称 / 编码 / 描述" style="width: 220px" />
        </NFormItem>
        <NFormItem label="业务">
          <NSelect v-model:value="searchForm.business" :options="businessOptions" clearable placeholder="全部" style="width: 140px" />
        </NFormItem>
        <NFormItem label="对象类型">
          <NInput v-model:value="searchForm.object_type" clearable placeholder="如 web / server" style="width: 160px" />
        </NFormItem>
        <NFormItem label="状态">
          <NSelect
            v-model:value="searchForm.enabled"
            :options="[{ label: '启用', value: 'true' }, { label: '停用', value: 'false' }]"
            clearable
            placeholder="全部"
            style="width: 120px"
          />
        </NFormItem>
        <NFormItem>
          <NSpace :size="8">
            <NButton type="primary" @click="onSearch">查询</NButton>
            <NButton @click="onReset">重置</NButton>
          </NSpace>
        </NFormItem>
      </NForm>

      <NDataTable
        remote
        :bordered="false"
        :columns="columns"
        :data="templates"
        :loading="loading"
        :pagination="pagination"
        :row-key="(row: DynamicFormTemplate) => row.id"
        :scroll-x="1050"
        size="small"
        striped
      />
    </NCard>

    <NModal
      v-model:show="showModal"
      preset="dialog"
      :title="editingId ? '编辑模板' : '新建模板'"
      style="width: min(620px, calc(100vw - 32px))"
    >
      <NForm class="template-modal-form" label-placement="left" label-width="92" :show-feedback="false">
        <NFormItem label="模板名称" required>
          <NInput v-model:value="formState.name" placeholder="如：资产扩展信息" />
        </NFormItem>
        <NFormItem label="模板编码">
          <NInput v-model:value="formState.code" :disabled="!!editingId" placeholder="留空自动生成" />
        </NFormItem>
        <NFormItem label="业务归属" required>
          <NSelect v-model:value="formState.business" :options="businessOptions" />
        </NFormItem>
        <NFormItem label="对象类型">
          <NInput v-model:value="formState.object_type" placeholder="可选，用于区分资产类型或通报类型" />
        </NFormItem>
        <NFormItem label="默认模板">
          <NSwitch v-model:value="formState.is_default" />
        </NFormItem>
        <NFormItem label="启用">
          <NSwitch v-model:value="formState.enabled" />
        </NFormItem>
        <NFormItem label="说明">
          <NInput v-model:value="formState.description" type="textarea" :rows="3" placeholder="表单适用场景" />
        </NFormItem>
      </NForm>
      <template #action>
        <NSpace>
          <NButton @click="showModal = false">取消</NButton>
          <NButton :loading="saving" type="primary" @click="saveTemplate">保存</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.form-templates-page {
  padding: 16px;
}

.template-filter {
  margin-bottom: 16px;
}

.template-modal-form {
  margin-top: 12px;
}

.template-name-cell {
  min-width: 0;
}

.template-title {
  color: var(--n-text-color);
  font-weight: 500;
  line-height: 1.4;
}

.template-code {
  margin-top: 2px;
  color: var(--n-text-color-3);
  font-size: 12px;
  line-height: 1.35;
}
</style>
