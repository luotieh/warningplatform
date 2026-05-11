<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from 'vue';

import type { DataTableColumns } from 'naive-ui';
import {
  NButton,
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NSelect,
  NSpace,
  NTag,
  useMessage,
} from 'naive-ui';

import type {
  DynamicFormSubmission,
  DynamicFormSubmissionDetail,
  DynamicFormTemplate,
} from '#/api/form';
import {
  deleteDynamicFormSubmission,
  getDynamicFormSubmission,
  getDynamicFormSubmissions,
  getDynamicFormTemplates,
  normalizePagedResponse,
} from '#/api/form';
import DynamicFormRenderer from '#/components/dynamic-form/DynamicFormRenderer.vue';

defineOptions({ name: 'FormSubmissions' });

const message = useMessage();
const loading = ref(false);
const detailLoading = ref(false);
const templateLoading = ref(false);
const showDetail = ref(false);
const submissions = ref<DynamicFormSubmission[]>([]);
const templates = ref<DynamicFormTemplate[]>([]);
const currentDetail = ref<DynamicFormSubmissionDetail | null>(null);

const businessOptions = [
  { label: '资产', value: 'asset' },
  { label: '通报', value: 'incident' },
];

const searchForm = reactive({
  business: undefined as string | undefined,
  object_id: '',
  object_type: '',
  template_id: undefined as string | undefined,
});

const pagination = reactive({
  itemCount: 0,
  onChange: (page: number) => {
    pagination.page = page;
    fetchSubmissions();
  },
  onUpdatePageSize: (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.page = 1;
    fetchSubmissions();
  },
  page: 1,
  pageSize: 20,
  pageSizes: [10, 20, 50, 100],
  showSizePicker: true,
});

const current = computed(() => currentDetail.value?.submission);
const currentVersion = computed(() => currentDetail.value?.version);
const templateOptions = computed(() => templates.value.map(item => ({
  label: `${item.name} (${businessLabel(item.business)})`,
  value: item.id,
})));

function businessLabel(value: string) {
  return businessOptions.find(item => item.value === value)?.label ?? value;
}

function templateName(id: string) {
  return templates.value.find(item => item.id === id)?.name ?? id;
}

async function fetchTemplates() {
  templateLoading.value = true;
  try {
    const res = await getDynamicFormTemplates({ enabled: 'true', page: 1, page_size: 100 });
    templates.value = normalizePagedResponse<DynamicFormTemplate>(res).items;
  } finally {
    templateLoading.value = false;
  }
}

async function fetchSubmissions() {
  loading.value = true;
  try {
    const res = await getDynamicFormSubmissions({
      business: searchForm.business,
      object_id: searchForm.object_id,
      object_type: searchForm.object_type,
      page: pagination.page,
      page_size: pagination.pageSize,
      template_id: searchForm.template_id,
    });
    const normalized = normalizePagedResponse<DynamicFormSubmission>(res);
    submissions.value = normalized.items;
    pagination.itemCount = normalized.total;
  } catch {
    message.error('加载表单数据失败');
  } finally {
    loading.value = false;
  }
}

function onSearch() {
  pagination.page = 1;
  fetchSubmissions();
}

function onReset() {
  Object.assign(searchForm, {
    business: undefined,
    object_id: '',
    object_type: '',
    template_id: undefined,
  });
  onSearch();
}

async function openDetail(row: DynamicFormSubmission) {
  showDetail.value = true;
  detailLoading.value = true;
  try {
    currentDetail.value = await getDynamicFormSubmission(row.id);
  } catch {
    message.error('加载表单数据详情失败');
  } finally {
    detailLoading.value = false;
  }
}

async function removeSubmission(row: DynamicFormSubmission) {
  try {
    await deleteDynamicFormSubmission(row.id);
    message.success('表单数据已删除');
    await fetchSubmissions();
  } catch {
    message.error('删除表单数据失败');
  }
}

function formatDate(value?: string) {
  return value?.replace('T', ' ').slice(0, 19) || '-';
}

const columns: DataTableColumns<DynamicFormSubmission> = [
  { key: 'template_id', minWidth: 220, title: '模板', render: row => templateName(row.template_id) },
  {
    key: 'business',
    title: '业务',
    width: 100,
    render: row => h(NTag, { bordered: false, size: 'small', type: row.business === 'asset' ? 'info' : 'warning' }, () => businessLabel(row.business)),
  },
  { key: 'object_type', minWidth: 120, title: '对象类型', render: row => row.object_type || '-' },
  { key: 'object_id', minWidth: 220, title: '对象ID', ellipsis: { tooltip: true } },
  { key: 'version', title: '填写版本', width: 100, render: row => `v${row.version || 1}` },
  { key: 'updated_at', minWidth: 170, title: '更新时间', render: row => formatDate(row.updated_at) },
  {
    fixed: 'right',
    key: 'actions',
    title: '操作',
    width: 150,
    render: row => h(NSpace, { size: 6 }, () => [
      h(NButton, { size: 'small', onClick: () => openDetail(row) }, () => '查看'),
      h(NPopconfirm, { onPositiveClick: () => removeSubmission(row) }, {
        default: () => '确认删除这条表单数据？',
        trigger: () => h(NButton, { size: 'small', type: 'error' }, () => '删除'),
      }),
    ]),
  },
];

onMounted(async () => {
  await fetchTemplates();
  await fetchSubmissions();
});
</script>

<template>
  <div class="form-submissions-page">
    <NCard size="small" title="表单数据">
      <template #header-extra>
        <NButton size="small" @click="fetchSubmissions">刷新</NButton>
      </template>

      <NForm class="submission-filter" inline label-placement="left" :show-feedback="false">
        <NFormItem label="模板">
          <NSelect
            v-model:value="searchForm.template_id"
            :loading="templateLoading"
            :options="templateOptions"
            clearable
            filterable
            placeholder="全部"
            style="width: 240px"
          />
        </NFormItem>
        <NFormItem label="业务">
          <NSelect v-model:value="searchForm.business" :options="businessOptions" clearable placeholder="全部" style="width: 140px" />
        </NFormItem>
        <NFormItem label="对象类型">
          <NInput v-model:value="searchForm.object_type" clearable placeholder="可选" style="width: 150px" />
        </NFormItem>
        <NFormItem label="对象ID">
          <NInput v-model:value="searchForm.object_id" clearable placeholder="业务对象 ID" style="width: 220px" />
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
        :data="submissions"
        :loading="loading"
        :pagination="pagination"
        :row-key="(row: DynamicFormSubmission) => row.id"
        :scroll-x="1120"
        size="small"
        striped
      />
    </NCard>

    <NModal
      v-model:show="showDetail"
      preset="card"
      title="表单数据详情"
      style="width: min(860px, calc(100vw - 32px))"
    >
      <NCard :bordered="false" size="small" :loading="detailLoading">
        <NDescriptions v-if="current" bordered :column="2" size="small">
          <NDescriptionsItem label="模板">{{ templateName(current.template_id) }}</NDescriptionsItem>
          <NDescriptionsItem label="业务">{{ businessLabel(current.business) }}</NDescriptionsItem>
          <NDescriptionsItem label="对象类型">{{ current.object_type || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="对象ID">{{ current.object_id }}</NDescriptionsItem>
          <NDescriptionsItem label="填写版本">v{{ current.version || currentVersion?.version || 1 }}</NDescriptionsItem>
          <NDescriptionsItem label="更新时间">{{ formatDate(current.updated_at) }}</NDescriptionsItem>
        </NDescriptions>

        <div v-if="currentVersion?.id" class="version-note">
          该数据按填写时的 v{{ currentVersion.version }} 表单快照渲染，后续模板变更不会影响历史展示。
        </div>
        <DynamicFormRenderer
          v-if="current"
          v-model="current.form_data"
          readonly
          :schema="currentVersion?.schema || {}"
          :options="currentVersion?.options || {}"
          class="submission-renderer"
        />
        <pre v-if="current && !currentVersion?.id" class="submission-json">{{ JSON.stringify(current.form_data || {}, null, 2) }}</pre>
      </NCard>
    </NModal>
  </div>
</template>

<style scoped>
.form-submissions-page {
  padding: 16px;
}

.submission-filter {
  margin-bottom: 16px;
}

.version-note {
  margin: 12px 0;
  padding: 8px 10px;
  color: var(--n-text-color-2);
  font-size: 12px;
  background: var(--n-color-embedded);
  border: 1px solid var(--n-border-color);
  border-radius: 6px;
}

.submission-renderer {
  margin-top: 12px;
}

.submission-json {
  max-height: 420px;
  margin: 16px 0 0;
  padding: 12px;
  overflow: auto;
  color: var(--n-text-color);
  font-size: 12px;
  line-height: 1.55;
  background: var(--n-color-embedded);
  border: 1px solid var(--n-border-color);
  border-radius: 6px;
}
</style>
