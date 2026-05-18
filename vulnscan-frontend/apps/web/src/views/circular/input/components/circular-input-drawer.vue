<script lang="ts" setup>
import { computed, ref, watch } from 'vue';
import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NDatePicker,
  NDrawer,
  NDrawerContent,
  NForm,
  NFormItem,
  NInput,
  NSelect,
  NSpace,
  NSpin,
  useMessage,
} from 'naive-ui';

import type { DynamicFormSubmissionDetail, DynamicFormTemplate } from '#/api/formdesign';
import {
  getDynamicFormSubmission,
  getDynamicFormSubmissions,
  getDynamicFormTemplates,
  normalizeFormRule,
  normalizePagedResponse,
} from '#/api/formdesign';
import { createInput, getInputDetail, updateInput } from '#/api/circular';
import OrganizeTreeSelect from '#/components/organize/OrganizeTreeSelect.vue';
import DynamicFormRenderer from '#/components/dynamic-form/DynamicFormRenderer.vue';

defineOptions({ name: 'CircularInputDrawer' });

const props = defineProps<{
  show: boolean;
  editId?: string;
}>();

const emit = defineEmits<{
  'update:show': [value: boolean];
  saved: [];
}>();

const message = useMessage();
const loading = ref(false);
const saving = ref(false);
const templates = ref<DynamicFormTemplate[]>([]);
const selectedTemplate = ref<DynamicFormTemplate | null>(null);
const selectedSubmission = ref<DynamicFormSubmissionDetail | null>(null);
const dynamicFormData = ref<Record<string, any>>({});
const processingDeadlineTs = ref<number | null>(null);

const form = ref({
  title: '',
  circular_template: '',
  organize: null as string | null,
  processing_deadline: '',
  source: 'manual_input',
});

const drawerTitle = computed(() => (props.editId ? '编辑通报' : '新建通报'));
const templateOptions = computed(() =>
  templates.value.map((item) => ({ label: item.name, value: item.id })),
);

function resetForm() {
  form.value = {
    title: '',
    circular_template: '',
    organize: null,
    processing_deadline: '',
    source: 'manual_input',
  };
  processingDeadlineTs.value = null;
  selectedTemplate.value = null;
  selectedSubmission.value = null;
  dynamicFormData.value = {};
}

async function loadTemplates() {
  const res = await getDynamicFormTemplates({
    business: 'incident',
    enabled: 'true',
    page: 1,
    page_size: 100,
  });
  templates.value = normalizePagedResponse<DynamicFormTemplate>(res).items;
}

async function loadSubmission(templateId: string, objectId: string) {
  selectedSubmission.value = null;
  dynamicFormData.value = {};
  if (!templateId || !objectId) return;

  const res = await getDynamicFormSubmissions({
    business: 'incident',
    object_id: objectId,
    page: 1,
    page_size: 1,
    template_id: templateId,
  });
  const item = normalizePagedResponse<{ id: string }>(res).items[0];
  if (!item?.id) return;

  const detail = await getDynamicFormSubmission(item.id);
  selectedSubmission.value = detail;
  dynamicFormData.value = { ...(detail.submission?.form_data || {}) };
}

async function loadDetail() {
  if (!props.editId) return;

  const detail = await getInputDetail(props.editId);
  form.value = {
    title: detail.title || '',
    circular_template: detail.circular_template || '',
    organize: detail.organize || null,
    processing_deadline: detail.processing_deadline || '',
    source: detail.source || 'manual_input',
  };
  if (detail.processing_deadline) {
    const ts = dayjs(detail.processing_deadline).valueOf();
    processingDeadlineTs.value = Number.isNaN(ts) ? null : ts;
  }

  const rows = Array.isArray(detail.circular_data) ? detail.circular_data : [];
  dynamicFormData.value = rows.reduce((acc: Record<string, unknown>, item: Record<string, unknown>) => {
    const field = item?.field ?? item?.name ?? item?.key ?? item?.title;
    if (field) acc[String(field)] = item?.value;
    return acc;
  }, {});

  if (form.value.circular_template) {
    selectedTemplate.value =
      templates.value.find((item) => item.id === form.value.circular_template) || null;
  }

  await loadSubmission(form.value.circular_template, props.editId);
}

function buildCircularData() {
  const schema = selectedSubmission.value?.version?.schema || selectedTemplate.value?.schema;
  const rules = normalizeFormRule(schema);
  return Object.entries(dynamicFormData.value).map(([field, value]) => {
    const rule = rules.find((item: Record<string, unknown>) => item?.field === field);
    const title = String(rule?.title ?? rule?.label ?? field);
    return {
      field,
      title,
      type: 'input',
      value,
    };
  });
}

async function onTemplateChange(templateId: string | null) {
  form.value.circular_template = templateId || '';
  selectedTemplate.value =
    templates.value.find((item) => item.id === form.value.circular_template) || null;
  selectedSubmission.value = null;
  dynamicFormData.value = {};

  if (props.editId && form.value.circular_template) {
    await loadSubmission(form.value.circular_template, props.editId);
  }
}

async function initDrawer() {
  loading.value = true;
  try {
    resetForm();
    await loadTemplates();
    if (!props.editId) {
      const defaultTemplate = templates.value.find((item) => item.is_default) || templates.value[0];
      if (defaultTemplate) {
        form.value.circular_template = defaultTemplate.id;
        selectedTemplate.value = defaultTemplate;
      }
    } else {
      await loadDetail();
    }
  } catch {
    message.error('加载通报表单失败');
  } finally {
    loading.value = false;
  }
}

function close() {
  emit('update:show', false);
}

async function handleSave() {
  if (!form.value.title.trim()) {
    message.warning('请输入标题');
    return;
  }
  if (!form.value.circular_template) {
    message.warning('请选择表单模板');
    return;
  }

  saving.value = true;
  try {
    const processing_deadline = processingDeadlineTs.value
      ? dayjs(processingDeadlineTs.value).format('YYYY-MM-DD HH:mm:ss')
      : '';
    const payload = {
      ...form.value,
      organize: form.value.organize || '',
      processing_deadline,
      circular_data: buildCircularData(),
    };

    if (props.editId) {
      await updateInput(props.editId, payload);
      message.success('更新成功');
    } else {
      await createInput(payload);
      message.success('创建成功');
    }
    emit('saved');
    close();
  } catch (e: unknown) {
    const err = e as { message?: string };
    message.error(err?.message || '保存失败');
  } finally {
    saving.value = false;
  }
}

watch(
  () => [props.show, props.editId] as const,
  ([visible]) => {
    if (visible) void initDrawer();
  },
);
</script>

<template>
  <NDrawer
    :show="show"
    :width="920"
    placement="right"
    @update:show="(v) => emit('update:show', v)"
  >
    <NDrawerContent :title="drawerTitle" closable :native-scrollbar="false">
      <NSpin :show="loading">
        <NForm label-placement="top">
          <NFormItem label="通报标题" required>
            <NInput v-model:value="form.title" placeholder="请输入标题" />
          </NFormItem>
          <NFormItem label="表单模板" required>
            <NSelect
              v-model:value="form.circular_template"
              :options="templateOptions"
              placeholder="选择通报录入模板"
              clearable
              @update:value="onTemplateChange"
            />
          </NFormItem>
          <NFormItem label="所属组织">
            <OrganizeTreeSelect v-model="form.organize" placeholder="请选择所属组织" />
          </NFormItem>
          <NFormItem label="处置期限">
            <NDatePicker
              v-model:value="processingDeadlineTs"
              type="datetime"
              clearable
              style="width: 100%"
              placeholder="请选择处置期限"
            />
          </NFormItem>
        </NForm>

        <div
          v-if="selectedTemplate || selectedSubmission?.version"
          class="circular-input-drawer__dynamic"
        >
          <div class="circular-input-drawer__dynamic-head">
            <span class="circular-input-drawer__dynamic-title">模板字段</span>
            <span v-if="selectedTemplate?.name" class="circular-input-drawer__dynamic-tag">
              {{ selectedTemplate.name }}
            </span>
          </div>
          <DynamicFormRenderer
            v-model="dynamicFormData"
            layout="vertical"
            :schema="selectedSubmission?.version?.schema || selectedTemplate?.schema || {}"
            :options="selectedSubmission?.version?.options || selectedTemplate?.options || {}"
          />
        </div>
      </NSpin>

      <template #footer>
        <NSpace justify="end">
          <NButton @click="close">取消</NButton>
          <NButton type="primary" :loading="saving" @click="handleSave">
            {{ editId ? '保存' : '创建' }}
          </NButton>
        </NSpace>
      </template>
    </NDrawerContent>
  </NDrawer>
</template>

<style scoped>
.circular-input-drawer__dynamic {
  margin-top: 12px;
  padding: 14px 16px 4px;
  border: 1px solid var(--n-border-color);
  border-radius: 8px;
  background: var(--n-color-embedded);
}

.circular-input-drawer__dynamic-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}

.circular-input-drawer__dynamic-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--n-text-color-1);
}

.circular-input-drawer__dynamic-tag {
  font-size: 12px;
  color: var(--n-text-color-3);
  padding: 2px 8px;
  border-radius: 4px;
  background: var(--n-action-color);
}
</style>
