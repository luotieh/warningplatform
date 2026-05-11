<script lang="ts" setup>
import { computed, onMounted, ref } from 'vue';
import { NButton, NCard, NForm, NFormItem, NInput, NSelect, NSpace, NSpin, useMessage } from 'naive-ui';
import { useRoute, useRouter } from 'vue-router';

import type { DynamicFormSubmissionDetail, DynamicFormTemplate } from '#/api/form';
import {
  getDynamicFormSubmission,
  getDynamicFormSubmissions,
  getDynamicFormTemplates,
  normalizePagedResponse,
} from '#/api/form';
import {
  createInput,
  updateInput,
  getInputDetail,
} from '#/api/circular';
import DynamicFormRenderer from '#/components/dynamic-form/DynamicFormRenderer.vue';

defineOptions({ name: 'CircularInputAdd' });

const route = useRoute();
const router = useRouter();
const message = useMessage();

const editId = ref((route.query.id as string) || '');
const loading = ref(false);
const saving = ref(false);
const templates = ref<DynamicFormTemplate[]>([]);
const selectedTemplate = ref<DynamicFormTemplate | null>(null);
const selectedSubmission = ref<DynamicFormSubmissionDetail | null>(null);
const dynamicFormData = ref<Record<string, any>>({});

const form = ref({
  title: '',
  circular_template: '',
  organize: '',
  processing_deadline: '',
  source: 'manual_input',
});

const templateOptions = computed(() =>
  templates.value.map(item => ({
    label: item.name,
    value: item.id,
  })),
);

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
  const item = normalizePagedResponse<any>(res).items[0];
  if (!item?.id) return;

  const detail = await getDynamicFormSubmission(item.id);
  selectedSubmission.value = detail;
  dynamicFormData.value = { ...(detail.submission?.form_data || {}) };
}

async function loadDetail() {
  if (!editId.value) return;

  const detail = await getInputDetail(editId.value) as any;
  form.value = {
    title: detail.title || '',
    circular_template: detail.circular_template || '',
    organize: detail.organize || '',
    processing_deadline: detail.processing_deadline || '',
    source: detail.source || 'manual_input',
  };

  const rows = Array.isArray(detail.circular_data) ? detail.circular_data : [];
  dynamicFormData.value = rows.reduce((acc: Record<string, any>, item: any) => {
    const field = item?.field || item?.name || item?.key || item?.title;
    if (field) {
      acc[field] = item?.value;
    }
    return acc;
  }, {});

  if (form.value.circular_template) {
    selectedTemplate.value =
      templates.value.find(item => item.id === form.value.circular_template) || null;
  }

  await loadSubmission(form.value.circular_template, editId.value);
  if (!selectedSubmission.value && Object.keys(dynamicFormData.value).length === 0) {
    dynamicFormData.value = {};
  }
}

function buildCircularData() {
  return Object.entries(dynamicFormData.value).map(([field, value]) => ({
    field,
    value,
  }));
}

async function onTemplateChange(templateId: string | null) {
  form.value.circular_template = templateId || '';
  selectedTemplate.value =
    templates.value.find(item => item.id === form.value.circular_template) || null;
  selectedSubmission.value = null;
  dynamicFormData.value = {};

  if (editId.value && form.value.circular_template) {
    await loadSubmission(form.value.circular_template, editId.value);
  }
}

async function handleSave() {
  if (!form.value.title) {
    message.warning('请输入标题');
    return;
  }
  if (!form.value.circular_template) {
    message.warning('请选择表单模板');
    return;
  }

  saving.value = true;
  try {
    const payload = {
      ...form.value,
      circular_data: buildCircularData(),
    };

    if (editId.value) {
      await updateInput(editId.value, payload);
      message.success('更新成功');
    } else {
      await createInput(payload);
      message.success('创建成功');
    }
    router.push('/circular/input');
  } catch (e: any) {
    message.error(e?.message || '保存失败');
  } finally {
    saving.value = false;
  }
}

onMounted(async () => {
  loading.value = true;
  try {
    await loadTemplates();
    if (!editId.value) {
      const defaultTemplate = templates.value.find(item => item.is_default) || templates.value[0];
      if (defaultTemplate) {
        form.value.circular_template = defaultTemplate.id;
        selectedTemplate.value = defaultTemplate;
      }
    }
    await loadDetail();
  } catch {
    message.error('加载通报模板失败');
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <div style="padding: 16px; max-width: 960px; margin: 0 auto">
    <NSpin :show="loading">
      <NCard :title="editId ? '编辑通报' : '新建通报'" size="small">
        <NForm label-placement="left" label-width="100">
          <NFormItem label="通报标题" required>
            <NInput v-model:value="form.title" placeholder="请输入标题" />
          </NFormItem>
          <NFormItem label="表单模板" required>
            <NSelect
              v-model:value="form.circular_template"
              :options="templateOptions"
              placeholder="选择 incident 业务模板"
              clearable
              @update:value="onTemplateChange"
            />
          </NFormItem>
          <NFormItem label="所属组织">
            <NInput v-model:value="form.organize" placeholder="请输入组织" />
          </NFormItem>
          <NFormItem label="处置期限">
            <NInput v-model:value="form.processing_deadline" placeholder="YYYY-MM-DD" />
          </NFormItem>
        </NForm>

        <NCard
          v-if="selectedTemplate || selectedSubmission?.version"
          size="small"
          style="margin-top: 16px"
          :title="selectedTemplate?.name || '动态表单'"
        >
          <DynamicFormRenderer
            v-model="dynamicFormData"
            :schema="selectedSubmission?.version?.schema || selectedTemplate?.schema || {}"
            :options="selectedSubmission?.version?.options || selectedTemplate?.options || {}"
          />
        </NCard>

        <NSpace justify="end" style="margin-top: 16px">
          <NButton @click="router.back()">取消</NButton>
          <NButton type="primary" :loading="saving" @click="handleSave">
            {{ editId ? '保存' : '创建' }}
          </NButton>
        </NSpace>
      </NCard>
    </NSpin>
  </div>
</template>
