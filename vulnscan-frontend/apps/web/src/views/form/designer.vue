<script setup lang="ts">
import { computed, h, nextTick, onMounted, reactive, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import type { DataTableColumns } from 'naive-ui';
import {
  NButton,
  NCard,
  NDataTable,
  NDivider,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NModal,
  NSelect,
  NSpace,
  NSwitch,
  NTabPane,
  NTabs,
  NTag,
  useMessage,
} from 'naive-ui';

import type { DynamicFormTemplate, DynamicFormTemplateVersion } from '#/api/formdesign';
import {
  createDynamicFormDraft,
  getDynamicFormTemplate,
  getDynamicFormTemplateVersions,
  publishDynamicFormDraft,
  saveDynamicFormDraft,
  updateDynamicFormTemplate,
} from '#/api/formdesign';
import FormPreview from '#/components/dynamic-form/FormPreview.vue';

defineOptions({ name: 'FormDesigner' });

const route = useRoute();
const router = useRouter();
const message = useMessage();
const loading = ref(false);
const saving = ref(false);
const publishing = ref(false);
const jsonError = ref('');
const previewData = ref<Record<string, any>>({});
const previewRule = ref<any[]>([]);
const previewOptionState = ref<Record<string, any>>({});
const template = ref<DynamicFormTemplate | null>(null);
const versions = ref<DynamicFormTemplateVersion[]>([]);
const designerRef = ref<any>(null);
const activeEditorTab = ref('designer');
const showPreviewModal = ref(false);
const showVersionModal = ref(false);
const changeLog = ref('');

const businessOptions = [
  { label: '资产', value: 'asset' },
  { label: '事件', value: 'incident' },
];

const fieldTypeOptions = [
  { label: '单行文本', value: 'input' },
  { label: '多行文本', value: 'textarea' },
  { label: '数字', value: 'inputNumber' },
  { label: '下拉选择', value: 'select' },
  { label: '开关', value: 'switch' },
  { label: '日期', value: 'datePicker' },
];

const metaForm = reactive({
  business: 'asset',
  code: '',
  description: '',
  enabled: true,
  is_default: false,
  name: '',
  object_type: '',
  version: 1,
});

const quickField = reactive({
  field: '',
  required: false,
  title: '',
  type: 'input',
});

const schemaText = ref(JSON.stringify({ rule: [] }, null, 2));
const optionsText = ref(JSON.stringify({ labelPlacement: 'left', labelWidth: 120, submitBtn: false }, null, 2));

const parsedSchema = computed(() => safeParse(schemaText.value, { rule: [] }));
const draftVersion = computed(() => versions.value.find(item => item.status === 'draft'));
const publishedVersion = computed(() => versions.value.find(item => item.id === template.value?.current_version_id) || versions.value.find(item => item.status === 'published'));
const ruleCount = computed(() => {
  const schema = parsedSchema.value;
  if (Array.isArray(schema)) return schema.length;
  return Array.isArray(schema?.rule) ? schema.rule.length : 0;
});

const designerConfig = {
  formOptions: { form: { labelWidth: '120px' }, submitBtn: false },
  showAi: false,
  showLanguage: false,
  showPreviewBtn: false,
};

function safeParse(value: string, fallback: Record<string, any>) {
  try {
    jsonError.value = '';
    return JSON.parse(value || '{}');
  } catch (error) {
    jsonError.value = error instanceof Error ? error.message : 'JSON format is invalid';
    return fallback;
  }
}

async function fetchDetail() {
  const id = String(route.params.id || '');
  if (!id) return;
  loading.value = true;
  try {
    const detail = await getDynamicFormTemplate(id);
    template.value = detail;
    Object.assign(metaForm, {
      business: detail.business,
      code: detail.code,
      description: detail.description || '',
      enabled: detail.enabled,
      is_default: detail.is_default,
      name: detail.name,
      object_type: detail.object_type || '',
      version: detail.version || 1,
    });
    schemaText.value = JSON.stringify(detail.schema?.rule ? detail.schema : { rule: [] }, null, 2);
    optionsText.value = JSON.stringify(detail.options || {}, null, 2);
    await fetchVersions();
    await nextTick();
    loadDesignerFromJson();
  } catch {
    message.error('加载表单模板失败');
  } finally {
    loading.value = false;
  }
}

async function fetchVersions() {
  const id = String(route.params.id || '');
  if (!id) return;
  versions.value = await getDynamicFormTemplateVersions(id);
}

function loadDesignerFromJson() {
  const designer = designerRef.value;
  if (!designer) return;
  const schema = safeParse(schemaText.value, { rule: [] });
  const options = safeParse(optionsText.value, {});
  designer.setRule?.(Array.isArray(schema) ? schema : schema.rule || []);
  designer.setOptions?.(options || {});
}

function syncJsonFromDesigner() {
  const designer = designerRef.value;
  if (!designer) return;
  const rule = designer.getRule?.() ?? [];
  const options = designer.getOptions?.() ?? {};
  schemaText.value = JSON.stringify({ rule }, null, 2);
  optionsText.value = JSON.stringify(options || {}, null, 2);
}

function currentRuleList() {
  const schema = safeParse(schemaText.value, { rule: [] });
  if (Array.isArray(schema)) return { schema: { rule: schema }, rule: schema };
  if (!Array.isArray(schema.rule)) schema.rule = [];
  return { schema, rule: schema.rule };
}

function addQuickField() {
  syncJsonFromDesigner();
  if (!quickField.title || !quickField.field) {
    message.warning('Please fill in both field title and field name');
    return;
  }
  const { schema, rule } = currentRuleList();
  if (rule.some((item: any) => item.field === quickField.field)) {
    message.warning('字段名已存在');
    return;
  }
  const item: Record<string, any> = {
    field: quickField.field,
    title: quickField.title,
    type: quickField.type,
  };
  if (quickField.type === 'textarea') {
    item.type = 'input';
    item.props = { type: 'textarea' };
  }
  if (quickField.type === 'select') {
    item.options = [
      { label: 'Option 1', value: 'option_1' },
      { label: 'Option 2', value: 'option_2' },
    ];
  }
  if (quickField.required) {
    item.validate = [{ message: `Please fill in ${quickField.title}`, required: true, trigger: 'blur' }];
  }
  rule.push(item);
  schemaText.value = JSON.stringify(schema, null, 2);
  Object.assign(quickField, { field: '', required: false, title: '', type: 'input' });
  nextTick(loadDesignerFromJson);
}

function formatJson() {
  const schema = safeParse(schemaText.value, { rule: [] });
  const options = safeParse(optionsText.value, {});
  schemaText.value = JSON.stringify(schema, null, 2);
  optionsText.value = JSON.stringify(options, null, 2);
}

function openPreview() {
  // 先同步设计器数据到文本字段（无论当前是哪个标签页）
  if (activeEditorTab.value === 'designer') {
    syncJsonFromDesigner();
  }
  // 统一从 schemaText 和 optionsText 读取数据进行预览
  const schema = safeParse(schemaText.value, { rule: [] });
  const options = safeParse(optionsText.value, {});
  const rawRule = Array.isArray(schema) ? schema : schema.rule || [];
  previewRule.value = JSON.parse(JSON.stringify(rawRule));
  previewOptionState.value = JSON.parse(JSON.stringify(options || {}));
  previewData.value = {};
  showPreviewModal.value = true;
}

function collectDraftPayload() {
  if (activeEditorTab.value === 'designer') syncJsonFromDesigner();
  const schema = safeParse(schemaText.value, { rule: [] });
  const options = safeParse(optionsText.value, {});
  return { schema, options, change_log: changeLog.value || '更新表单设计' };
}

async function saveTemplateMeta() {
  if (!template.value) return;
  await updateDynamicFormTemplate(template.value.id, {
    business: metaForm.business,
    code: metaForm.code,
    description: metaForm.description,
    enabled: metaForm.enabled,
    is_default: metaForm.is_default,
    name: metaForm.name,
    object_type: metaForm.object_type,
  });
}

async function ensureDraft() {
  if (!template.value) return;
  const draft = await createDynamicFormDraft(template.value.id);
  message.success(`已创建v${draft.version} 草稿`);
  await fetchDetail();
}

async function saveDraft() {
  if (!template.value) return;
  const payload = collectDraftPayload();
  if (jsonError.value) {
    message.warning('请先修正 JSON 格式');
    return;
  }
  saving.value = true;
  try {
    await saveTemplateMeta();
    await saveDynamicFormDraft(template.value.id, payload);
    message.success('草稿已保存，不影响已发布版本');
    await fetchDetail();
  } catch {
    message.error('保存草稿失败');
  } finally {
    saving.value = false;
  }
}

async function publishDraft() {
  if (!template.value) return;
  const payload = collectDraftPayload();
  if (jsonError.value) {
    message.warning('请先修正 JSON 格式');
    return;
  }
  publishing.value = true;
  try {
    await saveTemplateMeta();
    const version = await publishDynamicFormDraft(template.value.id, payload);
    message.success(`已发布v${version.version}`);
    changeLog.value = '';
    await fetchDetail();
  } catch {
    message.error('发布版本失败');
  } finally {
    publishing.value = false;
  }
}

function loadVersion(row: DynamicFormTemplateVersion) {
  schemaText.value = JSON.stringify(row.schema?.rule ? row.schema : { rule: [] }, null, 2);
  optionsText.value = JSON.stringify(row.options || {}, null, 2);
  showVersionModal.value = false;
  nextTick(loadDesignerFromJson);
  message.info(`已加载v${row.version} ${row.status === 'draft' ? '草稿' : '发布'}`);
}

function statusTag(row: DynamicFormTemplateVersion) {
  const map: Record<string, { label: string; type: 'default' | 'info' | 'success' | 'warning' }> = {
    archived: { label: '历史', type: 'default' },
    draft: { label: '草稿', type: 'warning' },
    published: { label: '已发布', type: 'success' },
  };
  return map[row.status] || { label: row.status, type: 'info' };
}

function formatDate(value?: string) {
  return value?.replace('T', ' ').slice(0, 19) || '-';
}

function onDesignerSave(payload?: { options?: string; rule?: string }) {
  if (payload?.rule) {
    schemaText.value = JSON.stringify({ rule: JSON.parse(payload.rule) }, null, 2);
  } else {
    syncJsonFromDesigner();
  }
  if (payload?.options) {
    optionsText.value = JSON.stringify(JSON.parse(payload.options), null, 2);
  }
  saveDraft();
}

const versionColumns: DataTableColumns<DynamicFormTemplateVersion> = [
  { title: '版本', key: 'version', width: 80, render: row => `v${row.version}` },
  {
    title: '状态',
    key: 'status',
    width: 100,
    render: row => {
      const tag = statusTag(row);
      return h(NTag, { bordered: false, size: 'small', type: tag.type }, () => tag.label);
    },
  },
  { title: '变更说明', key: 'change_log', minWidth: 180, render: row => row.change_log || '-' },
  { title: '发布时间', key: 'published_at', minWidth: 170, render: row => formatDate(row.published_at) },
  {
    title: '操作',
    key: 'actions',
    width: 90,
    render: row => h(NButton, { size: 'small', onClick: () => loadVersion(row) }, () => '导入'),
  },
];

onMounted(fetchDetail);
</script>

<template>
  <div class="form-designer-page">
    <div class="designer-shell">
      <aside class="designer-side">
        <div class="side-header">
          <div class="side-heading">
            <div class="side-title">{{ metaForm.name || '表单设计' }}</div>
            <div class="side-subtitle">{{ metaForm.code || '未生成编码' }}</div>
          </div>
          <NTag size="small" :bordered="false" type="info">{{ ruleCount }} 字段</NTag>
        </div>

        <div class="version-strip">
          <NTag size="small" :bordered="false" type="success">
            发布 v{{ publishedVersion?.version || '-' }}
          </NTag>
          <NTag size="small" :bordered="false" :type="draftVersion ? 'warning' : 'default'">
            草稿 {{ draftVersion ? 'v' + draftVersion.version : '无' }}
          </NTag>
        </div>

        <NForm class="compact-form" label-placement="top" :show-feedback="false">
          <NFormItem label="模板名称">
            <NInput v-model:value="metaForm.name" />
          </NFormItem>
          <div class="side-grid">
            <NFormItem label="业务归属">
              <NSelect v-model:value="metaForm.business" :options="businessOptions" />
            </NFormItem>
            <NFormItem label="版本">
              <NInputNumber v-model:value="metaForm.version" :min="1" disabled style="width: 100%" />
            </NFormItem>
          </div>
          <NFormItem label="对象类型">
            <NInput v-model:value="metaForm.object_type" placeholder="可选" />
          </NFormItem>
          <div class="switch-row">
            <span>默认模板</span>
            <NSwitch v-model:value="metaForm.is_default" />
          </div>
          <div class="switch-row">
            <span>启用</span>
            <NSwitch v-model:value="metaForm.enabled" />
          </div>
          <NFormItem label="变更说明">
            <NInput v-model:value="changeLog" placeholder="发布或保存草稿时记录" />
          </NFormItem>
          <NFormItem label="说明">
            <NInput v-model:value="metaForm.description" type="textarea" :rows="3" placeholder="表单适用场景" />
          </NFormItem>
        </NForm>

        <NDivider />

        <div class="section-title">快速添加字段</div>
        <NForm class="compact-form" label-placement="top" :show-feedback="false">
          <NFormItem label="字段标题">
            <NInput v-model:value="quickField.title" placeholder="页面显示名称" />
          </NFormItem>
          <NFormItem label="字段名">
            <NInput v-model:value="quickField.field" placeholder="如：owner_unit_note" />
          </NFormItem>
          <div class="side-grid">
            <NFormItem label="字段类型">
              <NSelect v-model:value="quickField.type" :options="fieldTypeOptions" />
            </NFormItem>
            <div class="required-field">
              <span>必填</span>
              <NSwitch v-model:value="quickField.required" />
            </div>
          </div>
          <NButton block type="primary" @click="addQuickField">添加到规则</NButton>
        </NForm>
      </aside>

      <main class="designer-main">
        <div class="designer-toolbar">
          <div class="toolbar-title">
            <span>表单规则</span>
            <small>保存草稿不会影响历史数据；发布后将同步生成新版本</small>
          </div>
          <NSpace :size="8">
            <NButton size="small" @click="router.push({ name: 'FormTemplates' })">返回</NButton>
            <NButton size="small" @click="showVersionModal = true">版本历史</NButton>
            <NButton size="small" @click="openPreview">预览</NButton>
            <NButton size="small" @click="formatJson">格式化</NButton>
            <NButton v-if="!draftVersion" size="small" @click="ensureDraft">创建草稿</NButton>
            <NButton :loading="saving" size="small" @click="saveDraft">保存草稿</NButton>
            <NButton :loading="publishing" size="small" type="primary" @click="publishDraft">发布版本</NButton>
          </NSpace>
        </div>

        <NCard class="designer-card" size="small" :bordered="false" :loading="loading">
          <NTabs v-model:value="activeEditorTab" animated type="line">
            <NTabPane name="designer" tab="可视化设计">
              <div class="visual-designer">
                <fc-designer
                  ref="designerRef"
                  :config="designerConfig"
                  height="calc(100vh - 238px)"
                  @save="onDesignerSave"
                />
              </div>
            </NTabPane>
            <NTabPane name="schema" tab="Schema">
              <NInput v-model:value="schemaText" class="json-editor" type="textarea" />
            </NTabPane>
            <NTabPane name="options" tab="Options">
              <NInput v-model:value="optionsText" class="json-editor" type="textarea" />
            </NTabPane>
          </NTabs>
          <div v-if="jsonError" class="json-error">{{ jsonError }}</div>
        </NCard>
      </main>
    </div>

    <NModal v-model:show="showPreviewModal" preset="card" title="表单预览" style="width: min(860px, calc(100vw - 32px))">
      <FormPreview
        v-model="previewData"
        :options="previewOptionState"
        :rule="previewRule"
      />
    </NModal>

    <NModal v-model:show="showVersionModal" preset="card" title="版本历史" style="width: min(860px, calc(100vw - 32px))">
      <NDataTable
        :bordered="false"
        :columns="versionColumns"
        :data="versions"
        :pagination="{ pageSize: 8 }"
        :row-key="(row: DynamicFormTemplateVersion) => row.id"
        size="small"
      />
    </NModal>
  </div>
</template>

<style scoped>
.form-designer-page {
  --designer-accent: var(--n-primary-color, hsl(var(--primary, 212 100% 45%)));
  --designer-accent-hover: var(--n-primary-color-hover, var(--designer-accent));
  --designer-bg: var(--n-body-color, hsl(var(--background-deep, 216 20.11% 95.47%)));
  --designer-border: var(--n-border-color, hsl(var(--border, 240 5.9% 90%)));
  --designer-control-bg: var(--n-input-color, hsl(var(--input-background, 0 0% 100%)));
  --designer-muted: var(--n-text-color-3, hsl(var(--muted-foreground, 240 3.8% 46.1%)));
  --designer-paper: var(--n-popover-color, hsl(var(--popover, 0 0% 100%)));
  --designer-soft: var(--n-action-color, hsl(var(--accent, 240 5% 96%)));
  --designer-surface: var(--n-color, hsl(var(--card, 0 0% 100%)));
  --designer-text: var(--n-text-color, hsl(var(--foreground, 210 6% 21%)));
  --designer-text-2: var(--n-text-color-2, hsl(var(--muted-foreground, 240 3.8% 46.1%)));

  min-height: calc(100vh - 90px);
  padding: 12px 14px 16px;
  color: var(--designer-text);
  background: var(--designer-bg);
  isolation: isolate;
}

:global(.dark) .form-designer-page {
  --designer-control-bg: #202733;
  --designer-paper: #1a2029;
  --designer-soft: #202733;
  --designer-surface: #171c24;
  --designer-text-2: #b6c0cf;
}

.designer-shell {
  display: grid;
  grid-template-columns: 340px minmax(0, 1fr);
  gap: 12px;
  min-height: calc(100vh - 122px);
}

.designer-side,
.designer-main {
  min-width: 0;
}

.designer-side {
  padding: 14px;
  overflow: auto;
  background: var(--designer-surface);
  border: 1px solid var(--designer-border);
  border-radius: 8px;
  box-shadow: 0 8px 22px rgba(15, 23, 42, 0.04);
}

:global(.dark) .designer-side {
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
}

.side-header {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 10px;
}

.side-heading {
  min-width: 0;
}

.side-title {
  overflow: hidden;
  color: var(--designer-text);
  font-size: 15px;
  font-weight: 600;
  line-height: 1.35;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.side-subtitle {
  margin-top: 3px;
  overflow: hidden;
  color: var(--designer-muted);
  font-size: 12px;
  line-height: 1.35;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.version-strip {
  display: flex;
  gap: 6px;
  margin-bottom: 14px;
}

.compact-form :deep(.n-form-item) {
  margin-bottom: 10px;
}

.side-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 96px;
  gap: 10px;
}

.switch-row,
.required-field {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 34px;
  color: var(--designer-text-2);
  font-size: 13px;
}

.required-field {
  align-self: end;
  padding-bottom: 10px;
}

.section-title {
  margin-bottom: 10px;
  color: var(--designer-text);
  font-size: 14px;
  font-weight: 600;
}

.designer-main {
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: var(--designer-surface);
  border: 1px solid var(--designer-border);
  border-radius: 8px;
  box-shadow: 0 8px 22px rgba(15, 23, 42, 0.04);
}

:global(.dark) .designer-main {
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
}

.designer-toolbar {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  border-bottom: 1px solid var(--designer-border);
}

.toolbar-title {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.toolbar-title span {
  color: var(--designer-text);
  font-size: 15px;
  font-weight: 600;
}

.toolbar-title small {
  margin-top: 2px;
  color: var(--designer-muted);
  font-size: 12px;
}

.designer-card {
  flex: 1;
  min-height: 0;
  background: transparent;
}

.designer-card :deep(.n-card__content) {
  height: 100%;
  padding: 0 12px 12px;
}

.visual-designer {
  min-height: calc(100vh - 238px);
  overflow: hidden;
  color: var(--designer-text);
  background: var(--designer-bg);
  border: 1px solid var(--designer-border);
  border-radius: 8px;
}

.visual-designer :deep(._fc-designer) {
  color: var(--designer-text);
  background: var(--designer-surface);
  border-color: var(--designer-border);
  --fc-tool-border-color: rgba(76, 157, 255, 0.38);
  --el-bg-color: var(--designer-surface);
  --el-bg-color-overlay: var(--designer-paper);
  --el-border-color: var(--designer-border);
  --el-border-color-light: var(--designer-border);
  --el-border-color-lighter: var(--designer-border);
  --el-color-primary: var(--designer-accent);
  --el-color-primary-light-9: rgba(22, 119, 255, 0.14);
  --el-disabled-bg-color: var(--designer-soft);
  --el-disabled-border-color: var(--designer-border);
  --el-disabled-text-color: var(--designer-muted);
  --el-fill-color: var(--designer-soft);
  --el-fill-color-blank: var(--designer-surface);
  --el-fill-color-light: var(--designer-soft);
  --el-fill-color-lighter: var(--designer-paper);
  --el-mask-color: rgba(0, 0, 0, 0.45);
  --el-text-color-disabled: var(--designer-muted);
  --el-text-color-placeholder: var(--designer-muted);
  --el-text-color-primary: var(--designer-text);
  --el-text-color-regular: var(--designer-text-2);
  --el-text-color-secondary: var(--designer-muted);
}

:global(.dark) .form-designer-page {
  --n-border-color: rgba(148, 163, 184, 0.16);
  --n-divider-color: rgba(148, 163, 184, 0.16);
}

.visual-designer :deep(._fc-l),
.visual-designer :deep(._fc-m),
.visual-designer :deep(._fc-r),
.visual-designer :deep(._fc-l-menu),
.visual-designer :deep(._fc-m-tools),
.visual-designer :deep(._fc-r ._fc-r-tabs),
.visual-designer :deep(._fc-l-tabs) {
  color: var(--designer-text);
  background: var(--designer-surface);
  border-color: var(--designer-border);
}

.visual-designer :deep(._fc-m-con) {
  background:
    linear-gradient(90deg, rgba(148, 163, 184, 0.07) 1px, transparent 1px),
    linear-gradient(0deg, rgba(148, 163, 184, 0.07) 1px, transparent 1px),
    var(--designer-bg);
  background-size: 24px 24px;
}

.visual-designer :deep(._fc-m-drag),
.visual-designer :deep(.draggable-drag),
.visual-designer :deep(._fd-draggable-drag.drag-holder) {
  color: var(--designer-text);
  background: var(--designer-paper);
}

.visual-designer :deep(._fc-m-drag) {
  box-shadow: 0 10px 28px rgba(15, 23, 42, 0.08);
}

:global(.dark) .visual-designer :deep(._fc-m-drag) {
  box-shadow: 0 10px 32px rgba(0, 0, 0, 0.28);
}

.visual-designer :deep(._fc-l-group) {
  background: var(--designer-paper);
  border-color: var(--designer-border);
  border-radius: 6px;
}

.visual-designer :deep(._fc-l-title),
.visual-designer :deep(._fc-l-label),
.visual-designer :deep(._fc-l-tab),
.visual-designer :deep(._fc-r ._fc-r-tab),
.visual-designer :deep(._fc-r-title),
.visual-designer :deep(._fc-r .el-form-item__label),
.visual-designer :deep(._fc-l .el-tree-node__label),
.visual-designer :deep(._fc-l .el-tree-node__content > .el-tree-node__expand-icon),
.visual-designer :deep(.el-form-item__label),
.visual-designer :deep(.el-radio),
.visual-designer :deep(.el-checkbox),
.visual-designer :deep(.el-tabs__item) {
  color: var(--designer-text);
}

.visual-designer :deep(._fc-l-info),
.visual-designer :deep(.fc-configured),
.visual-designer :deep(._fc-m-tools-l .fc-icon.disabled),
.visual-designer :deep(.el-input__inner::placeholder),
.visual-designer :deep(.el-textarea__inner::placeholder) {
  color: var(--designer-muted);
}

.visual-designer :deep(._fc-l-item),
.visual-designer :deep(._fc-m .form-create ._fc-l-item) {
  color: var(--designer-text-2);
  background: var(--designer-soft);
  border-color: var(--designer-border);
  border-radius: 6px;
}

:global(.dark) .visual-designer :deep(._fc-l-item),
:global(.dark) .visual-designer :deep(._fc-m .form-create ._fc-l-item) {
  color: #c5cfdd;
  background: #202733;
  border: 1px solid rgba(148, 163, 184, 0.14);
}

.visual-designer :deep(._fc-l-item:hover),
.visual-designer :deep(._fc-l-menu-item.active),
.visual-designer :deep(._fc-tree-node.active),
.visual-designer :deep(._fc-tree-node.active .icon-more),
.visual-designer :deep(._fc-r ._fc-r-tab.active),
.visual-designer :deep(._fc-l ._fc-l-tab.active),
.visual-designer :deep(._fc-m-tools-l .devices .fc-icon.active),
.visual-designer :deep(._fc-manage-text) {
  color: var(--designer-accent);
}

.visual-designer :deep(._fc-l-item:hover) {
  background: rgba(22, 119, 255, 0.12);
}

:global(.dark) .visual-designer :deep(._fc-l-item:hover) {
  color: #eef6ff;
  background: rgba(76, 157, 255, 0.16);
  border-color: rgba(76, 157, 255, 0.38);
}

.visual-designer :deep(._fc-r ._fc-r-tab.active),
.visual-designer :deep(._fc-l ._fc-l-tab.active) {
  border-bottom-color: var(--designer-accent);
}

.visual-designer :deep(._fc-l-close),
.visual-designer :deep(._fc-r-close),
.visual-designer :deep(._fc-l-open),
.visual-designer :deep(._fc-r-open),
.visual-designer :deep(._fc-m-input-handle),
.visual-designer :deep(._fc-m-tools ._fd-m-extend) {
  color: var(--designer-text-2);
  background: var(--designer-paper);
  border-color: var(--designer-border);
}

.visual-designer :deep(._fc-m-tools .line),
.visual-designer :deep(._fc-r .el-tabs__nav-wrap::after),
.visual-designer :deep(._fc-tabs .el-tabs__nav-wrap::after) {
  background: var(--designer-border);
}

.visual-designer :deep(.el-input__wrapper),
.visual-designer :deep(.el-textarea__inner),
.visual-designer :deep(.el-select__wrapper),
.visual-designer :deep(.el-input-group__append),
.visual-designer :deep(.el-input-group__prepend) {
  color: var(--designer-text);
  background: var(--designer-control-bg);
  border-color: var(--designer-border);
  box-shadow: 0 0 0 1px var(--designer-border) inset;
}

:global(.dark) .visual-designer :deep(.el-input__wrapper),
:global(.dark) .visual-designer :deep(.el-textarea__inner),
:global(.dark) .visual-designer :deep(.el-select__wrapper),
:global(.dark) .visual-designer :deep(.el-input-group__append),
:global(.dark) .visual-designer :deep(.el-input-group__prepend) {
  background: #202733;
  box-shadow: 0 0 0 1px rgba(148, 163, 184, 0.18) inset;
}

.visual-designer :deep(.el-input__wrapper:hover),
.visual-designer :deep(.el-textarea__inner:hover),
.visual-designer :deep(.el-select__wrapper:hover) {
  box-shadow: 0 0 0 1px var(--designer-accent-hover) inset;
}

.visual-designer :deep(.el-button:not(.el-button--primary)) {
  color: var(--designer-text-2);
  background: var(--designer-soft);
  border-color: var(--designer-border);
}

:global(.dark) .visual-designer :deep(.el-button:not(.el-button--primary)) {
  color: #c5cfdd;
  background: #202733;
  border-color: rgba(148, 163, 184, 0.18);
}

:global(.dark) .visual-designer :deep(.el-radio__inner),
:global(.dark) .visual-designer :deep(.el-checkbox__inner),
:global(.dark) .visual-designer :deep(.el-switch__core),
:global(.dark) .visual-designer :deep(.el-input-number__increase),
:global(.dark) .visual-designer :deep(.el-input-number__decrease) {
  background: #202733;
  border-color: rgba(148, 163, 184, 0.26);
}

:global(.dark) .visual-designer :deep(.el-radio__input.is-checked .el-radio__inner),
:global(.dark) .visual-designer :deep(.el-checkbox__input.is-checked .el-checkbox__inner),
:global(.dark) .visual-designer :deep(.el-switch.is-checked .el-switch__core) {
  background: var(--designer-accent);
  border-color: var(--designer-accent);
}

:global(.dark) .visual-designer :deep(.el-input-number__increase),
:global(.dark) .visual-designer :deep(.el-input-number__decrease) {
  color: #c5cfdd;
}

.visual-designer :deep(.el-button:not(.el-button--primary):hover) {
  color: var(--designer-accent);
  background: rgba(22, 119, 255, 0.12);
  border-color: var(--designer-accent-hover);
}

.visual-designer :deep(.el-table),
.visual-designer :deep(.el-table tr),
.visual-designer :deep(.el-table th.el-table__cell),
.visual-designer :deep(.el-table td.el-table__cell) {
  color: var(--designer-text-2);
  background: var(--designer-paper);
  border-color: var(--designer-border);
}

.visual-designer :deep(._fd-draggable-drag.drag-holder:after),
.visual-designer :deep(._fc-child-empty:after) {
  color: var(--designer-muted);
}

:global(.dark) .visual-designer :deep(._fd-drag-tool) {
  outline: 1px dashed rgba(76, 157, 255, 0.22);
}

:global(.dark) .visual-designer :deep(._fd-drag-tool:hover) {
  outline-color: rgba(76, 157, 255, 0.32);
  outline-style: solid;
}

:global(.dark) .visual-designer :deep(._fd-drag-tool.active) {
  outline: 1px solid rgba(76, 157, 255, 0.52);
}

:global(.dark) .visual-designer :deep(._fd-drag-btn) {
  background-color: rgba(76, 157, 255, 0.92);
}

:global(.dark) .visual-designer :deep(._fd-drag-danger) {
  background-color: rgba(255, 78, 106, 0.92);
}

:global(.dark) .visual-designer :deep(._fd-draggable-drag.drag-holder),
:global(.dark) .visual-designer :deep(._fd-tableFormColumn-drag.drag-holder),
:global(.dark) .visual-designer :deep(._fd-elTabPane-drag.drag-holder),
:global(.dark) .visual-designer :deep(._fd-group-drag.drag-holder),
:global(.dark) .visual-designer :deep(._fd-subForm-drag.drag-holder),
:global(.dark) .visual-designer :deep(._fd-elCard-drag.drag-holder),
:global(.dark) .visual-designer :deep(._fd-elCollapseItem-drag.drag-holder),
:global(.dark) .visual-designer :deep(._fd-row._fc-child-empty) {
  background: rgba(148, 163, 184, 0.04);
}

.json-editor {
  min-height: calc(100vh - 238px);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
}

.json-editor :deep(textarea) {
  min-height: calc(100vh - 238px) !important;
  line-height: 1.55;
}

.json-error {
  margin-top: 8px;
  padding: 8px 10px;
  color: var(--n-error-color, hsl(var(--destructive, 359.33 100% 65.1%)));
  font-size: 12px;
  background: var(
    --n-error-color-suppl,
    hsl(var(--destructive, 359.33 100% 65.1%) / 0.14)
  );
  border-radius: 6px;
}

@media (max-width: 1080px) {
  .designer-shell {
    grid-template-columns: 1fr;
  }
}
</style>




