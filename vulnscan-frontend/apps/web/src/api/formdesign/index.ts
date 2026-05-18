import { baseRequestClient, requestClient } from '#/api/request';

export type DynamicFormBusiness = 'asset' | 'incident' | string;

export interface DynamicFormTemplate {
  id: string;
  name: string;
  code: string;
  business: DynamicFormBusiness;
  object_type: string;
  description: string;
  schema: Record<string, any>;
  options: Record<string, any>;
  version: number;
  current_version_id: string;
  draft_version_id: string;
  enabled: boolean;
  is_default: boolean;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface DynamicFormSubmission {
  id: string;
  template_id: string;
  template_version_id: string;
  business: DynamicFormBusiness;
  object_id: string;
  object_type: string;
  form_data: Record<string, any>;
  version: number;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface DynamicFormTemplateVersion {
  id: string;
  template_id: string;
  version: number;
  status: 'archived' | 'draft' | 'published' | string;
  schema: Record<string, any>;
  options: Record<string, any>;
  change_log: string;
  created_by: string;
  updated_by: string;
  published_by: string;
  published_at?: string;
  created_at: string;
  updated_at: string;
}

export interface DynamicFormTemplateInput {
  name: string;
  code?: string;
  business: DynamicFormBusiness;
  object_type?: string;
  description?: string;
  schema?: Record<string, any>;
  options?: Record<string, any>;
  version?: number;
  enabled?: boolean;
  is_default?: boolean;
}

export interface DynamicFormSubmissionInput {
  template_id: string;
  template_version_id?: string;
  business: DynamicFormBusiness;
  object_id: string;
  object_type?: string;
  form_data?: Record<string, any>;
  version?: number;
}

export interface DynamicFormSubmissionDetail {
  submission: DynamicFormSubmission;
  version?: DynamicFormTemplateVersion;
}

export function getDynamicFormTemplates(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/formdesign/templates', { params });
}

export function getDynamicFormTemplate(id: string) {
  return requestClient.get<DynamicFormTemplate>(`/formdesign/templates/${id}`);
}

export function createDynamicFormTemplate(data: DynamicFormTemplateInput) {
  return requestClient.post<DynamicFormTemplate>('/formdesign/templates', data);
}

export function updateDynamicFormTemplate(
  id: string,
  data: DynamicFormTemplateInput,
) {
  return requestClient.put(`/formdesign/templates/${id}`, data);
}

export function deleteDynamicFormTemplate(id: string) {
  return requestClient.delete(`/formdesign/templates/${id}`);
}

export function getDynamicFormTemplateVersions(id: string) {
  return requestClient.get<DynamicFormTemplateVersion[]>(`/formdesign/templates/${id}/versions`);
}

export function getDynamicFormTemplateVersion(id: string, versionId: string) {
  return requestClient.get<DynamicFormTemplateVersion>(`/formdesign/templates/${id}/versions/${versionId}`);
}

export function createDynamicFormDraft(id: string) {
  return requestClient.post<DynamicFormTemplateVersion>(`/formdesign/templates/${id}/draft`);
}

export function saveDynamicFormDraft(
  id: string,
  data: { change_log?: string; options?: Record<string, any>; schema?: Record<string, any> },
) {
  return requestClient.put<{ id: string }>(`/formdesign/templates/${id}/draft`, data);
}

export function publishDynamicFormDraft(
  id: string,
  data: { change_log?: string; options?: Record<string, any>; schema?: Record<string, any> },
) {
  return requestClient.post<DynamicFormTemplateVersion>(`/formdesign/templates/${id}/publish`, data);
}

export function getDynamicFormSubmissions(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/formdesign/submissions', { params });
}

export function getDynamicFormSubmission(id: string) {
  return requestClient.get<DynamicFormSubmissionDetail>(`/formdesign/submissions/${id}`);
}

export function saveDynamicFormSubmission(data: DynamicFormSubmissionInput) {
  return requestClient.post<{ id: string }>('/formdesign/submissions', data);
}

export function deleteDynamicFormSubmission(id: string) {
  return requestClient.delete(`/formdesign/submissions/${id}`);
}

export { normalizePagedResponse } from '../helpers';

/** 解析后端/设计器保存的 schema（支持 JSON 字符串、rule 数组） */
export function parseFormSchema(schema?: unknown): Record<string, any> {
  if (!schema) return { rule: [] };
  if (typeof schema === 'string') {
    try {
      const parsed = JSON.parse(schema);
      return parseFormSchema(parsed);
    } catch {
      return { rule: [] };
    }
  }
  if (Array.isArray(schema)) return { rule: schema };
  if (typeof schema === 'object') return schema as Record<string, any>;
  return { rule: [] };
}

export function normalizeFormRule(schema?: unknown) {
  const parsed = parseFormSchema(schema);
  if (Array.isArray(parsed.rule)) return parsed.rule;
  if (Array.isArray(parsed.rules)) return parsed.rules;
  return [];
}

/** Element 设计器类型 → Naive form-create 别名（与 @form-create/naive-ui alias 一致） */
const legacyDesignerTypeMap: Record<string, string> = {
  number: 'inputNumber',
  'el-input': 'input',
  'el-input-number': 'inputNumber',
  'el-select': 'select',
  'el-switch': 'switch',
  'el-date-picker': 'datePicker',
  'el-time-picker': 'timePicker',
  'el-cascader': 'cascader',
  'el-radio-group': 'radio',
  'el-checkbox-group': 'checkbox',
  'el-row': 'row',
  'el-col': 'col',
  fcRow: 'row',
  FcRow: 'row',
};

/** 误存为 Naive 组件名时转回 form-create 别名 */
const naiveComponentToAlias: Record<string, string> = {
  NAutoComplete: 'autoComplete',
  NButton: 'button',
  NCascader: 'cascader',
  NCheckbox: 'checkbox',
  NCheckboxGroup: 'checkbox',
  NCol: 'col',
  NColorPicker: 'colorPicker',
  NDatePicker: 'datePicker',
  NDynamicTags: 'dynamicTags',
  NInput: 'input',
  NInputNumber: 'inputNumber',
  NRadio: 'radio',
  NRadioGroup: 'radio',
  NRate: 'rate',
  NRow: 'row',
  NSelect: 'select',
  NSlider: 'slider',
  NSwitch: 'switch',
  NTimePicker: 'timePicker',
  NTree: 'tree',
  NUpload: 'upload',
  nInput: 'input',
  nInputNumber: 'inputNumber',
  nSelect: 'select',
  nSwitch: 'switch',
  nDatePicker: 'datePicker',
};

function mapDesignerComponentType(type: string): string {
  if (legacyDesignerTypeMap[type]) return legacyDesignerTypeMap[type];
  if (naiveComponentToAlias[type]) return naiveComponentToAlias[type];
  return type;
}

function normalizeFormCreateNode(node: any): any {
  if (Array.isArray(node)) {
    return node.map(normalizeFormCreateNode);
  }
  if (!node || typeof node !== 'object') {
    return node;
  }

  const normalized = { ...node };
  if (typeof normalized.type === 'string') {
    normalized.type = mapDesignerComponentType(normalized.type);
  }

  // textarea 在 Element 设计器里常为 input + props.type=textarea
  if (normalized.type === 'input' && normalized.props?.type === 'textarea') {
    normalized.type = 'textarea';
    const props = { ...normalized.props };
    delete props.type;
    normalized.props = props;
  }

  if (!normalized.title && !normalized.label && normalized.field) {
    normalized.title = String(normalized.field);
  }

  if (normalized.wrap === false) {
    normalized.wrap = { show: true };
  }

  if (Array.isArray(normalized.children)) {
    normalized.children = normalized.children.map(normalizeFormCreateNode);
  }
  if (Array.isArray(normalized.control)) {
    normalized.control = normalized.control.map((item: any) => ({
      ...item,
      rule: Array.isArray(item?.rule)
        ? item.rule.map(normalizeFormCreateNode)
        : item?.rule,
    }));
  }
  return normalized;
}

export function normalizeRuntimeFormRule(schema?: unknown) {
  return normalizeFormRule(schema).map(normalizeFormCreateNode);
}

export function normalizeFormOptions(
  schema?: unknown,
  options?: Record<string, any>,
  layout: 'horizontal' | 'vertical' = 'horizontal',
) {
  const parsed = parseFormSchema(schema);
  const normalized = {
    submitBtn: false,
    resetBtn: false,
    inline: false,
    row: { show: true, gutter: 12 },
    col: { show: true, span: 24 },
    wrap: { show: true },
    labelWidth: layout === 'vertical' ? undefined : 120,
    ...(parsed.option ?? {}),
    ...(parsed.options ?? {}),
    ...(options ?? {}),
  };

  normalized.submitBtn = false;
  normalized.resetBtn = false;
  normalized.inline = false;

  const form = normalized.form;
  if (form && typeof form === 'object') {
    const nextForm = { ...form } as Record<string, any>;

    if (nextForm.labelPosition && !nextForm.labelPlacement) {
      nextForm.labelPlacement = nextForm.labelPosition;
    }
    delete nextForm.labelPosition;
    delete nextForm.hideRequiredAsterisk;
    nextForm.inline = false;

    if (layout === 'vertical') {
      nextForm.labelPlacement = 'top';
      delete nextForm.labelWidth;
    }

    if (typeof nextForm.size === 'string') {
      const size = nextForm.size.toLowerCase();
      if (size === 'default') {
        delete nextForm.size;
      } else if (size === 'small' || size === 'medium' || size === 'large') {
        nextForm.size = size;
      } else {
        delete nextForm.size;
      }
    }

    normalized.form = nextForm;
  } else if (layout === 'vertical') {
    normalized.form = { labelPlacement: 'top', inline: false };
  }

  return normalized;
}
