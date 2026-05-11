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
  return baseRequestClient.get<any>('/form/templates', { params });
}

export function getDynamicFormTemplate(id: string) {
  return requestClient.get<DynamicFormTemplate>(`/form/templates/${id}`);
}

export function createDynamicFormTemplate(data: DynamicFormTemplateInput) {
  return requestClient.post<DynamicFormTemplate>('/form/templates', data);
}

export function updateDynamicFormTemplate(
  id: string,
  data: DynamicFormTemplateInput,
) {
  return requestClient.put(`/form/templates/${id}`, data);
}

export function deleteDynamicFormTemplate(id: string) {
  return requestClient.delete(`/form/templates/${id}`);
}

export function getDynamicFormTemplateVersions(id: string) {
  return requestClient.get<DynamicFormTemplateVersion[]>(`/form/templates/${id}/versions`);
}

export function getDynamicFormTemplateVersion(id: string, versionId: string) {
  return requestClient.get<DynamicFormTemplateVersion>(`/form/templates/${id}/versions/${versionId}`);
}

export function createDynamicFormDraft(id: string) {
  return requestClient.post<DynamicFormTemplateVersion>(`/form/templates/${id}/draft`);
}

export function saveDynamicFormDraft(
  id: string,
  data: { change_log?: string; options?: Record<string, any>; schema?: Record<string, any> },
) {
  return requestClient.put<{ id: string }>(`/form/templates/${id}/draft`, data);
}

export function publishDynamicFormDraft(
  id: string,
  data: { change_log?: string; options?: Record<string, any>; schema?: Record<string, any> },
) {
  return requestClient.post<DynamicFormTemplateVersion>(`/form/templates/${id}/publish`, data);
}

export function getDynamicFormSubmissions(params?: Record<string, any>) {
  return baseRequestClient.get<any>('/form/submissions', { params });
}

export function getDynamicFormSubmission(id: string) {
  return requestClient.get<DynamicFormSubmissionDetail>(`/form/submissions/${id}`);
}

export function saveDynamicFormSubmission(data: DynamicFormSubmissionInput) {
  return requestClient.post<{ id: string }>('/form/submissions', data);
}

export function deleteDynamicFormSubmission(id: string) {
  return requestClient.delete(`/form/submissions/${id}`);
}

export function normalizePagedResponse<T>(res: any) {
  const body = res?.data ?? res;
  return {
    items: (body?.data ?? body?.items ?? []) as T[],
    total: Number(body?.count ?? body?.total ?? 0),
  };
}

export function normalizeFormRule(schema?: Record<string, any>) {
  if (Array.isArray(schema)) return schema;
  if (Array.isArray(schema?.rule)) return schema.rule;
  if (Array.isArray(schema?.rules)) return schema.rules;
  return [];
}

const formCreateComponentMap: Record<string, string> = {
  nAutoComplete: 'NAutoComplete',
  nButton: 'NButton',
  nCascader: 'NCascader',
  nCheckbox: 'NCheckbox',
  nCheckboxGroup: 'NCheckboxGroup',
  nCol: 'NCol',
  nColorPicker: 'NColorPicker',
  nDatePicker: 'NDatePicker',
  nDynamicTags: 'NDynamicTags',
  nForm: 'NForm',
  nFormItem: 'NFormItem',
  nIcon: 'NIcon',
  nInput: 'NInput',
  nInputGroup: 'NInputGroup',
  nInputGroupLabel: 'NInputGroupLabel',
  nInputNumber: 'NInputNumber',
  nModal: 'NModal',
  nPopover: 'NPopover',
  nRadio: 'NRadio',
  nRadioGroup: 'NRadioGroup',
  nRate: 'NRate',
  nRow: 'NRow',
  nSelect: 'NSelect',
  nSlider: 'NSlider',
  nSwitch: 'NSwitch',
  nTimePicker: 'NTimePicker',
  nTooltip: 'NTooltip',
  nTree: 'NTree',
  nUpload: 'NUpload',
};

function normalizeFormCreateNode(node: any): any {
  if (Array.isArray(node)) {
    return node.map(normalizeFormCreateNode);
  }
  if (!node || typeof node !== 'object') {
    return node;
  }

  const normalized = { ...node };
  if (typeof normalized.type === 'string' && formCreateComponentMap[normalized.type]) {
    normalized.type = formCreateComponentMap[normalized.type];
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

export function normalizeRuntimeFormRule(schema?: Record<string, any>) {
  return normalizeFormRule(schema).map(normalizeFormCreateNode);
}

export function normalizeFormOptions(
  schema?: Record<string, any>,
  options?: Record<string, any>,
) {
  const normalized = {
    submitBtn: false,
    resetBtn: false,
    labelWidth: 120,
    ...(schema?.option ?? {}),
    ...(schema?.options ?? {}),
    ...(options ?? {}),
  };

  const form = normalized.form;
  if (form && typeof form === 'object') {
    const nextForm = { ...form } as Record<string, any>;

    if (nextForm.labelPosition && !nextForm.labelPlacement) {
      nextForm.labelPlacement = nextForm.labelPosition;
    }
    delete nextForm.labelPosition;
    delete nextForm.hideRequiredAsterisk;

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
  }

  return normalized;
}
