import { baseRequestClient, requestClient } from '#/api/request';
import { normalizePagedResponse } from '#/api/helpers';

export interface PromptTemplate {
  id: string;
  name: string;
  scene: string;
  description?: string;
  system_prompt: string;
  user_prompt: string;
  output_format?: string;
  variables?: string;
  model_name?: string;
  temperature: number;
  max_tokens: number;
  enabled: boolean;
  is_builtin: boolean;
  version: number;
  created_at: string;
  updated_at: string;
}

export const SCENE_OPTIONS = [
  { label: 'AI预审分析', value: 'ai_preaudit' },
  { label: 'AI分类打标', value: 'ai_classify' },
  { label: '情报分析', value: 'intel_analysis' },
  { label: '自定义', value: 'custom' },
];

export const SCENE_MAP: Record<string, string> = {
  ai_preaudit: 'AI预审分析',
  ai_classify: 'AI分类打标',
  intel_analysis: '情报分析',
  custom: '自定义',
};

export async function getPromptList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/prompt-templates', { params });
  return normalizePagedResponse<PromptTemplate>(res);
}

export function getPromptDetail(id: string) {
  return requestClient.get<PromptTemplate>(`/prompt-templates/${id}`);
}

export function getPromptByScene(scene: string) {
  return requestClient.get<PromptTemplate>('/prompt-templates/by-scene', {
    params: { scene },
  });
}

export function createPrompt(data: Partial<PromptTemplate>) {
  return requestClient.post('/prompt-templates', data);
}

export function updatePrompt(id: string, data: Partial<PromptTemplate>) {
  return requestClient.put(`/prompt-templates/${id}`, data);
}

export function deletePrompt(id: string) {
  return requestClient.delete(`/prompt-templates/${id}`);
}

export function togglePrompt(id: string) {
  return requestClient.post(`/prompt-templates/${id}/toggle`);
}
