import { baseRequestClient } from '#/api/request';

export interface ModuleInfo {
  id: string;
  name: string;
  category: string;
}

export interface StageInfo {
  name: string;
  modules: ModuleInfo[];
}

export interface ProfileInfo {
  id: string;
  name: string;
  description: string;
  modules_count: number;
}

export async function getPipelineModules() {
  const res = await baseRequestClient.get<any>('/pipeline/modules');
  const body = (res as Record<string, unknown>).data ?? res;
  return ((body as { data?: ModuleInfo[] }).data ?? []) as ModuleInfo[];
}

export async function getPipelineStages() {
  const res = await baseRequestClient.get<any>('/pipeline/stages');
  const body = (res as Record<string, unknown>).data ?? res;
  return ((body as { data?: StageInfo[] }).data ?? []) as StageInfo[];
}

export async function getPipelineProfiles() {
  const res = await baseRequestClient.get<any>('/pipeline/profiles');
  const body = (res as Record<string, unknown>).data ?? res;
  return ((body as { data?: ProfileInfo[] }).data ?? []) as ProfileInfo[];
}

export interface ModuleParam {
  key: string;
  name: string;
  type: string;
  default_value: any;
  description: string;
  required: boolean;
  options?: { value: any; label: string }[];
  min?: number;
  max?: number;
}

export interface ModuleConfigInfo {
  id: string;
  name: string;
  category: string;
  params: ModuleParam[];
}

export async function getModuleConfigs() {
  const res = await baseRequestClient.get<any>('/pipeline/modules/config');
  const body = (res as Record<string, unknown>).data ?? res;
  return ((body as { data?: ModuleConfigInfo[] }).data ?? []) as ModuleConfigInfo[];
}
