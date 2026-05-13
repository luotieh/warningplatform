import { baseRequestClient } from '#/api/request';
import { normalizeListResponse } from '#/api/helpers';

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
  return normalizeListResponse<ModuleInfo>(res);
}

export async function getPipelineStages() {
  const res = await baseRequestClient.get<any>('/pipeline/stages');
  return normalizeListResponse<StageInfo>(res);
}

export async function getPipelineProfiles() {
  const res = await baseRequestClient.get<any>('/pipeline/profiles');
  return normalizeListResponse<ProfileInfo>(res);
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
  return normalizeListResponse<ModuleConfigInfo>(res);
}
