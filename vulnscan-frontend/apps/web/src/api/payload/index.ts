import { baseRequestClient, requestClient } from '#/api/request';
import { normalizeListResponse, normalizePagedResponse } from '#/api/helpers';

export interface VulnPayload {
  id: number;
  category: string;
  name: string;
  value: string;
  type: string;
  databases: string;
  expect: string;
  context: string;
  tags: string;
  severity: string;
  description: string;
  enabled: boolean;
  sort_order: number;
  created_at: string;
  updated_at: string;
}

export interface VulnPayloadPattern {
  id: number;
  category: string;
  name: string;
  pattern: string;
  description: string;
  severity: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface VulnPayloadConfig {
  id: number;
  category: string;
  config_key: string;
  config_val: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface PayloadListResult {
  items: VulnPayload[];
  total: number;
}

export interface PatternListResult {
  items: VulnPayloadPattern[];
  total: number;
}

export async function getPayloadList(params?: Record<string, any>): Promise<PayloadListResult> {
  const res = await baseRequestClient.get<any>('/payloads/list', { params });
  return normalizePagedResponse<VulnPayload>(res);
}

export function getPayloadDetail(id: number) {
  return requestClient.get<VulnPayload>(`/payloads/${id}`);
}

export function createPayload(data: Partial<VulnPayload>) {
  return requestClient.post('/payloads', data);
}

export function updatePayload(id: number, data: Partial<VulnPayload>) {
  return requestClient.put(`/payloads/${id}`, data);
}

export function deletePayload(id: number) {
  return requestClient.delete(`/payloads/${id}`);
}

export function batchCreatePayloads(payloads: Partial<VulnPayload>[]) {
  return requestClient.post('/payloads/batch', { payloads });
}

export async function getPatternList(params?: Record<string, any>): Promise<PatternListResult> {
  const res = await baseRequestClient.get<any>('/payloads/patterns', { params });
  return normalizePagedResponse<VulnPayloadPattern>(res);
}

export function getPatternDetail(id: number) {
  return requestClient.get<VulnPayloadPattern>(`/payloads/patterns/${id}`);
}

export function createPattern(data: Partial<VulnPayloadPattern>) {
  return requestClient.post('/payloads/patterns', data);
}

export function updatePattern(id: number, data: Partial<VulnPayloadPattern>) {
  return requestClient.put(`/payloads/patterns/${id}`, data);
}

export function deletePattern(id: number) {
  return requestClient.delete(`/payloads/patterns/${id}`);
}

export function batchCreatePatterns(patterns: Partial<VulnPayloadPattern>[]) {
  return requestClient.post('/payloads/patterns/batch', { patterns });
}

export async function getConfigList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/payloads/configs', { params });
  return normalizeListResponse<VulnPayloadConfig>(res);
}

export function getConfigDetail(id: number) {
  return requestClient.get<VulnPayloadConfig>(`/payloads/configs/${id}`);
}

export function createConfig(data: Partial<VulnPayloadConfig>) {
  return requestClient.post('/payloads/configs', data);
}

export function updateConfig(id: number, data: Partial<VulnPayloadConfig>) {
  return requestClient.put(`/payloads/configs/${id}`, data);
}

export function deleteConfig(id: number) {
  return requestClient.delete(`/payloads/configs/${id}`);
}

export function getCategories() {
  return requestClient.get<string[]>('/payloads/categories');
}
