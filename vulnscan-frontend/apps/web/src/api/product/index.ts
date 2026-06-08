import { baseRequestClient, requestClient } from '#/api/request';
import { normalizePagedResponse } from '#/api/helpers';

export interface Product {
  id: string;
  name: string;
  vendor: string;
  category: string;
  description: string;
  homepage: string;
  logo_url: string;
  cpe_prefix: string;
  tags: string[];
  aliases: string[];
  created_at: string;
  updated_at: string;
  poc_count?: number;
  fingerprint_count?: number;
  vuln_count?: number;
}

export async function getProductList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/products/list', { params });
  return normalizePagedResponse<Product>(res);
}

export function getProductDetail(id: string) {
  return requestClient.get<Product>(`/products/${id}`);
}

export function searchProducts(keyword: string) {
  return requestClient.get<Product[]>('/products/search', { params: { keyword } });
}

export function createProduct(data: Partial<Product>) {
  return requestClient.post<Product>('/products', data);
}

export function updateProduct(id: string, data: Partial<Product>) {
  return requestClient.put(`/products/${id}`, data);
}

export function deleteProduct(id: string) {
  return requestClient.delete(`/products/${id}`);
}

export function backfillProducts() {
  return requestClient.post<{ poc_updated: number; fingerprint_updated: number }>('/products/backfill');
}

export interface VendorGroup {
  vendor: string;
  count: number;
}

export interface CategoryGroup {
  category: string;
  count: number;
}

export interface ProductSummary {
  vendors: VendorGroup[];
  categories: CategoryGroup[];
}

export function getProductSummary() {
  return requestClient.get<ProductSummary>('/products/summary');
}

export function reclassifyProducts() {
  return requestClient.post<{ updated: number }>('/products/reclassify');
}
