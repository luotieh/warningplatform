import { requestClient } from '#/api/request';

export interface SyncMenuItem {
  name: string;
  title: string;
  path?: string;
  component?: string;
  icon?: string;
  menu_type?: number;
  rank?: number;
  redirect?: string;
  show_link?: boolean;
  hide_in_menu?: boolean;
  unique_value?: string;
  backend_refs?: string[];
  children?: SyncMenuItem[];
}

export interface SyncResult {
  created: number;
  updated: number;
  unchanged: number;
}

/** 使用应用凭证同步到 IAM（需特权账号）；勿用 SDK 默认 /frontends/sync（非 admin 会 403） */
export function syncFrontendRoutes(items: SyncMenuItem[]) {
  return requestClient.post<SyncResult>('/system/iam/sync-frontends', { items });
}
