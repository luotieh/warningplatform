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
  children?: SyncMenuItem[];
}

export interface SyncResult {
  created: number;
  updated: number;
  unchanged: number;
}

export function syncFrontendRoutes(items: SyncMenuItem[]) {
  return requestClient.post<SyncResult>('/frontends/sync', { items });
}
