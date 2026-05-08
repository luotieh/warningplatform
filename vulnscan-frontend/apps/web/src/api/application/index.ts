import { baseRequestClient, requestClient } from '#/api/request';

export namespace AppApi {
  /** iframe 自定义参数注入方式 */
  export type IframeParamMode = 'hash' | 'postmessage' | 'query';

  /** iframe 自定义参数 */
  export interface IframeParam {
    /** 参数名 */
    key: string;
    /** 参数值 */
    value: string;
    /** 注入方式 */
    mode: IframeParamMode;
    /** 备注（仅 UI 展示） */
    description?: string;
  }

  /** 应用访问白名单 IP 条目 */
  export interface ApplicationWhiteIP {
    /** IP 或 CIDR 地址 */
    ip: string;
    /** 描述说明 */
    description?: string;
  }

  export interface AppItem {
    id: string;
    app_name: string;
    app_type: 'service' | 'spa' | 'web';
    app_secret?: string;
    logo: string;
    enabled: boolean;
    display_name: string;
    sort: number;
    app_notes: string;
    redirect_uri: string[];
    grant_types: string[];
    response_types: string[];
    iframe_uri: string;
    /**
     * iframe 自定义注入参数
     * - mode=query   → 拼到 URL ?key=value
     * - mode=hash    → 拼到 URL #key=value
     * - mode=postmessage → iframe load 后 window.postMessage 下发
     */
    iframe_params?: IframeParam[];
    /** 访问白名单 IP/CIDR 列表 */
    allow_ips?: ApplicationWhiteIP[];
    display: boolean;
    /**
     * 菜单是否由 IAM 统一管理
     * - true（默认）：应用菜单从 IAM 拉取并渲染在左侧
     * - false：应用自管菜单，切换后直接 iframe 加载 iframe_uri，IAM 仅透传 SSO
     */
    menu_managed_by_iam?: boolean;
    access_token_expire: number;
    created_at: string;
    updated_at: string;
  }

  export interface AppCreateReq {
    app_name: string;
    app_type?: string;
    logo?: string;
    enabled?: boolean;
    display_name?: string;
    sort?: number;
    app_notes?: string;
    redirect_uri?: string[];
    grant_types?: string[];
    iframe_uri?: string;
    iframe_params?: IframeParam[];
    allow_ips?: ApplicationWhiteIP[];
    display?: boolean;
    menu_managed_by_iam?: boolean;
    access_token_expire?: number;
  }

  export interface AppUpdateReq {
    app_name?: string;
    app_type?: string;
    logo?: string;
    enabled?: boolean;
    display_name?: string;
    sort?: number;
    app_notes?: string;
    redirect_uri?: string[];
    grant_types?: string[];
    iframe_uri?: string;
    iframe_params?: IframeParam[];
    allow_ips?: ApplicationWhiteIP[];
    display?: boolean;
    menu_managed_by_iam?: boolean;
    access_token_expire?: number;
  }
}

export async function getAppList(params?: {
  index?: number;
  size?: number;
  app_name?: string;
  enabled?: string;
  display?: string;
}) {
  const res = await baseRequestClient.get<any>('/applications', { params });
  const body = res.data ?? res;
  return {
    items: (body.data ?? []) as AppApi.AppItem[],
    total: body.count ?? 0,
  };
}

export function getAppDetail(id: string) {
  return requestClient.get<AppApi.AppItem>(`/applications/${id}`);
}

/** 创建应用；返回包含明文密钥的 IdSecret */
export function createApp(data: AppApi.AppCreateReq) {
  return requestClient.post<{ id: string; secret: string }>(
    '/applications',
    data,
  );
}

export function updateApp(id: string, data: AppApi.AppUpdateReq) {
  return requestClient.put(`/applications/${id}`, data);
}

export function deleteApp(id: string) {
  return requestClient.delete(`/applications/${id}`);
}

/** 重置应用密钥；返回新的 IdSecret（明文密钥仅此一次可见） */
export function resetAppSecret(id: string) {
  return requestClient.put<{ id: string; secret: string }>(
    `/applications/secret/${id}`,
  );
}
