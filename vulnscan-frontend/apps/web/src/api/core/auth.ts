import { baseRequestClient, requestClient } from '#/api/request';

export namespace AuthApi {
  export interface LoginParams {
    account: string;
    password: string;
    captcha_key?: string;
    answer?: string;
    point?: number[];
    angle?: number;
    totp_code?: string;
  }

  export interface LoginResult {
    session: string;
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_at: number;
    refresh_expires_at: number;
    user_id: string;
    account: string;
    issued_at: number;
    require_totp: boolean;
    allow_totp: boolean;
    login_method: string;
    locked_until: number;
    password_expired: boolean;
    invalid_credentials: boolean;
  }

  export interface RefreshTokenResult {
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_at: number;
    refresh_expires_at: number;
    user_id: string;
    account: string;
    issued_at: number;
  }

  export interface PermissionUser {
    user_id: string;
    user_name: string;
    nick_name: string;
    avatar: string;
    email: string;
    phone: string;
    status: number;
    mfa: number;
    primary_organize_id: string;
    primary_department_id: string;
  }

  export interface RoleSummary {
    id: string;
    name: string;
    code?: string;
    description?: string;
    enabled?: boolean;
  }

  export interface AppSummary {
    id: string;
    app_name: string;
    display_name?: string;
  }

  export interface OrganizeSummary {
    id: string;
    name: string;
    code?: string;
  }

  export interface DepartmentSummary {
    id: string;
    name: string;
    code?: string;
  }

  export interface PositionSummary {
    id: string;
    name: string;
    code?: string;
  }

  export interface VisibleMenu {
    id: string;
    name: string;
    title: string;
    app?: string;
    parent_id?: string;
    path?: string;
    component?: string;
    redirect?: string;
    icon?: string;
    unique_value?: string;
    menu_type?: number | string;
    sort?: number;
    show_link?: boolean;
    children?: VisibleMenu[];
    buttons?: VisibleMenu[];
  }

  export interface MenuGroup {
    app_id: string;
    app_name: string;
    menus: VisibleMenu[];
  }

  export interface PermissionBundle {
    user: PermissionUser;
    roles: RoleSummary[];
    applications: AppSummary[];
    organizes: OrganizeSummary[];
    departments: DepartmentSummary[];
    positions: PositionSummary[];
    generated_at: string;
  }
}

export async function loginApi(data: AuthApi.LoginParams) {
  return requestClient.post<AuthApi.LoginResult>('/auth/login', data);
}

export async function refreshTokenApi(): Promise<AuthApi.RefreshTokenResult> {
  const refreshToken = localStorage.getItem('iam_refresh_token') || '';
  const res = await baseRequestClient.post<{ code: number; data: AuthApi.RefreshTokenResult }>('/auth/refresh', {
    refresh_token: refreshToken,
  });
  const envelope = (res as Record<string, unknown>).data as Record<string, unknown> | undefined;
  return (envelope?.data ?? envelope) as AuthApi.RefreshTokenResult;
}

export async function logoutApi() {
  return requestClient.post('/auth/logout');
}

export async function getPermissionApi(appId?: string) {
  const params = appId ? { app: appId } : {};
  return requestClient.get<AuthApi.PermissionBundle>('/me/profile', {
    params,
  });
}

/**
 * 单独拉取当前用户可见菜单（按应用分组）
 *   GET /me/menus?app_id=
 */
export async function getUserMenusApi(appId?: string) {
  const params = appId ? { app_id: appId } : {};
  return requestClient.get<AuthApi.MenuGroup[]>('/me/menus', { params });
}

/**
 * 收集 access codes：
 * - 角色 code：用于 role 维度的指令判断
 * - 菜单 path / name：粗粒度的菜单可见性
 * - 按钮（menu_type === 4）的 unique_value：细粒度的按钮级权限
 *
 * 实现：并行拉 /me/profile（取角色） + /me/menus（取菜单），
 * 避免在 /me/profile 上重复传输菜单数据。
 */
export async function getAccessCodesApi() {
  try {
    const [bundle, menuGroups] = await Promise.all([
      getPermissionApi(),
      getUserMenusApi(),
    ]);

    const codes = new Set<string>();
    if (bundle?.roles) {
      for (const role of bundle.roles) {
        if (role?.code) codes.add(String(role.code));
        if (role?.name) codes.add(String(role.name));
      }
    }

    const walk = (list: AuthApi.VisibleMenu[]) => {
      for (const node of list || []) {
        if (!node) continue;
        if (node.unique_value) codes.add(String(node.unique_value));
        if (node.path) codes.add(String(node.path));
        if (node.name) codes.add(String(node.name));
        if (Array.isArray(node.children)) walk(node.children);
        if (Array.isArray(node.buttons)) walk(node.buttons);
      }
    };

    for (const group of menuGroups || []) {
      if (group?.menus) walk(group.menus);
    }

    return [...codes];
  } catch {
    console.warn('[AccessCodes] IAM 接口不可用，返回空权限码');
    return [];
  }
}
