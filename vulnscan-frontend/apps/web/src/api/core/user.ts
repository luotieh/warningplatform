import type { UserInfo } from '@vben/types';

import { getPermissionApi } from './auth';

export async function getUserInfoApi(): Promise<UserInfo> {
  try {
    const bundle = await getPermissionApi();
    const u = bundle.user;
    const roles = (bundle.roles ?? []).map(
      (r: { code?: string; id?: string; name?: string }) =>
        r.code ?? r.name ?? r.id ?? '',
    );

    return {
      userId: u.user_id,
      username: u.user_name,
      realName: u.nick_name || u.user_name,
      avatar: u.avatar || '',
      desc: '',
      homePath: '/workbench',
      token: '',
      roles,
    };
  } catch (err: unknown) {
    const status = (err as { response?: { status?: number } })?.response?.status;
    if (status === 403) {
      console.error('[UserInfo] 无权访问用户画像（/iam/profile），请检查 IAM 角色与菜单权限');
      throw err;
    }
    console.warn('[UserInfo] IAM 接口不可用，使用本地降级用户');
    return {
      userId: '',
      username: 'user',
      realName: '用户',
      avatar: '',
      desc: '',
      homePath: '/workbench',
      token: '',
      roles: [],
    };
  }
}
