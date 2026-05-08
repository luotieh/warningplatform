import type { UserInfo } from '@vben/types';

import { getPermissionApi } from './auth';

export async function getUserInfoApi(): Promise<UserInfo> {
  try {
    const bundle = await getPermissionApi();
    const u = bundle.user;
    const roles = (bundle.roles ?? []).map(
      (r: { code?: string; name?: string }) => r.code ?? r.name ?? '',
    );

    return {
      userId: u.user_id,
      username: u.user_name,
      realName: u.nick_name || u.user_name,
      avatar: u.avatar || '',
      desc: '',
      homePath: '/dashboard',
      token: '',
      roles,
    };
  } catch {
    console.warn('[UserInfo] IAM 接口不可用，使用本地降级用户');
    return {
      userId: '',
      username: 'user',
      realName: '用户',
      avatar: '',
      desc: '',
      homePath: '/dashboard',
      token: '',
      roles: [],
    };
  }
}
