import type { AuthApi } from '#/api/core/auth';

import { requestClient } from '#/api/request';

export namespace ProfileApi {
  export interface ProfileInfo {
    user_id: string;
    user_name: string;
    nick_name: string;
    email: string;
    phone: string;
    avatar: string;
    status: number;
    mfa: boolean | number;
    remark: string;
  }

  export interface UpdateProfileReq {
    nick_name?: string;
    avatar?: string;
    phone?: string;
    email?: string;
    remark?: string;
  }

  export interface ChangePasswordReq {
    old_password: string;
    new_password: string;
    captcha_key?: string;
    answer?: string;
    totp_code?: string;
  }

  export interface SessionItem {
    session_id: string;
    issued_at: number;
    expires_at: number;
    last_active_at: number;
    client_ip?: string;
    user_agent?: string;
  }
}

export function getProfile() {
  return requestClient.get<ProfileApi.ProfileInfo>('/auth/profile');
}

export function updateProfile(data: ProfileApi.UpdateProfileReq) {
  return requestClient.put('/auth/profile', data);
}

export function changePassword(data: ProfileApi.ChangePasswordReq) {
  return requestClient.post('/auth/change-password', data);
}

export function listSessions() {
  return requestClient.get<ProfileApi.SessionItem[]>('/auth/sessions');
}

export function logoutAllSessions() {
  return requestClient.post('/auth/logout-all');
}

export function switchContext(data: { organize_id?: string; department_id?: string }) {
  return requestClient.post<AuthApi.LoginResult>('/auth/switch-context', data);
}

export function trustDevice(data: { device_fingerprint: string; device_name?: string }) {
  return requestClient.post<{ device_hash: string; trusted: boolean; expires_in: number }>(
    '/auth/devices/trust',
    data,
  );
}

export function untrustDevice(data: { device_fingerprint: string }) {
  return requestClient.delete('/auth/devices/trust', { data });
}

export function createRememberMeToken() {
  return requestClient.post<{ remember_me_token: string; expires_in: number }>('/auth/remember-me');
}

export function loginWithRememberMe(data: { remember_me_token: string }) {
  return requestClient.post<{ login: AuthApi.LoginResult; remember_me_token: string }>(
    '/auth/remember-me/login',
    data,
  );
}
