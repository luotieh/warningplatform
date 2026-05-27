import type { AuthApi } from '#/api/core/auth';

import { requestClient } from '#/api/request';

// ========== TOTP ==========
export interface TotpSecret {
  qr_code: string;
  totp: {
    secret: string;
    issuer: string;
    account: string;
    url: string;
  };
}

export interface TotpDevice {
  id: string;
  device_name: string;
  last_used_at: string;
  created_at: string;
}

export function totpGenerateSecret(data: { user: string; device_name: string; account_name?: string }) {
  return requestClient.post<TotpSecret>('/iam/auth/totp/generate-secret', data);
}
export function totpVerify(data: { user: string; code: string }) {
  return requestClient.post<{ valid: boolean }>('/iam/auth/totp/verify', data);
}
export function totpGetDeviceCount(user: string) {
  return requestClient.get<{ count: number }>(`/iam/auth/totp/${user}/device-count`);
}
export function totpGetDevices(user: string) {
  return requestClient.get<TotpDevice[]>(`/iam/auth/totp/${user}/devices`);
}
export function totpDeleteDevice(user: string, id: string) {
  return requestClient.delete(`/iam/auth/totp/${user}/${id}`);
}
export function totpEnable(user: string) {
  return requestClient.post(`/iam/auth/totp/${user}/enable`);
}
export function totpDisable(user: string) {
  return requestClient.post(`/iam/auth/totp/${user}/disable`);
}

// ========== WebAuthn ==========
export interface WebAuthnCredential {
  id: string;
  name: string;
  credential_type: string;
  created_at: string;
  last_used_at: string;
}

export interface WebAuthnRegistrationOptions {
  publicKey: PublicKeyCredentialCreationOptions;
}

export interface WebAuthnLoginOptions {
  publicKey: PublicKeyCredentialRequestOptions;
}

export function webauthnListCredentials() {
  return requestClient.get<WebAuthnCredential[]>('/iam/auth/webauthn/credentials');
}
export function webauthnDeleteCredential(id: string) {
  return requestClient.delete(`/iam/auth/webauthn/credentials/${id}`);
}
export function webauthnRenameCredential(id: string, data: { name: string }) {
  return requestClient.put(`/iam/auth/webauthn/credentials/${id}`, data);
}
export function webauthnRegisterBegin() {
  return requestClient.post<{ options: WebAuthnRegistrationOptions; session_id: string }>(
    '/iam/auth/webauthn/register/begin',
  );
}
export function webauthnRegisterFinish(
  sessionId: string,
  deviceName: string,
  body: Record<string, unknown>,
) {
  return requestClient.post('/iam/auth/webauthn/register/finish', body, {
    params: { session_id: sessionId, device_name: deviceName },
  });
}

// ========== Federation 第三方登录 ==========
export async function federationListProviders() {
  const res = await requestClient.get<{ providers?: string[] }>(
    '/iam/auth/federation/providers',
  );
  return Array.isArray(res?.providers) ? res.providers : [];
}

export function federationAuthorizeUrl(provider: string, redirectUri?: string) {
  return requestClient.post<{ auth_url: string; state: string }>(
    `/iam/auth/federation/${provider}/authorize-url`,
    redirectUri ? { redirect_uri: redirectUri } : undefined,
  );
}

// ========== WebAuthn 登录 ==========
export function webauthnLoginBegin(account: string) {
  return requestClient.post<{ options: WebAuthnLoginOptions; session_id: string }>(
    '/iam/auth/webauthn/login/begin',
    { account },
  );
}

export function webauthnLoginFinish(sessionId: string, body: Record<string, unknown>) {
  return requestClient.post<AuthApi.LoginResult>('/iam/auth/webauthn/login/finish', body, {
    params: { session_id: sessionId },
  });
}
