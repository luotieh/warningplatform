/**
 * SSO 单点登录工具
 *
 * 两种模式：
 *  - 生产环境（嵌入部署）：后端 Token Relay
 *    前端跳 /sso/login → 后端处理 OAuth2 全流程 → 回调 /auth/sso-callback?access_token=xxx
 *
 *  - 开发环境（可选）：纯前端 PKCE
 *    前端直接跳 IAM /auth/oauth2/authorize → 回调 /auth/sso-callback → 前端用 code 换 token
 */

const SSO_STATE_KEY = 'iam_sso_state';
const SSO_VERIFIER_KEY = 'iam_sso_verifier';
const SSO_NEXT_KEY = 'iam_sso_next';

function getEnv(key: string, defaultValue = ''): string {
  return (import.meta.env[key] as string) ?? defaultValue;
}

export function isSSOMode(): boolean {
  return getEnv('VITE_AUTH_MODE', 'local') === 'sso';
}

function useTokenRelay(): boolean {
  return !getEnv('VITE_IAM_BASE_URL') || !getEnv('VITE_SSO_CLIENT_ID');
}

// ——————————— Token Relay 模式（生产，零配置）———————————

/**
 * 发起 SSO 登录
 *
 * 生产环境：跳 /sso/login（后端 Token Relay）
 * 开发环境（配了 IAM_BASE_URL + CLIENT_ID）：纯前端 PKCE
 */
export async function redirectToSSO(nextPath?: string): Promise<void> {
  if (nextPath) {
    sessionStorage.setItem(SSO_NEXT_KEY, nextPath);
  }

  if (useTokenRelay()) {
    window.location.href = '/sso/login';
    return;
  }

  await redirectWithPKCE(nextPath);
}

// ——————————— 纯前端 PKCE 模式（开发）———————————

function base64UrlEncode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let str = '';
  for (const b of bytes) str += String.fromCodePoint(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256(plain: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(plain));
}

async function redirectWithPKCE(_nextPath?: string): Promise<void> {
  const iamBaseUrl = getEnv('VITE_IAM_BASE_URL');
  const clientId = getEnv('VITE_SSO_CLIENT_ID');
  const scopes = getEnv('VITE_SSO_SCOPES', 'openid profile');
  const callbackPath = getEnv('VITE_SSO_CALLBACK_PATH', '/auth/sso-callback');

  const state = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
  sessionStorage.setItem(SSO_STATE_KEY, state);

  const redirectUri = `${window.location.origin}${callbackPath}`;
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes,
    state,
  });

  const verifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64UrlEncode(await sha256(verifier));
  sessionStorage.setItem(SSO_VERIFIER_KEY, verifier);
  params.set('code_challenge', challenge);
  params.set('code_challenge_method', 'S256');

  window.location.href = `${iamBaseUrl}/auth/oauth2/authorize?${params.toString()}`;
}

// ——————————— 回调处理 ———————————

export interface SSOTokenResult {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

/**
 * 处理纯前端 PKCE 回调：校验 state → 用 code 换 token
 */
export async function handleSSOCallback(): Promise<{
  tokens: SSOTokenResult;
  nextPath: string;
}> {
  const url = new URL(window.location.href);
  const iamBaseUrl = getEnv('VITE_IAM_BASE_URL');
  const clientId = getEnv('VITE_SSO_CLIENT_ID');
  const callbackPath = getEnv('VITE_SSO_CALLBACK_PATH', '/auth/sso-callback');

  const error = url.searchParams.get('error');
  if (error) {
    throw new Error(
      `${error}: ${url.searchParams.get('error_description') || ''}`,
    );
  }

  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state) {
    throw new Error('Missing code or state in callback URL');
  }

  const savedState = sessionStorage.getItem(SSO_STATE_KEY);
  sessionStorage.removeItem(SSO_STATE_KEY);
  if (!savedState || savedState !== state) {
    throw new Error('State mismatch (potential CSRF)');
  }

  const verifier = sessionStorage.getItem(SSO_VERIFIER_KEY) || '';
  sessionStorage.removeItem(SSO_VERIFIER_KEY);

  const nextPath = sessionStorage.getItem(SSO_NEXT_KEY) || '/';
  sessionStorage.removeItem(SSO_NEXT_KEY);

  const redirectUri = `${window.location.origin}${callbackPath}`;
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
  });
  if (verifier) {
    body.set('code_verifier', verifier);
  }

  const resp = await fetch(`${iamBaseUrl}/auth/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Token exchange failed: ${resp.status} ${text}`);
  }

  const tokens: SSOTokenResult = await resp.json();
  return { tokens, nextPath };
}

function extractTokenFromParams(params: URLSearchParams): SSOTokenResult | null {
  const accessToken = params.get('access_token');
  if (!accessToken) return null;

  return {
    access_token: accessToken,
    token_type: params.get('token_type') || 'Bearer',
    expires_in: Number.parseInt(params.get('expires_in') || '0', 10),
    refresh_token: params.get('refresh_token') || undefined,
    id_token: params.get('id_token') || undefined,
    scope: params.get('scope') || undefined,
  };
}

/**
 * 解析 URL 中的 token（后端 Token Relay 模式使用）
 * 优先从 query 参数解析，回退到 hash fragment
 */
export function parseTokenFromURL(): SSOTokenResult | null {
  const url = new URL(window.location.href);
  return (
    extractTokenFromParams(url.searchParams) ||
    extractTokenFromParams(new URLSearchParams(window.location.hash.slice(1)))
  );
}

/** @deprecated 使用 parseTokenFromURL 代替 */
export const parseTokenFromFragment = parseTokenFromURL;
