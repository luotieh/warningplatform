/**
 * OAuth2 / SSO 相关接口
 *
 * 当前仅封装 IAM 内部跨应用 SSO 所需的"获取 authorization code"接口。
 * 业务系统作为 client 拿到 code 后，可走标准 OAuth2 流程换取 access_token。
 *
 * 注意：OAuth2 端点遵循标准协议响应格式（成功 { code, redirect_uri, state }；
 * 失败 { error, error_description }），因此不能走 IAM 业务格式的 requestClient
 * （那个拦截器会因 code !== 2000 直接 reject 且丢失错误信息）。
 * 这里使用 baseRequestClient + 手动解析。
 */
import { baseRequestClient } from '#/api/request';

export namespace OAuth2Api {
  export interface SSOCodeReq {
    /** 应用 client_id（IAM 应用主键 id 即 client_id） */
    client_id: string;
    /** 子应用回调地址，必须与应用配置中的 redirect_uri 之一匹配 */
    redirect_uri: string;
    /** OAuth2 scope，默认 "openid profile" */
    scope?: string;
    /** CSRF state，建议随机字符串 */
    state?: string;
    /** PKCE 挑战码（可选） */
    code_challenge?: string;
    code_challenge_method?: string;
    /** OIDC nonce */
    nonce?: string;
  }

  export interface SSOCodeResp {
    code: string;
    redirect_uri: string;
    state?: string;
  }
}

/**
 * 获取 SSO authorization code
 * 后端：POST /auth/oauth2/sso/code（需登录）
 *
 * 失败时 throw new Error(error_description || error)，便于上层显示真实原因
 */
export async function fetchSSOCode(
  data: OAuth2Api.SSOCodeReq,
): Promise<OAuth2Api.SSOCodeResp> {
  try {
    const res = await baseRequestClient.post<any>(
      '/auth/oauth2/sso/code',
      data,
    );
    const body = res?.data ?? res;
    if (!body || !body.code) {
      const reason =
        body?.error_description || body?.error || '响应缺少 code 字段';
      throw new Error(`SSO 授权码获取失败：${reason}`);
    }
    return {
      code: body.code,
      redirect_uri: body.redirect_uri || data.redirect_uri,
      state: body.state || data.state,
    };
  } catch (err: any) {
    // axios 抛出的 error 上挂着原始响应体
    const respData = err?.response?.data;
    if (respData) {
      const reason =
        respData.error_description ||
        respData.error ||
        respData.msg ||
        respData.message ||
        '未知错误';
      throw new Error(reason);
    }
    throw err;
  }
}
