import { requestClient } from '#/api/request';

/**
 * 公共认证接口（注册、忘记密码、无密码登录、验证码等）
 * 这些接口不需要登录态，使用 baseRequestClient 避免 token 干扰
 */

export namespace PublicApi {
  export interface ForgotPasswordReq {
    account: string;
    captcha_key?: string;
    answer?: string;
    point?: number[];
    angle?: number;
  }

  export interface ForgotPasswordResp {
    reset_token: string;
    expires_in: number;
    message: string;
  }

  export interface VerifyResetCodeReq {
    reset_token: string;
    code: string;
  }

  export interface ResetPasswordReq {
    reset_token: string;
    code: string;
    new_password: string;
  }

  export interface SendMagicLinkReq {
    email: string;
    captcha_key?: string;
    answer?: string;
  }

  export interface VerifyMagicLinkReq {
    token: string;
  }

  export interface SendSMSCodeReq {
    phone: string;
    captcha_key?: string;
    answer?: string;
  }

  export interface VerifySMSCodeReq {
    phone: string;
    code: string;
  }

  export interface RegisterReq {
    user_name: string;
    password: string;
    nick_name?: string;
    email?: string;
    phone?: string;
    captcha_key?: string;
    answer?: string;
    invite_code?: string;
  }

  export interface CaptchaResult {
    captcha_key: string;
    image_base64?: string;
    thumb_base64?: string;
    tile_base64?: string;
    tile_width?: number;
    tile_height?: number;
    tile_x?: number;
    tile_y?: number;
    audio_base64?: string;
    validy?: number;
    [key: string]: any;
  }
}

// 忘记密码 - 三步流程
export function forgotPassword(data: PublicApi.ForgotPasswordReq) {
  return requestClient.post<PublicApi.ForgotPasswordResp>(
    '/auth/forgot-password',
    data,
  );
}

export function verifyResetCode(data: PublicApi.VerifyResetCodeReq) {
  return requestClient.post('/auth/verify-reset-code', data);
}

export function resetPassword(data: PublicApi.ResetPasswordReq) {
  return requestClient.post('/auth/reset-password', data);
}

// 邮箱 Magic Link 登录
export function sendMagicLink(data: PublicApi.SendMagicLinkReq) {
  return requestClient.post('/auth/magic-link/send', data);
}

export function verifyMagicLink(data: PublicApi.VerifyMagicLinkReq) {
  return requestClient.post<any>('/auth/magic-link/verify', data);
}

// 短信验证码登录
export function sendSMSCode(data: PublicApi.SendSMSCodeReq) {
  return requestClient.post('/auth/sms-login/send', data);
}

export function verifySMSCode(data: PublicApi.VerifySMSCodeReq) {
  return requestClient.post<any>('/auth/sms-login/verify', data);
}

// 用户注册
export function registerUser(data: PublicApi.RegisterReq) {
  return requestClient.post('/auth/register', data);
}

// 验证码
export function getCaptcha(type: 'audio' | 'click' | 'image' | 'math' | 'rotate' | 'slide' = 'math') {
  return requestClient.get<PublicApi.CaptchaResult>(`/auth/captcha/${type}`);
}

export function checkCaptcha(data: { key: string; answer?: string; point?: number[]; angle?: number }) {
  return requestClient.post<{ success: boolean }>('/auth/captcha/check', data);
}

// 修改过期密码
export function changeExpiredPassword(data: {
  account: string;
  old_password: string;
  new_password: string;
}) {
  return requestClient.post('/auth/change-expired-password', data);
}

// 登录页公开配置
export interface LoginSettings {
  require_captcha: boolean;
  captcha_type: string;
  allow_register: boolean;
  allow_password_login: boolean;
  allow_email_login: boolean;
  allow_phone_login: boolean;
  allow_webauthn: boolean;
}

export function getLoginSettings() {
  return requestClient.get<LoginSettings>('/auth/login-settings');
}
