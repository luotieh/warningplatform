<script lang="ts" setup>
import type { VbenFormSchema } from '@vben/common-ui';

import { computed, h, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import { AuthenticationLogin, z } from '@vben/common-ui';
import { $t } from '@vben/locales';
import { updatePreferences } from '@vben/preferences';

import {
  NButton,
  NInput as NaiveInput,
  NModal,
  NSpace,
  NTooltip,
} from 'naive-ui';

import {
  federationAuthorizeUrl,
  federationListProviders,
  webauthnLoginBegin,
  webauthnLoginFinish,
} from '#/api/auth';
import { getCaptcha, getLoginSettings } from '#/api/core/public';
import { message } from '#/adapter/naive';
import { useAuthStore } from '#/store';

defineOptions({ name: 'Login' });

const authStore = useAuthStore();
const router = useRouter();

const requireCaptcha = ref(false);
const captchaType = ref('math');
const captchaKey = ref('');
const captchaImage = ref('');
const captchaAnswer = ref('');
const allowRegister = ref(true);
const allowPasswordLogin = ref(true);
const allowWebAuthn = ref(true);

async function loadLoginSettings() {
  try {
    const settings = await getLoginSettings();
    requireCaptcha.value = settings.require_captcha;
    captchaType.value = settings.captcha_type || 'math';
    allowRegister.value = settings.allow_register;
    allowPasswordLogin.value = settings.allow_password_login !== false;
    allowWebAuthn.value = settings.allow_webauthn !== false;

    if (settings.site_name || settings.copyright) {
      const updates: Record<string, any> = {};
      if (settings.site_name) {
        updates.app = { name: settings.site_name };
      }
      if (settings.copyright || settings.site_name) {
        updates.copyright = {
          companyName: settings.copyright || settings.site_name || '',
          enable: true,
        };
      }
      updatePreferences(updates);
    }
  } catch {
    // 登录配置不可用时走默认表单登录。
  }
}

async function loadCaptcha() {
  if (!requireCaptcha.value) return;
  try {
    const res = await getCaptcha(captchaType.value as any);
    captchaKey.value = res.captcha_key;
    const b64 = res.image_base64 || '';
    captchaImage.value = b64.startsWith('data:')
      ? b64
      : b64
        ? `data:image/png;base64,${b64}`
        : '';
  } catch {
    message.warning('验证码加载失败，请重试');
  }
}

async function handleLogin(values: Record<string, any>) {
  if (!allowPasswordLogin.value) {
    message.warning('当前系统未开启账号密码登录');
    return;
  }

  if (requireCaptcha.value) {
    if (!captchaAnswer.value) {
      message.warning('请输入验证码');
      return;
    }
    values.captcha_key = captchaKey.value;
    values.answer = captchaAnswer.value;
  }

  try {
    const result = await authStore.authLogin(values);

    if (requireCaptcha.value && !result?.userInfo) {
      captchaAnswer.value = '';
      await loadCaptcha();
    }
  } catch (error: any) {
    message.error(error?.message || '登录失败，请稍后重试');
    if (requireCaptcha.value) {
      captchaAnswer.value = '';
      await loadCaptcha();
    }
  }
}

const formSchema = computed((): VbenFormSchema[] => [
  {
    component: 'VbenInput',
    componentProps: {
      placeholder: $t('authentication.usernameTip'),
    },
    fieldName: 'username',
    label: $t('authentication.username'),
    rules: z.string().min(1, { message: $t('authentication.usernameTip') }),
  },
  {
    component: 'VbenInputPassword',
    componentProps: {
      placeholder: $t('authentication.password'),
    },
    fieldName: 'password',
    label: $t('authentication.password'),
    rules: z.string().min(1, { message: $t('authentication.passwordTip') }),
  },
]);

const fedProviders = ref<string[]>([]);

const PROVIDER_LABEL: Record<string, string> = {
  dingtalk: '钉钉',
  gitee: 'Gitee',
  github: 'GitHub',
  google: 'Google',
  lark: '飞书',
  'oauth2-generic': 'OAuth2',
  wecom: '企业微信',
  'wechat-mp': '微信',
};

function getSocialIcon(provider: string) {
  return {
    render() {
      const icons: Record<string, string> = {
        dingtalk:
          '<path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2Zm4.64 7.48-1.3 5.58s-.1.38-.47.2l-2.08-1.58-.75.72s-.06.05-.12.03l.22-1.97 3.85-3.47c.17-.15-.04-.23-.26-.09l-4.76 3-2.07-.65s-.32-.11-.03-.37l8.36-3.24c.16-.06.6-.2.42.53Z"/>',
        gitee:
          '<path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2Zm5 11.5h-5a.5.5 0 0 1-.5-.5V8a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v3.5H17a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5Z"/>',
        github:
          '<path d="M12 2C6.48 2 2 6.49 2 12.03c0 4.43 2.87 8.18 6.84 9.5.5.09.68-.22.68-.48 0-.24-.01-.87-.01-1.7-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.89 1.53 2.34 1.09 2.91.83.09-.65.35-1.09.64-1.34-2.22-.25-4.56-1.11-4.56-4.95 0-1.09.39-1.99 1.03-2.69-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.03A9.57 9.57 0 0 1 12 6.85a9.6 9.6 0 0 1 2.5.34c1.91-1.3 2.75-1.03 2.75-1.03.55 1.38.2 2.4.1 2.65.64.7 1.03 1.6 1.03 2.69 0 3.85-2.34 4.7-4.57 4.94.36.31.68.92.68 1.86 0 1.34-.01 2.42-.01 2.75 0 .27.18.58.69.48A10.02 10.02 0 0 0 22 12.03C22 6.49 17.52 2 12 2Z"/>',
        google:
          '<path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.27-4.74 3.27-8.1Z"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23Z"/><path d="M5.84 14.09A6.69 6.69 0 0 1 5.5 12c0-.72.12-1.42.34-2.09V7.07H2.18A10 10 0 0 0 2 12c0 1.61.39 3.14 1.07 4.49l3.77-2.4Z"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53Z"/>',
        lark:
          '<path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2Zm3.17 14.25-5.93-2.3a.42.42 0 0 1-.24-.43l.72-5.97c.03-.27.39-.34.52-.1l4.2 7.36c.22.39-.04.58-.27.44Z"/>',
        wecom:
          '<path d="M16.7 10.4a.5.5 0 1 0 .5.5.5.5 0 0 0-.5-.5Zm-3.5-1a.5.5 0 1 0 .5.5.5.5 0 0 0-.5-.5ZM12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2Zm5.3 12.4c-.4.7-1 1.2-1.7 1.6l.5 1.5-1.7-.9c-.5.1-1 .2-1.5.2-3.1 0-5.5-2.1-5.5-4.6 0-2.6 2.5-4.6 5.5-4.6s5.5 2.1 5.5 4.6c0 .8-.3 1.6-.8 2.3Z"/>',
        'wechat-mp':
          '<path d="M8.69 11.34a.65.65 0 1 0-.65-.65.65.65 0 0 0 .65.65Zm3.37-.65a.65.65 0 1 0 .65-.65.65.65 0 0 0-.65.65ZM12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2Zm-.12 14.66c-.93 0-1.8-.18-2.58-.52l-2.82.89.73-2.66A6.19 6.19 0 0 1 5.5 11.2c0-3.63 2.86-6.56 6.38-6.56s6.38 2.93 6.38 6.56c0 3.62-2.86 6.56-6.38 6.56v-.1Z"/>',
      };
      const fillIcon = icons[provider];
      if (fillIcon) {
        return h('svg', {
          fill: 'currentColor',
          height: '20',
          innerHTML: fillIcon,
          viewBox: '0 0 24 24',
          width: '20',
        });
      }
      return h(
        'svg',
        {
          fill: 'none',
          height: '20',
          stroke: 'currentColor',
          'stroke-linecap': 'round',
          'stroke-linejoin': 'round',
          'stroke-width': '2',
          viewBox: '0 0 24 24',
          width: '20',
        },
        [
          h('rect', { height: '11', rx: '2', width: '18', x: '3', y: '11' }),
          h('path', { d: 'M7 11V7a5 5 0 0 1 10 0v4' }),
        ],
      );
    },
  };
}

async function handleFederationCallback() {
  const hash = window.location.hash;
  if (!hash || hash.length < 2) return false;

  const params = new URLSearchParams(hash.slice(1));
  const accessToken = params.get('access_token');
  if (!accessToken) {
    const error = params.get('error_description') || params.get('error');
    if (error) {
      message.error(`第三方登录失败：${error}`);
      window.location.hash = '';
    }
    return false;
  }

  const refreshToken = params.get('refresh_token') || undefined;
  window.location.hash = '';
  await authStore.authLogin({
    __webauthn_refresh: refreshToken,
    __webauthn_token: accessToken,
  });
  return true;
}

onMounted(async () => {
  if (await handleFederationCallback()) return;

  await loadLoginSettings();
  await loadCaptcha();

  try {
    fedProviders.value = await federationListProviders();
  } catch {
    fedProviders.value = [];
  }
});

const webauthnLoading = ref(false);
const showWebAuthnAccountModal = ref(false);
const webauthnAccount = ref('');

const expiredOldPw = ref('');
const expiredNewPw = ref('');
const expiredConfirmPw = ref('');
const changePwLoading = ref(false);

async function handleChangeExpiredPw() {
  if (!expiredNewPw.value) {
    message.warning('请输入新密码');
    return;
  }
  if (expiredNewPw.value !== expiredConfirmPw.value) {
    message.warning('两次输入的新密码不一致');
    return;
  }
  changePwLoading.value = true;
  try {
    await authStore.handleChangeExpiredPassword(
      authStore.expiredAccount,
      expiredOldPw.value,
      expiredNewPw.value,
    );
    message.success('密码修改成功，请重新登录');
    expiredOldPw.value = '';
    expiredNewPw.value = '';
    expiredConfirmPw.value = '';
  } catch (error: any) {
    message.error(error?.message || '修改失败');
  } finally {
    changePwLoading.value = false;
  }
}

function requestWebAuthnLogin() {
  if (!window.PublicKeyCredential) {
    message.warning('当前浏览器不支持 WebAuthn');
    return;
  }
  webauthnAccount.value = '';
  showWebAuthnAccountModal.value = true;
}

function confirmWebAuthnAccount() {
  const account = webauthnAccount.value.trim();
  if (!account) {
    message.warning('请输入用户名');
    return;
  }
  showWebAuthnAccountModal.value = false;
  loginWithWebAuthn(account);
}

function base64UrlToUint8Array(value: string) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

function arrayBufferToBase64Url(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function loginWithWebAuthn(account: string) {
  webauthnLoading.value = true;
  try {
    const beginRes = await webauthnLoginBegin(account);
    const options = beginRes.options as unknown as Record<string, unknown>;
    const sessionId = beginRes.session_id;

    if (options.publicKey) {
      const publicKey = options.publicKey as Record<string, unknown>;
      if (publicKey.challenge && typeof publicKey.challenge === 'string') {
        publicKey.challenge = base64UrlToUint8Array(publicKey.challenge);
      }
      if (Array.isArray(publicKey.allowCredentials)) {
        publicKey.allowCredentials = publicKey.allowCredentials.map(
          (credential: Record<string, unknown>) => ({
            ...credential,
            id:
              typeof credential.id === 'string'
                ? base64UrlToUint8Array(credential.id)
                : credential.id,
          }),
        );
      }
    }

    const credential = (await navigator.credentials.get(
      options,
    )) as PublicKeyCredential;
    if (!credential) {
      message.warning('未选择凭证');
      return;
    }

    const response = credential.response as AuthenticatorAssertionResponse;
    const body = {
      id: credential.id,
      rawId: arrayBufferToBase64Url(credential.rawId),
      response: {
        authenticatorData: arrayBufferToBase64Url(response.authenticatorData),
        clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
        signature: arrayBufferToBase64Url(response.signature),
        userHandle: response.userHandle
          ? arrayBufferToBase64Url(response.userHandle)
          : undefined,
      },
      type: credential.type,
    };

    const loginResult = await webauthnLoginFinish(sessionId, body);
    if (loginResult?.access_token) {
      await authStore.authLogin({
        __webauthn_refresh: loginResult.refresh_token,
        __webauthn_token: loginResult.access_token,
      });
    }
  } catch (error: any) {
    const isUserCancel =
      error?.name === 'AbortError' ||
      error?.name === 'NotAllowedError' ||
      /cancel/i.test(error?.message || '');
    if (!isUserCancel) {
      message.error(error?.message || 'WebAuthn 登录失败');
    }
  } finally {
    webauthnLoading.value = false;
  }
}

async function loginWith(provider: string) {
  try {
    const redirectUri = `${window.location.origin}/auth/login`;
    const res = await federationAuthorizeUrl(provider, redirectUri);
    if (res?.auth_url) {
      window.location.href = res.auth_url;
    } else {
      message.warning('未获取到授权 URL');
    }
  } catch (error: any) {
    message.error(error?.message || '获取授权 URL 失败');
  }
}
</script>

<template>
  <div class="vuln-login">
    <AuthenticationLogin
      :form-schema="formSchema"
      :loading="authStore.loginLoading"
      :show-code-login="false"
      :show-forget-password="true"
      :show-qrcode-login="false"
      :show-register="allowRegister"
      :show-third-party-login="true"
      @submit="handleLogin"
    >
      <template #title>
        <div class="vuln-login-title">
          <div class="vuln-login-title__mark" aria-hidden="true">
            <svg
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="1.8"
            >
              <path d="M12 3 4.5 6.2v5.6c0 4.65 3.2 8.75 7.5 9.85 4.3-1.1 7.5-5.2 7.5-9.85V6.2L12 3Z" />
              <path d="M9 12.2 11.1 14.3 15.4 10" />
            </svg>
          </div>
          <div>
            <h2>登录漏洞扫描平台</h2>
            <p>统一身份认证接入，进入资产、扫描与风险处置工作台</p>
          </div>
        </div>
      </template>

      <template #extra-form>
        <div v-if="requireCaptcha" class="vuln-captcha">
          <NaiveInput
            v-model:value="captchaAnswer"
            class="vuln-captcha__input"
            placeholder="请输入验证码"
            @keydown.enter.prevent
          />
          <button
            class="vuln-captcha__image"
            type="button"
            @click="loadCaptcha"
          >
            <img v-if="captchaImage" :src="captchaImage" alt="验证码" />
            <span v-else>获取验证码</span>
          </button>
        </div>
      </template>

      <template #third-party-login>
        <div class="vuln-fed-login">
          <div class="vuln-fed-login__divider">
            <span />
            <em>其他登录方式</em>
            <span />
          </div>
          <div class="vuln-fed-login__actions">
            <NTooltip placement="bottom">
              <template #trigger>
                <button
                  class="vuln-social-btn"
                  type="button"
                  @click="router.push('/auth/code-login')"
                >
                  <svg
                    fill="none"
                    height="20"
                    stroke="currentColor"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    viewBox="0 0 24 24"
                    width="20"
                  >
                    <rect height="20" rx="2" width="14" x="5" y="2" />
                    <path d="M12 18h.01" />
                  </svg>
                </button>
              </template>
              手机号 / 邮箱登录
            </NTooltip>
            <NTooltip v-if="allowWebAuthn" placement="bottom">
              <template #trigger>
                <button
                  class="vuln-social-btn"
                  :disabled="webauthnLoading"
                  type="button"
                  @click="requestWebAuthnLogin"
                >
                  <svg
                    fill="none"
                    height="20"
                    stroke="currentColor"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    viewBox="0 0 24 24"
                    width="20"
                  >
                    <rect height="11" rx="2" width="18" x="3" y="11" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    <path d="M12 16h.01" />
                  </svg>
                </button>
              </template>
              Passkey / 安全密钥登录
            </NTooltip>
            <NTooltip v-for="provider in fedProviders" :key="provider" placement="bottom">
              <template #trigger>
                <button
                  class="vuln-social-btn"
                  type="button"
                  @click="loginWith(provider)"
                >
                  <component :is="getSocialIcon(provider)" />
                </button>
              </template>
              {{ PROVIDER_LABEL[provider] || provider }} 登录
            </NTooltip>
          </div>
        </div>
      </template>
    </AuthenticationLogin>

    <NModal
      :show="authStore.passwordExpired"
      :closable="false"
      :mask-closable="false"
      preset="card"
      style="width: min(420px, calc(100vw - 32px))"
      title="密码已过期，请修改密码"
    >
      <NSpace vertical :size="12">
        <NaiveInput
          v-model:value="expiredOldPw"
          placeholder="当前密码"
          show-password-on="click"
          type="password"
        />
        <NaiveInput
          v-model:value="expiredNewPw"
          placeholder="新密码"
          show-password-on="click"
          type="password"
        />
        <NaiveInput
          v-model:value="expiredConfirmPw"
          placeholder="确认新密码"
          show-password-on="click"
          type="password"
        />
      </NSpace>
      <template #footer>
        <div class="vuln-modal-footer">
          <NButton @click="authStore.passwordExpired = false">取消</NButton>
          <NButton
            :loading="changePwLoading"
            type="primary"
            @click="handleChangeExpiredPw"
          >
            确认修改
          </NButton>
        </div>
      </template>
    </NModal>

    <NModal
      v-model:show="showWebAuthnAccountModal"
      preset="card"
      style="width: min(380px, calc(100vw - 32px))"
      title="WebAuthn 登录"
    >
      <p class="vuln-modal-tip">请输入用户名以查找已注册的安全凭证</p>
      <NaiveInput
        v-model:value="webauthnAccount"
        placeholder="用户名 / 手机号 / 邮箱"
        @keydown.enter="confirmWebAuthnAccount"
      />
      <template #footer>
        <div class="vuln-modal-footer">
          <NButton @click="showWebAuthnAccountModal = false">取消</NButton>
          <NButton type="primary" @click="confirmWebAuthnAccount">确定</NButton>
        </div>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.vuln-login {
  --vuln-primary: 3 105 161;
  --vuln-primary-soft: 14 165 233;
  --vuln-safe: 34 197 94;
  animation: vuln-login-enter 0.42s ease-out;
}

.vuln-login-title {
  display: flex;
  gap: 14px;
  align-items: flex-start;
  width: 100%;
  max-width: 420px;
  margin: 0 auto 26px;
  color: hsl(var(--foreground));
}

.vuln-login-title__mark {
  display: grid;
  flex: 0 0 44px;
  width: 44px;
  height: 44px;
  color: rgb(var(--vuln-primary));
  place-items: center;
  background: rgba(var(--vuln-primary-soft), 0.12);
  border: 1px solid rgba(var(--vuln-primary), 0.18);
  border-radius: 12px;
}

.vuln-login-title__mark svg {
  width: 25px;
  height: 25px;
}

.vuln-login-title h2 {
  margin: 0;
  font-size: clamp(24px, 3vw, 32px);
  font-weight: 700;
  line-height: 1.2;
  letter-spacing: 0;
}

.vuln-login-title p {
  margin: 8px 0 0;
  font-size: 14px;
  line-height: 1.7;
  color: hsl(var(--muted-foreground));
}

.vuln-captcha {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 124px;
  gap: 10px;
  margin-bottom: 12px;
}

.vuln-captcha__image {
  display: grid;
  height: 38px;
  padding: 0;
  overflow: hidden;
  font-size: 13px;
  color: rgb(var(--vuln-primary));
  cursor: pointer;
  place-items: center;
  background: rgba(var(--vuln-primary-soft), 0.07);
  border: 1px solid rgba(var(--vuln-primary), 0.18);
  border-radius: 8px;
  transition:
    border-color 0.2s ease,
    box-shadow 0.2s ease,
    background 0.2s ease;
}

.vuln-captcha__image:hover,
.vuln-captcha__image:focus-visible {
  background: rgba(var(--vuln-primary-soft), 0.12);
  border-color: rgba(var(--vuln-primary), 0.38);
  box-shadow: 0 0 0 3px rgba(var(--vuln-primary-soft), 0.12);
  outline: none;
}

.vuln-captcha__image img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.vuln-fed-login {
  width: 100%;
  margin-top: 18px;
}

.vuln-fed-login__divider {
  display: flex;
  gap: 12px;
  align-items: center;
}

.vuln-fed-login__divider span {
  flex: 1;
  height: 1px;
  background: linear-gradient(
    90deg,
    transparent,
    rgba(var(--vuln-primary), 0.24),
    transparent
  );
}

.vuln-fed-login__divider em {
  font-size: 12px;
  font-style: normal;
  line-height: 1;
  color: hsl(var(--muted-foreground));
  white-space: nowrap;
}

.vuln-fed-login__actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  justify-content: center;
  margin-top: 14px;
}

.vuln-social-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 42px;
  height: 42px;
  color: rgb(var(--vuln-primary));
  cursor: pointer;
  background: rgba(var(--vuln-primary-soft), 0.07);
  border: 1px solid rgba(var(--vuln-primary), 0.16);
  border-radius: 10px;
  transition:
    color 0.2s ease,
    background 0.2s ease,
    border-color 0.2s ease,
    box-shadow 0.2s ease;
}

.vuln-social-btn:hover,
.vuln-social-btn:focus-visible {
  color: rgb(var(--vuln-primary-soft));
  background: rgba(var(--vuln-primary-soft), 0.12);
  border-color: rgba(var(--vuln-primary), 0.38);
  box-shadow: 0 8px 22px rgba(15, 23, 42, 0.08);
  outline: none;
}

.vuln-social-btn:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.vuln-modal-tip {
  margin: 0 0 12px;
  font-size: 13px;
  line-height: 1.6;
  color: hsl(var(--muted-foreground));
}

.vuln-modal-footer {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}

.vuln-login :deep(.n-input) {
  border-radius: 8px;
  transition:
    box-shadow 0.2s ease,
    border-color 0.2s ease;
}

.vuln-login :deep(.n-input--focus),
.vuln-login :deep(.n-input:focus-within) {
  box-shadow: 0 0 0 3px rgba(var(--vuln-primary-soft), 0.12);
}

.vuln-login :deep(button[type='submit']),
.vuln-login :deep(.vben-button[type='submit']) {
  border-radius: 8px;
  font-weight: 600;
}

:global(.dark) .vuln-login {
  --vuln-primary: 56 189 248;
  --vuln-primary-soft: 14 165 233;
}

:global(.dark) .vuln-login-title__mark,
:global(.dark) .vuln-social-btn,
:global(.dark) .vuln-captcha__image {
  background: rgba(14, 165, 233, 0.1);
  border-color: rgba(148, 163, 184, 0.2);
}

:global(.dark) .vuln-social-btn:hover,
:global(.dark) .vuln-social-btn:focus-visible {
  box-shadow: 0 8px 24px rgba(14, 165, 233, 0.12);
}

@media (max-width: 480px) {
  .vuln-login-title {
    gap: 12px;
    margin-bottom: 20px;
  }

  .vuln-login-title__mark {
    flex-basis: 40px;
    width: 40px;
    height: 40px;
  }

  .vuln-captcha {
    grid-template-columns: 1fr;
  }

  .vuln-captcha__image {
    width: 100%;
  }
}

@media (prefers-reduced-motion: reduce) {
  .vuln-login {
    animation: none;
  }
}

@keyframes vuln-login-enter {
  from {
    opacity: 0;
    transform: translateY(10px);
  }

  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style>
