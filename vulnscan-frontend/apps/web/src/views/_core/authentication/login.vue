<script lang="ts" setup>
import type { VbenFormSchema } from '@vben/common-ui';

import { computed, onMounted, ref } from 'vue';

import { AuthenticationLogin, z } from '@vben/common-ui';
import { $t } from '@vben/locales';

import { NButton, NInput as NaiveInput, NModal, NSpace, NTooltip } from 'naive-ui';

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

const requireCaptcha = ref(false);
const captchaType = ref('math');
const captchaKey = ref('');
const captchaImage = ref('');
const captchaAnswer = ref('');
const allowRegister = ref(true);

async function loadLoginSettings() {
  try {
    const settings = await getLoginSettings();
    requireCaptcha.value = settings.require_captcha;
    captchaType.value = settings.captcha_type || 'math';
    allowRegister.value = settings.allow_register;
  } catch {
    // 获取失败则默认不需要验证码
  }
}

async function loadCaptcha() {
  if (!requireCaptcha.value) return;
  try {
    const res = await getCaptcha(captchaType.value as any);
    captchaKey.value = res.captcha_key;
    const b64 = res.image_base64 || '';
    captchaImage.value = b64.startsWith('data:') ? b64 : (b64 ? `data:image/png;base64,${b64}` : '');
  } catch {
    message.warning('验证码加载失败，请重试');
  }
}

async function handleLogin(values: Record<string, any>) {
  if (requireCaptcha.value) {
    if (!captchaAnswer.value) {
      message.warning('请输入验证码');
      return;
    }
    values.captcha_key = captchaKey.value;
    values.answer = captchaAnswer.value;
  }

  const result = await authStore.authLogin(values);

  if (requireCaptcha.value && !result?.userInfo) {
    captchaAnswer.value = '';
    await loadCaptcha();
  }
}

const formSchema = computed((): VbenFormSchema[] => {
  return [
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
  ];
});

// 第三方登录提供方
const fedProviders = ref<string[]>([]);

const PROVIDER_LABEL: Record<string, string> = {
  github: 'GitHub',
  gitee: 'Gitee',
  google: 'Google',
  wecom: '企业微信',
  dingtalk: '钉钉',
  lark: '飞书',
  'wechat-mp': '微信',
  'oauth2-generic': 'OAuth2',
};

const PROVIDER_ICON: Record<string, string> = {
  github: '🐙',
  gitee: '🦊',
  google: 'Ⓖ',
  wecom: '🏢',
  dingtalk: '🔔',
  lark: '🐤',
  'wechat-mp': '💬',
  'oauth2-generic': '🔑',
};

onMounted(async () => {
  await loadLoginSettings();
  await loadCaptcha();

  try {
    fedProviders.value = await federationListProviders();
  } catch {
    fedProviders.value = [];
  }
});

const webauthnLoading = ref(false);

// 过期密码修改
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
  } catch (e: any) {
    message.error(e?.message || '修改失败');
  } finally {
    changePwLoading.value = false;
  }
}

async function loginWithWebAuthn() {
  if (!window.PublicKeyCredential) {
    message.warning('当前浏览器不支持 WebAuthn');
    return;
  }
  webauthnLoading.value = true;
  try {
    const beginRes = await webauthnLoginBegin();
    const options = beginRes.options as unknown as Record<string, unknown>;
    const sessionId = beginRes.session_id;

    if (options.publicKey) {
      const pk = options.publicKey as Record<string, unknown>;
      if (pk.challenge && typeof pk.challenge === 'string') {
        pk.challenge = Uint8Array.from(atob(pk.challenge.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
      }
      if (Array.isArray(pk.allowCredentials)) {
        pk.allowCredentials = pk.allowCredentials.map((c: Record<string, unknown>) => ({
          ...c,
          id: typeof c.id === 'string'
            ? Uint8Array.from(atob(c.id.replace(/-/g, '+').replace(/_/g, '/')), (ch: string) => ch.charCodeAt(0))
            : c.id,
        }));
      }
    }

    const credential = await navigator.credentials.get(options) as PublicKeyCredential;
    if (!credential) {
      message.warning('未选择凭证');
      return;
    }

    const response = credential.response as AuthenticatorAssertionResponse;
    const toBase64Url = (buf: ArrayBuffer) => {
      const bytes = new Uint8Array(buf);
      let binary = '';
      bytes.forEach((b) => (binary += String.fromCharCode(b)));
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };

    const body = {
      id: credential.id,
      rawId: toBase64Url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: toBase64Url(response.authenticatorData),
        clientDataJSON: toBase64Url(response.clientDataJSON),
        signature: toBase64Url(response.signature),
        userHandle: response.userHandle ? toBase64Url(response.userHandle) : undefined,
      },
    };

    const loginResult = await webauthnLoginFinish(sessionId, body);
    if (loginResult?.access_token) {
      await authStore.authLogin({
        __webauthn_token: loginResult.access_token,
        __webauthn_refresh: loginResult.refresh_token,
      });
    }
  } catch (e: any) {
    if (e?.name !== 'AbortError' && e?.name !== 'NotAllowedError') {
      message.error(e?.message || 'WebAuthn 登录失败');
    }
  } finally {
    webauthnLoading.value = false;
  }
}

async function loginWith(provider: string) {
  try {
    const res = await federationAuthorizeUrl(provider);
    if (res?.auth_url) {
      window.location.href = res.auth_url;
    } else {
      message.warning('未获取到授权 URL');
    }
  } catch (e: any) {
    message.error(e?.message || '获取授权 URL 失败');
  }
}
</script>

<template>
  <div>
  <AuthenticationLogin
    :form-schema="formSchema"
    :loading="authStore.loginLoading"
    :show-code-login="true"
    :show-qrcode-login="false"
    :show-register="allowRegister"
    :show-forget-password="true"
    :show-third-party-login="true"
    @submit="handleLogin"
  >
    <template #extra-form>
      <div v-if="requireCaptcha" class="mb-3 flex items-center gap-2">
        <NaiveInput
          v-model:value="captchaAnswer"
          placeholder="请输入验证码"
          class="flex-1"
          @keydown.enter.prevent
        />
        <img
          v-if="captchaImage"
          :src="captchaImage"
          class="h-[38px] cursor-pointer rounded border"
          alt="captcha"
          @click="loadCaptcha"
        />
        <NButton v-else size="small" @click="loadCaptcha">
          获取验证码
        </NButton>
      </div>
    </template>

    <template #third-party-login>
      <div class="iam-fed-login w-full mt-2">
        <div class="flex items-center justify-between">
          <span class="iam-fed-login__line"></span>
          <span class="text-muted-foreground text-xs uppercase tracking-wider">
            其他登录方式
          </span>
          <span class="iam-fed-login__line"></span>
        </div>
        <div class="mt-3 flex flex-wrap items-center justify-center gap-2">
          <NTooltip placement="bottom">
            <template #trigger>
              <NButton
                circle
                quaternary
                size="medium"
                class="iam-fed-login__btn"
                :loading="webauthnLoading"
                @click="loginWithWebAuthn"
              >
                <span class="text-lg">🔐</span>
              </NButton>
            </template>
            Passkey / 安全密钥 登录
          </NTooltip>
          <NTooltip
            v-for="p in fedProviders"
            :key="p"
            placement="bottom"
          >
            <template #trigger>
              <NButton
                circle
                quaternary
                size="medium"
                class="iam-fed-login__btn"
                @click="loginWith(p)"
              >
                <span class="text-lg">{{ PROVIDER_ICON[p] || '🔑' }}</span>
              </NButton>
            </template>
            {{ PROVIDER_LABEL[p] || p }} 登录
          </NTooltip>
        </div>
      </div>
    </template>
  </AuthenticationLogin>

  <!-- 过期密码修改弹窗 -->
  <NModal
    :show="authStore.passwordExpired"
    title="密码已过期，请修改密码"
    preset="card"
    style="width: 420px"
    :closable="false"
    :mask-closable="false"
  >
    <NSpace vertical :size="12">
      <NaiveInput
        v-model:value="expiredOldPw"
        type="password"
        show-password-on="click"
        placeholder="当前密码"
      />
      <NaiveInput
        v-model:value="expiredNewPw"
        type="password"
        show-password-on="click"
        placeholder="新密码"
      />
      <NaiveInput
        v-model:value="expiredConfirmPw"
        type="password"
        show-password-on="click"
        placeholder="确认新密码"
      />
    </NSpace>
    <template #footer>
      <NSpace justify="end">
        <NButton @click="authStore.passwordExpired = false">取消</NButton>
        <NButton type="primary" :loading="changePwLoading" @click="handleChangeExpiredPw">
          确认修改
        </NButton>
      </NSpace>
    </template>
  </NModal>
  </div>
</template>

<style scoped>
.iam-fed-login__line {
  flex: 1;
  height: 1px;
  background-color: var(--n-border-color, rgba(0, 0, 0, 0.06));
  margin: 0 12px;
}

.iam-fed-login__btn {
  border: 1px solid rgba(0, 0, 0, 0.08);
  background: var(--n-color, transparent);
  transition: all 0.15s;
}

.iam-fed-login__btn:hover {
  border-color: rgba(91, 140, 255, 0.5);
  background: rgba(91, 140, 255, 0.06);
  transform: translateY(-1px);
}

:deep(.dark) .iam-fed-login__btn {
  border-color: rgba(255, 255, 255, 0.1);
}
</style>
