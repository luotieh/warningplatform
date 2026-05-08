<script lang="ts" setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';

import { preferences } from '@vben/preferences';
import { useAccessStore } from '@vben/stores';

import {
  NAlert,
  NButton,
  NForm,
  NFormItem,
  NImage,
  NInput,
  NSpace,
  NTabPane,
  NTabs,
} from 'naive-ui';

import { getAccessCodesApi } from '#/api/core/auth';
import {
  getCaptcha,
  sendMagicLink,
  sendSMSCode,
  verifyMagicLink,
  verifySMSCode,
} from '#/api/core/public';
import { message } from '#/adapter/naive';
import { useAuthStore } from '#/store';

defineOptions({ name: 'CodeLogin' });

const router = useRouter();
const authStore = useAuthStore();
const accessStore = useAccessStore();

const activeTab = ref<'sms' | 'magic'>('sms');
const submitting = ref(false);
const sending = ref(false);
const countdown = ref(0);

const captchaImg = ref('');
const captchaKey = ref('');

const smsForm = ref({ phone: '', code: '', answer: '' });
const magicForm = ref({ email: '', token: '', answer: '' });

async function refreshCaptcha() {
  try {
    const res: any = await getCaptcha();
    captchaImg.value = res?.image || res?.data?.image || '';
    captchaKey.value = res?.key || res?.data?.key || '';
  } catch {
    captchaImg.value = '';
  }
}

function startCountdown() {
  countdown.value = 60;
  const timer = setInterval(() => {
    countdown.value--;
    if (countdown.value <= 0) clearInterval(timer);
  }, 1000);
}

async function handleSendSMS() {
  if (!/^1[3-9]\d{9}$/.test(smsForm.value.phone)) {
    message.warning('请输入正确的手机号');
    return;
  }
  sending.value = true;
  try {
    await sendSMSCode({
      phone: smsForm.value.phone,
      captcha_key: captchaKey.value || undefined,
      answer: smsForm.value.answer || undefined,
    });
    message.success('验证码已发送');
    startCountdown();
  } catch (error: any) {
    message.error(error?.message || '发送失败');
    await refreshCaptcha();
  } finally {
    sending.value = false;
  }
}

async function handleSendMagic() {
  if (!magicForm.value.email) {
    message.warning('请输入邮箱');
    return;
  }
  sending.value = true;
  try {
    await sendMagicLink({
      email: magicForm.value.email,
      captcha_key: captchaKey.value || undefined,
      answer: magicForm.value.answer || undefined,
    });
    message.success('登录链接已发送至邮箱');
  } catch (error: any) {
    message.error(error?.message || '发送失败');
    await refreshCaptcha();
  } finally {
    sending.value = false;
  }
}

async function applyLoginResult(result: any) {
  if (!result?.access_token) {
    throw new Error('登录失败');
  }
  accessStore.setAccessToken(result.access_token);
  if (result.refresh_token) {
    localStorage.setItem('iam_refresh_token', result.refresh_token);
  }
  const [userInfo, accessCodes] = await Promise.all([
    authStore.fetchUserInfo(),
    getAccessCodesApi(),
  ]);
  accessStore.setAccessCodes(accessCodes);
  await router.push(userInfo?.homePath || preferences.app.defaultHomePath);
}

async function handleSMSLogin() {
  if (!smsForm.value.code) {
    message.warning('请输入验证码');
    return;
  }
  submitting.value = true;
  try {
    const result = await verifySMSCode({
      phone: smsForm.value.phone,
      code: smsForm.value.code,
    });
    await applyLoginResult(result);
  } catch (error: any) {
    message.error(error?.message || '登录失败');
  } finally {
    submitting.value = false;
  }
}

async function handleMagicVerify() {
  if (!magicForm.value.token) {
    message.warning('请输入邮件中的 Token');
    return;
  }
  submitting.value = true;
  try {
    const result = await verifyMagicLink({ token: magicForm.value.token });
    await applyLoginResult(result);
  } catch (error: any) {
    message.error(error?.message || '登录失败');
  } finally {
    submitting.value = false;
  }
}

refreshCaptcha();
</script>

<template>
  <div class="mx-auto w-full max-w-[420px]">
    <h2 class="mb-6 text-2xl font-bold">无密码登录</h2>

    <NTabs v-model:value="activeTab" type="line" justify-content="space-evenly">
      <NTabPane name="sms" tab="短信验证码">
        <NForm label-placement="top">
          <NFormItem label="手机号" required>
            <NInput
              v-model:value="smsForm.phone"
              placeholder="请输入手机号"
              maxlength="11"
            />
          </NFormItem>
          <NFormItem v-if="captchaImg" label="图形验证码">
            <NSpace>
              <NInput
                v-model:value="smsForm.answer"
                placeholder="计算结果"
                style="width: 160px"
              />
              <NImage
                :src="captchaImg"
                :preview-disabled="true"
                :width="120"
                :height="40"
                class="cursor-pointer"
                @click="refreshCaptcha"
              />
            </NSpace>
          </NFormItem>
          <NFormItem label="短信验证码" required>
            <NSpace>
              <NInput
                v-model:value="smsForm.code"
                placeholder="6 位验证码"
                maxlength="6"
                style="width: 160px"
              />
              <NButton
                :disabled="countdown > 0"
                :loading="sending"
                @click="handleSendSMS"
              >
                {{ countdown > 0 ? `${countdown}s` : '发送验证码' }}
              </NButton>
            </NSpace>
          </NFormItem>
          <NButton
            type="primary"
            block
            :loading="submitting"
            @click="handleSMSLogin"
          >
            登录
          </NButton>
        </NForm>
      </NTabPane>

      <NTabPane name="magic" tab="邮箱 Magic Link">
        <NAlert type="info" class="mb-4" :show-icon="false">
          点击「发送邮件」后，请到邮箱复制 Token 到下方框，或直接点击邮件中的链接完成登录。
        </NAlert>
        <NForm label-placement="top">
          <NFormItem label="邮箱" required>
            <NInput
              v-model:value="magicForm.email"
              placeholder="请输入邮箱"
            />
          </NFormItem>
          <NFormItem v-if="captchaImg" label="图形验证码">
            <NSpace>
              <NInput
                v-model:value="magicForm.answer"
                placeholder="计算结果"
                style="width: 160px"
              />
              <NImage
                :src="captchaImg"
                :preview-disabled="true"
                :width="120"
                :height="40"
                class="cursor-pointer"
                @click="refreshCaptcha"
              />
            </NSpace>
          </NFormItem>
          <NSpace class="mb-3">
            <NButton :loading="sending" @click="handleSendMagic">
              发送邮件
            </NButton>
          </NSpace>
          <NFormItem label="邮件中的 Token">
            <NInput
              v-model:value="magicForm.token"
              placeholder="粘贴邮件中的 Token"
            />
          </NFormItem>
          <NButton
            type="primary"
            block
            :loading="submitting"
            @click="handleMagicVerify"
          >
            登录
          </NButton>
        </NForm>
      </NTabPane>
    </NTabs>

    <div class="mt-4 text-center">
      <NButton text type="primary" @click="router.push('/auth/login')">
        返回密码登录
      </NButton>
    </div>
  </div>
</template>
