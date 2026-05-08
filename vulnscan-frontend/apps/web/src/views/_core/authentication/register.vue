<script lang="ts" setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';

import {
  NAlert,
  NButton,
  NForm,
  NFormItem,
  NImage,
  NInput,
  NSpace,
} from 'naive-ui';

import { getCaptcha, registerUser } from '#/api/core/public';
import { message } from '#/adapter/naive';

defineOptions({ name: 'Register' });

const router = useRouter();
const submitting = ref(false);
const captchaImg = ref('');
const captchaKey = ref('');

const formData = ref({
  user_name: '',
  password: '',
  confirm_password: '',
  nick_name: '',
  email: '',
  phone: '',
  invite_code: '',
  answer: '',
});

async function refreshCaptcha() {
  try {
    const res: any = await getCaptcha();
    captchaImg.value = res?.image || res?.data?.image || '';
    captchaKey.value = res?.key || res?.data?.key || '';
  } catch {
    captchaImg.value = '';
  }
}

async function handleSubmit() {
  if (!formData.value.user_name) {
    message.warning('请输入用户名');
    return;
  }
  if (!formData.value.password || formData.value.password.length < 8) {
    message.warning('密码至少 8 位');
    return;
  }
  if (formData.value.password !== formData.value.confirm_password) {
    message.warning('两次输入的密码不一致');
    return;
  }
  submitting.value = true;
  try {
    await registerUser({
      user_name: formData.value.user_name,
      password: formData.value.password,
      nick_name: formData.value.nick_name || undefined,
      email: formData.value.email || undefined,
      phone: formData.value.phone || undefined,
      invite_code: formData.value.invite_code || undefined,
      captcha_key: captchaKey.value || undefined,
      answer: formData.value.answer || undefined,
    });
    message.success('注册成功，请登录');
    setTimeout(() => router.push('/auth/login'), 800);
  } catch (error: any) {
    message.error(error?.message || '注册失败');
    await refreshCaptcha();
  } finally {
    submitting.value = false;
  }
}

refreshCaptcha();
</script>

<template>
  <div class="mx-auto w-full max-w-[420px]">
    <h2 class="mb-6 text-2xl font-bold">注册账号</h2>

    <NAlert type="info" class="mb-4" :show-icon="false">
      若管理员关闭了自助注册，本页将无法成功提交。
    </NAlert>

    <NForm label-placement="top">
      <NFormItem label="用户名" required>
        <NInput
          v-model:value="formData.user_name"
          placeholder="请输入用户名"
          maxlength="50"
        />
      </NFormItem>
      <NFormItem label="密码" required>
        <NInput
          v-model:value="formData.password"
          type="password"
          show-password-on="click"
          placeholder="至少 8 位"
        />
      </NFormItem>
      <NFormItem label="确认密码" required>
        <NInput
          v-model:value="formData.confirm_password"
          type="password"
          show-password-on="click"
          placeholder="再次输入密码"
        />
      </NFormItem>
      <NFormItem label="昵称">
        <NInput
          v-model:value="formData.nick_name"
          placeholder="可选"
        />
      </NFormItem>
      <NFormItem label="邮箱">
        <NInput
          v-model:value="formData.email"
          placeholder="可选（如管理员开启邮箱验证则必填）"
        />
      </NFormItem>
      <NFormItem label="手机号">
        <NInput
          v-model:value="formData.phone"
          placeholder="可选（如管理员开启手机验证则必填）"
        />
      </NFormItem>
      <NFormItem label="邀请码">
        <NInput
          v-model:value="formData.invite_code"
          placeholder="若管理员开启邀请码注册，必填"
        />
      </NFormItem>
      <NFormItem v-if="captchaImg" label="验证码">
        <NSpace>
          <NInput
            v-model:value="formData.answer"
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

      <NButton
        type="primary"
        block
        :loading="submitting"
        @click="handleSubmit"
      >
        注册
      </NButton>
    </NForm>

    <div class="mt-4 text-center">
      <NButton text type="primary" @click="router.push('/auth/login')">
        已有账号？立即登录
      </NButton>
    </div>
  </div>
</template>
