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
  NSteps,
  NStep,
} from 'naive-ui';

import {
  forgotPassword,
  getCaptcha,
  resetPassword,
  verifyResetCode,
} from '#/api/core/public';
import { message } from '#/adapter/naive';

defineOptions({ name: 'ForgetPassword' });

const router = useRouter();
const currentStep = ref(0);
const submitting = ref(false);
const captchaImg = ref('');
const captchaKey = ref('');

// step 1
const step1Form = ref({
  account: '',
  answer: '',
});
const resetToken = ref('');

// step 2
const step2Form = ref({
  code: '',
});

// step 3
const step3Form = ref({
  new_password: '',
  confirm_password: '',
});

async function refreshCaptcha() {
  try {
    const res: any = await getCaptcha();
    captchaImg.value = res?.image || res?.data?.image || '';
    captchaKey.value = res?.key || res?.data?.key || '';
  } catch (error: any) {
    message.error(error?.message || '验证码加载失败');
  }
}

async function handleStep1() {
  if (!step1Form.value.account) {
    message.warning('请输入账号');
    return;
  }
  submitting.value = true;
  try {
    const res = await forgotPassword({
      account: step1Form.value.account,
      captcha_key: captchaKey.value || undefined,
      answer: step1Form.value.answer || undefined,
    });
    resetToken.value = res.reset_token || '';
    if (!resetToken.value) {
      message.warning(res.message || '账号不存在或验证码服务未发送');
      await refreshCaptcha();
      return;
    }
    message.success('验证码已发送，请检查邮箱/短信');
    currentStep.value = 1;
  } catch (error: any) {
    message.error(error?.message || '请求失败');
    await refreshCaptcha();
  } finally {
    submitting.value = false;
  }
}

async function handleStep2() {
  if (!step2Form.value.code) {
    message.warning('请输入验证码');
    return;
  }
  submitting.value = true;
  try {
    await verifyResetCode({
      reset_token: resetToken.value,
      code: step2Form.value.code,
    });
    message.success('验证通过');
    currentStep.value = 2;
  } catch (error: any) {
    message.error(error?.message || '验证码错误或已过期');
  } finally {
    submitting.value = false;
  }
}

async function handleStep3() {
  if (
    !step3Form.value.new_password ||
    step3Form.value.new_password.length < 8
  ) {
    message.warning('密码至少 8 位');
    return;
  }
  if (step3Form.value.new_password !== step3Form.value.confirm_password) {
    message.warning('两次输入的密码不一致');
    return;
  }
  submitting.value = true;
  try {
    await resetPassword({
      reset_token: resetToken.value,
      code: step2Form.value.code,
      new_password: step3Form.value.new_password,
    });
    message.success('密码重置成功，即将跳转登录');
    setTimeout(() => router.push('/auth/login'), 1000);
  } catch (error: any) {
    message.error(error?.message || '密码重置失败');
  } finally {
    submitting.value = false;
  }
}

refreshCaptcha();
</script>

<template>
  <div class="mx-auto w-full max-w-[420px]">
    <h2 class="mb-6 text-2xl font-bold">找回密码</h2>

    <NSteps
      :current="currentStep + 1"
      class="mb-6"
      size="small"
    >
      <NStep title="确认账号" />
      <NStep title="验证身份" />
      <NStep title="重置密码" />
    </NSteps>

    <!-- Step 1 -->
    <div v-if="currentStep === 0">
      <NForm label-placement="top">
        <NFormItem label="账号（用户名 / 邮箱 / 手机号）">
          <NInput
            v-model:value="step1Form.account"
            placeholder="请输入账号"
          />
        </NFormItem>
        <NFormItem v-if="captchaImg" label="验证码">
          <NSpace>
            <NInput
              v-model:value="step1Form.answer"
              placeholder="计算结果"
              style="width: 160px"
            />
            <NImage
              :src="captchaImg"
              :preview-disabled="true"
              :width="120"
              :height="40"
              @click="refreshCaptcha"
              class="cursor-pointer"
            />
          </NSpace>
        </NFormItem>
        <NButton
          type="primary"
          block
          :loading="submitting"
          @click="handleStep1"
        >
          发送验证码
        </NButton>
      </NForm>
    </div>

    <!-- Step 2 -->
    <div v-else-if="currentStep === 1">
      <NAlert type="info" class="mb-4">
        验证码已发送至账号绑定的邮箱或手机，15 分钟内有效。
      </NAlert>
      <NForm label-placement="top">
        <NFormItem label="验证码">
          <NInput
            v-model:value="step2Form.code"
            placeholder="请输入验证码"
            maxlength="6"
          />
        </NFormItem>
        <NSpace>
          <NButton @click="currentStep = 0">上一步</NButton>
          <NButton
            type="primary"
            :loading="submitting"
            @click="handleStep2"
          >
            下一步
          </NButton>
        </NSpace>
      </NForm>
    </div>

    <!-- Step 3 -->
    <div v-else>
      <NForm label-placement="top">
        <NFormItem label="新密码">
          <NInput
            v-model:value="step3Form.new_password"
            type="password"
            show-password-on="click"
            placeholder="至少 8 位"
          />
        </NFormItem>
        <NFormItem label="确认新密码">
          <NInput
            v-model:value="step3Form.confirm_password"
            type="password"
            show-password-on="click"
            placeholder="再次输入新密码"
          />
        </NFormItem>
        <NButton
          type="primary"
          block
          :loading="submitting"
          @click="handleStep3"
        >
          重置密码
        </NButton>
      </NForm>
    </div>

    <div class="mt-4 text-center">
      <NButton text type="primary" @click="router.push('/auth/login')">
        返回登录
      </NButton>
    </div>
  </div>
</template>
