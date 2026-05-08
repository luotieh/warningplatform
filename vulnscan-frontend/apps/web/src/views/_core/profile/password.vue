<script lang="ts" setup>
import { ref } from 'vue';

import {
  NAlert,
  NButton,
  NForm,
  NFormItem,
  NInput,
  NSpace,
} from 'naive-ui';

import { changePassword } from '#/api/core/profile';
import { message } from '#/adapter/naive';
import { useAuthStore } from '#/store';

const authStore = useAuthStore();

const formRef = ref();
const submitting = ref(false);

const formData = ref({
  old_password: '',
  new_password: '',
  confirm_password: '',
  totp_code: '',
});

const rules = {
  old_password: { required: true, message: '请输入旧密码', trigger: 'blur' },
  new_password: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 8, message: '密码至少 8 位', trigger: 'blur' },
  ],
  confirm_password: [
    { required: true, message: '请再次输入新密码', trigger: 'blur' },
    {
      validator: (_rule: unknown, value: string) => {
        return value === formData.value.new_password;
      },
      message: '两次输入的密码不一致',
      trigger: 'blur',
    },
  ],
};

async function handleSubmit() {
  try {
    await formRef.value?.validate();
  } catch {
    return;
  }
  submitting.value = true;
  try {
    await changePassword({
      old_password: formData.value.old_password,
      new_password: formData.value.new_password,
      totp_code: formData.value.totp_code || undefined,
    });
    message.success('密码修改成功，请重新登录');
    setTimeout(() => {
      authStore.logout();
    }, 800);
  } catch (error: any) {
    message.error(error?.message || '密码修改失败');
  } finally {
    submitting.value = false;
  }
}

function handleReset() {
  formData.value = {
    old_password: '',
    new_password: '',
    confirm_password: '',
    totp_code: '',
  };
}
</script>

<template>
  <div class="max-w-[520px]">
    <NAlert type="info" class="mb-4">
      修改密码后，所有已登录的会话将被注销，您需要使用新密码重新登录。
    </NAlert>

    <NForm
      ref="formRef"
      :model="formData"
      :rules="rules"
      label-placement="left"
      label-width="100"
    >
      <NFormItem label="当前密码" path="old_password">
        <NInput
          v-model:value="formData.old_password"
          type="password"
          show-password-on="click"
          placeholder="请输入当前密码"
        />
      </NFormItem>
      <NFormItem label="新密码" path="new_password">
        <NInput
          v-model:value="formData.new_password"
          type="password"
          show-password-on="click"
          placeholder="至少 8 位"
        />
      </NFormItem>
      <NFormItem label="确认新密码" path="confirm_password">
        <NInput
          v-model:value="formData.confirm_password"
          type="password"
          show-password-on="click"
          placeholder="再次输入新密码"
        />
      </NFormItem>
      <NFormItem label="TOTP 验证码" path="totp_code">
        <NInput
          v-model:value="formData.totp_code"
          placeholder="若已绑定 TOTP，请输入 6 位验证码"
          maxlength="6"
        />
      </NFormItem>
      <NFormItem :show-label="false">
        <NSpace>
          <NButton type="primary" :loading="submitting" @click="handleSubmit">
            提交修改
          </NButton>
          <NButton @click="handleReset">重置</NButton>
        </NSpace>
      </NFormItem>
    </NForm>
  </div>
</template>
