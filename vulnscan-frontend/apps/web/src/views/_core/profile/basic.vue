<script lang="ts" setup>
import { computed, onMounted, ref } from 'vue';

import {
  NAvatar,
  NButton,
  NCard,
  NDescriptions,
  NDescriptionsItem,
  NForm,
  NFormItem,
  NInput,
  NSelect,
  NSpace,
  NSpin,
  NTag,
} from 'naive-ui';

import {
  type ProfileApi,
  getProfile,
  switchContext,
  updateProfile,
} from '#/api/core/profile';
import { getPermissionApi } from '#/api/core/auth';
import { message } from '#/adapter/naive';

const loading = ref(false);
const saving = ref(false);
const profile = ref<ProfileApi.ProfileInfo | null>(null);
const formRef = ref();

const formData = ref<ProfileApi.UpdateProfileReq>({
  nick_name: '',
  avatar: '',
  phone: '',
  email: '',
  remark: '',
});

const rules = {
  email: [
    {
      pattern: /^[\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)+$/,
      message: '邮箱格式不正确',
      trigger: ['blur', 'change'],
    },
  ],
  phone: [
    {
      pattern: /^1[3-9]\d{9}$/,
      message: '手机号格式不正确',
      trigger: ['blur', 'change'],
    },
  ],
};

async function load() {
  loading.value = true;
  try {
    const res = await getProfile();
    profile.value = res;
    formData.value = {
      nick_name: res.nick_name || '',
      avatar: res.avatar || '',
      phone: res.phone || '',
      email: res.email || '',
      remark: res.remark || '',
    };
  } finally {
    loading.value = false;
  }
}

async function handleSave() {
  try {
    await formRef.value?.validate();
  } catch {
    return;
  }
  saving.value = true;
  try {
    await updateProfile(formData.value);
    message.success('保存成功');
    await load();
  } catch (error: any) {
    message.error(error?.message || '保存失败');
  } finally {
    saving.value = false;
  }
}

function statusText(status?: number) {
  switch (status) {
    case 1: {
      return { text: '正常', type: 'success' };
    }
    case 2: {
      return { text: '禁用', type: 'error' };
    }
    case 3: {
      return { text: '锁定', type: 'warning' };
    }
    default: {
      return { text: '未知', type: 'default' };
    }
  }
}

// 组织上下文切换
const organizes = ref<Array<{ label: string; value: string }>>([]);
const currentOrganize = ref<string | null>(null);
const switchingContext = ref(false);

async function loadOrganizes() {
  try {
    const bundle = await getPermissionApi();
    if (bundle?.organizes) {
      organizes.value = bundle.organizes.map((o: any) => ({
        label: o.name || o.organize_name || o.id,
        value: o.id || o.organize_id,
      }));
      currentOrganize.value = bundle.user?.primary_organize_id || null;
    }
  } catch {
    organizes.value = [];
  }
}

async function handleSwitchContext(organizeId: string) {
  switchingContext.value = true;
  try {
    await switchContext({ organize_id: organizeId });
    currentOrganize.value = organizeId;
    message.success('已切换组织上下文');
    window.location.reload();
  } catch (e: any) {
    message.error(e?.message || '切换失败');
  } finally {
    switchingContext.value = false;
  }
}

const avatarFallback = computed(() => {
  const seed = profile.value?.nick_name || profile.value?.user_name || 'U';
  const initial = seed[0]!.toUpperCase();
  let hash = 0;
  for (const ch of seed) hash = ((hash << 5) - hash + ch.charCodeAt(0)) | 0;
  const hue = ((hash % 360) + 360) % 360;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128"><rect width="128" height="128" rx="64" fill="hsl(${hue},55%,55%)"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" fill="#fff" font-size="56" font-family="sans-serif">${initial}</text></svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
});

onMounted(() => {
  load();
  loadOrganizes();
});
</script>

<template>
  <NSpin :show="loading">
    <div class="flex flex-col gap-6 lg:flex-row">
      <!-- 头像和基础信息展示 -->
      <div class="flex w-full flex-col items-center gap-4 lg:w-[260px]">
        <NAvatar
          round
          :size="128"
          :src="profile?.avatar"
          :fallback-src="avatarFallback"
        />
        <div class="text-center">
          <div class="text-lg font-semibold">
            {{ profile?.nick_name || profile?.user_name }}
          </div>
          <div class="text-muted-foreground text-sm">
            @{{ profile?.user_name }}
          </div>
          <NSpace class="mt-2" justify="center">
            <NTag
              size="small"
              :type="(statusText(profile?.status).type as any)"
            >
              {{ statusText(profile?.status).text }}
            </NTag>
            <NTag
              size="small"
              :type="profile?.mfa ? 'success' : 'default'"
            >
              MFA {{ profile?.mfa ? '已开启' : '未开启' }}
            </NTag>
          </NSpace>
        </div>
        <NDescriptions
          label-placement="left"
          :column="1"
          size="small"
          class="w-full"
        >
          <NDescriptionsItem label="用户ID">
            {{ profile?.user_id || '-' }}
          </NDescriptionsItem>
        </NDescriptions>
      </div>

      <!-- 编辑表单 -->
      <div class="flex-1">
        <!-- 组织上下文切换 -->
        <NCard v-if="organizes.length > 1" size="small" :bordered="true" class="mb-4">
          <div class="flex items-center gap-3">
            <span class="text-sm font-medium text-gray-600 dark:text-gray-400">当前组织：</span>
            <NSelect
              :value="currentOrganize"
              :options="organizes"
              :loading="switchingContext"
              placeholder="选择组织"
              style="width: 240px"
              @update:value="handleSwitchContext"
            />
          </div>
        </NCard>
        <NForm
          ref="formRef"
          :model="formData"
          :rules="rules"
          label-placement="left"
          label-width="100"
        >
          <NFormItem label="昵称" path="nick_name">
            <NInput
              v-model:value="formData.nick_name"
              placeholder="请输入昵称"
              maxlength="50"
              show-count
            />
          </NFormItem>
          <NFormItem label="头像URL" path="avatar">
            <NInput
              v-model:value="formData.avatar"
              placeholder="请输入头像URL"
            />
          </NFormItem>
          <NFormItem label="手机号" path="phone">
            <NInput
              v-model:value="formData.phone"
              placeholder="请输入手机号"
            />
          </NFormItem>
          <NFormItem label="邮箱" path="email">
            <NInput
              v-model:value="formData.email"
              placeholder="请输入邮箱"
            />
          </NFormItem>
          <NFormItem label="备注" path="remark">
            <NInput
              v-model:value="formData.remark"
              type="textarea"
              :autosize="{ minRows: 2, maxRows: 4 }"
              placeholder="个人简介"
              maxlength="200"
              show-count
            />
          </NFormItem>
          <NFormItem :show-label="false">
            <NSpace>
              <NButton type="primary" :loading="saving" @click="handleSave">
                保存修改
              </NButton>
              <NButton @click="load">重置</NButton>
            </NSpace>
          </NFormItem>
        </NForm>
      </div>
    </div>
  </NSpin>
</template>
