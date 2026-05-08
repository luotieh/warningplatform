<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import { preferences } from '@vben/preferences';
import { useAccessStore, useUserStore } from '@vben/stores';

import { NSpin } from 'naive-ui';

import { getAccessCodesApi, getUserInfoApi } from '#/api';
import {
  handleSSOCallback,
  parseTokenFromURL,
} from '#/utils/sso';

defineOptions({ name: 'SSOCallback' });

const router = useRouter();
const accessStore = useAccessStore();
const userStore = useUserStore();

const loading = ref(true);
const errorMsg = ref('');

function buildRedirectTarget(path: string) {
  const url = new URL(window.location.href);
  const query: Record<string, string> = {};
  for (const key of ['embed', 'iam_theme', 'iam_app_id']) {
    const val = url.searchParams.get(key);
    if (val !== null) query[key] = val;
  }
  return Object.keys(query).length > 0 ? { path, query } : path;
}

async function processTokens(accessToken: string, refreshToken?: string) {
  accessStore.setAccessToken(accessToken);
  if (refreshToken) {
    localStorage.setItem('iam_refresh_token', refreshToken);
  }

  const [userInfo, accessCodes] = await Promise.all([
    getUserInfoApi(),
    getAccessCodesApi(),
  ]);

  userStore.setUserInfo(userInfo);
  accessStore.setAccessCodes(accessCodes);
}

onMounted(async () => {
  try {
    const fromURL = parseTokenFromURL();

    if (fromURL) {
      await processTokens(fromURL.access_token, fromURL.refresh_token);
      await router.replace(
        buildRedirectTarget(preferences.app.defaultHomePath),
      );
    } else {
      const { tokens, nextPath } = await handleSSOCallback();
      await processTokens(tokens.access_token, tokens.refresh_token);
      await router.replace(
        buildRedirectTarget(nextPath || preferences.app.defaultHomePath),
      );
    }
  } catch (err: any) {
    errorMsg.value = err?.message || 'SSO 登录失败';
    console.error('[SSO Callback]', err);
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <div class="flex h-screen w-full items-center justify-center">
    <div v-if="loading" class="text-center">
      <NSpin size="large" />
      <p class="mt-4 text-gray-500">正在完成登录...</p>
    </div>
    <div v-else-if="errorMsg" class="text-center">
      <p class="text-lg text-red-500">{{ errorMsg }}</p>
      <button
        class="mt-4 rounded bg-blue-500 px-4 py-2 text-white hover:bg-blue-600"
        @click="router.replace('/auth/login')"
      >
        返回登录
      </button>
    </div>
  </div>
</template>
