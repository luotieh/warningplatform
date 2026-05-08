<script setup lang="ts">
import { onMounted, ref } from 'vue';

import { Page } from '@vben/common-ui';

import { NCard, NTabPane, NTabs } from 'naive-ui';

import ProfileBasic from './basic.vue';
import ProfileMfa from './mfa.vue';
import ProfilePassword from './password.vue';
import ProfileSessions from './sessions.vue';
import ProfileWebAuthn from './webauthn.vue';

defineOptions({ name: 'ProfileCenter' });

const activeTab = ref('basic');
const refreshKey = ref(0);

function handleTabChange(value: string) {
  activeTab.value = value;
  refreshKey.value += 1;
}

onMounted(() => {
  // noop
});
</script>

<template>
  <Page auto-content-height>
    <NCard size="small" :bordered="false">
      <NTabs
        :value="activeTab"
        type="line"
        animated
        @update:value="handleTabChange"
      >
        <NTabPane name="basic" tab="基本信息">
          <ProfileBasic :key="`basic-${refreshKey}`" />
        </NTabPane>
        <NTabPane name="password" tab="修改密码">
          <ProfilePassword :key="`password-${refreshKey}`" />
        </NTabPane>
        <NTabPane name="mfa" tab="二步验证 (TOTP)">
          <ProfileMfa :key="`mfa-${refreshKey}`" />
        </NTabPane>
        <NTabPane name="webauthn" tab="WebAuthn 凭证">
          <ProfileWebAuthn :key="`webauthn-${refreshKey}`" />
        </NTabPane>
        <NTabPane name="sessions" tab="登录会话">
          <ProfileSessions :key="`sessions-${refreshKey}`" />
        </NTabPane>
      </NTabs>
    </NCard>
  </Page>
</template>
