<script lang="ts" setup>
import { onMounted, ref } from 'vue';

import {
  NAlert,
  NButton,
  NEmpty,
  NList,
  NListItem,
  NPopconfirm,
  NSpin,
  NTag,
  NThing,
} from 'naive-ui';

import {
  webauthnDeleteCredential,
  webauthnListCredentials,
  webauthnRegisterBegin,
  webauthnRegisterFinish,
  webauthnRenameCredential,
} from '#/api/auth';
import { message } from '#/adapter/naive';
import { formatDateTime } from '#/components/table';

const loading = ref(false);
const registering = ref(false);
const credentials = ref<any[]>([]);
const supported = ref(false);

// base64url <-> ArrayBuffer
function base64UrlToBuffer(base64url: string): ArrayBuffer {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replaceAll('-', '+').replaceAll('_', '/');
  const raw = window.atob(base64);
  const buffer = new ArrayBuffer(raw.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < raw.length; i++) {
    view[i] = raw.codePointAt(i) ?? 0;
  }
  return buffer;
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (const byte of bytes) str += String.fromCodePoint(byte);
  return window
    .btoa(str)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}

async function load() {
  loading.value = true;
  try {
    credentials.value = (await webauthnListCredentials()) ?? [];
  } catch {
    credentials.value = [];
  } finally {
    loading.value = false;
  }
}

async function handleRegister() {
  if (!supported.value) {
    message.warning('当前浏览器不支持 WebAuthn');
    return;
  }
  registering.value = true;
  try {
    const { options, session_id } = await webauthnRegisterBegin();
    // 后端以 JSON 传输，challenge/id 为 base64url 字符串
    const rawOpts = options as unknown as Record<string, unknown>;
    const publicKey = rawOpts.publicKey || rawOpts;
    const pk = publicKey as Record<string, unknown>;

    const challenge = base64UrlToBuffer(pk.challenge as string);
    const userObj = pk.user as Record<string, unknown>;
    const userId = base64UrlToBuffer(userObj.id as string);
    const rawExclude = (pk.excludeCredentials ?? []) as Array<Record<string, unknown>>;
    const excludeCredentials: PublicKeyCredentialDescriptor[] = rawExclude.map(
      (c) => ({
        type: 'public-key' as const,
        id: base64UrlToBuffer(c.id as string),
      }),
    );

    const credential = (await navigator.credentials.create({
      publicKey: {
        ...(pk as unknown as PublicKeyCredentialCreationOptions),
        challenge,
        user: { ...(userObj as unknown as PublicKeyCredentialUserEntity), id: userId },
        excludeCredentials,
      },
    })) as PublicKeyCredential | null;

    if (!credential) {
      message.warning('注册被取消');
      return;
    }

    const response = credential.response as AuthenticatorAttestationResponse;
    const body = {
      id: credential.id,
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bufferToBase64Url(response.attestationObject),
        clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      },
      clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
    };

    const deviceName =
      window.prompt('请输入设备名称', '我的安全密钥') || '安全密钥';

    await webauthnRegisterFinish(session_id, deviceName, body);
    message.success('凭证注册成功');
    await load();
  } catch (error: any) {
    message.error(error?.message || 'WebAuthn 注册失败');
  } finally {
    registering.value = false;
  }
}

async function handleDelete(id: string) {
  try {
    await webauthnDeleteCredential(id);
    message.success('凭证已删除');
    await load();
  } catch (error: any) {
    message.error(error?.message || '删除失败');
  }
}

async function handleRename(item: any) {
  const newName = window.prompt('请输入新名称', item.name || '');
  if (!newName || newName === item.name) return;
  try {
    await webauthnRenameCredential(item.id, { name: newName });
    message.success('已重命名');
    await load();
  } catch (error: any) {
    message.error(error?.message || '重命名失败');
  }
}

onMounted(() => {
  supported.value =
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined';
  load();
});
</script>

<template>
  <NSpin :show="loading">
    <NAlert
      :type="supported ? 'info' : 'warning'"
      class="mb-4"
      :show-icon="true"
    >
      {{
        supported
          ? 'WebAuthn 支持使用安全密钥（YubiKey 等）、Touch ID、Windows Hello、Face ID 等设备生物识别进行无密码认证。'
          : '当前浏览器或环境不支持 WebAuthn。请使用 Chrome / Edge / Safari 等现代浏览器，且通过 HTTPS 访问。'
      }}
    </NAlert>

    <div class="mb-3 flex items-center justify-between">
      <div class="text-base font-medium">已注册凭证</div>
      <NButton
        type="primary"
        size="small"
        :loading="registering"
        :disabled="!supported"
        @click="handleRegister"
      >
        添加凭证
      </NButton>
    </div>

    <NList v-if="credentials.length > 0" bordered hoverable>
      <NListItem v-for="c in credentials" :key="c.id">
        <NThing :title="c.name || c.device_name || '未命名凭证'">
          <template #header-extra>
            <NTag size="small">
              {{ c.aaguid ? c.aaguid.slice(0, 8) : 'WebAuthn' }}
            </NTag>
          </template>
          <div class="text-muted-foreground text-xs">
            <div>凭证 ID：{{ (c.credential_id || c.id).slice(0, 32) }}…</div>
            <div>添加时间：{{ formatDateTime(c.created_at) }}</div>
            <div>最近使用：{{ c.last_used_at ? formatDateTime(c.last_used_at) : '从未使用' }}</div>
          </div>
        </NThing>
        <template #suffix>
          <div class="flex gap-2">
            <NButton size="small" @click="handleRename(c)">重命名</NButton>
            <NPopconfirm @positive-click="handleDelete(c.id)">
              <template #trigger>
                <NButton size="small" type="error" ghost>删除</NButton>
              </template>
              确定删除该凭证？删除后将无法用此设备登录。
            </NPopconfirm>
          </div>
        </template>
      </NListItem>
    </NList>
    <NEmpty v-else description="尚未注册 WebAuthn 凭证" />
  </NSpin>
</template>
