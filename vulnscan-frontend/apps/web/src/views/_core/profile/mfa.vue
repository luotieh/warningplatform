<script lang="ts" setup>
import { computed, onMounted, ref } from 'vue';

import { useUserStore } from '@vben/stores';

import {
  NAlert,
  NButton,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NList,
  NListItem,
  NModal,
  NPopconfirm,
  NSpace,
  NSpin,
  NTag,
  NThing,
} from 'naive-ui';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore - qrcode 缺类型声明
import QRCode from 'qrcode';

import {
  totpDeleteDevice,
  totpDisable,
  totpEnable,
  totpGenerateSecret,
  totpGetDevices,
  totpVerify,
} from '#/api/auth';
import { getProfile } from '#/api/core/profile';
import { message } from '#/adapter/naive';

const userStore = useUserStore();
const userId = computed(() => userStore.userInfo?.userId ?? '');

const loading = ref(false);
const devices = ref<any[]>([]);
const mfaEnabled = ref(false);

// === 添加设备弹窗 ===
const showAddModal = ref(false);
const addStep = ref<'verify' | 'create'>('create');
const adding = ref(false);
const verifying = ref(false);
const newDevice = ref({ device_name: '', account_name: '', code: '' });
const generatedQR = ref('');
const generatedQRDataUrl = ref('');
const generatedSecret = ref<any>(null);

async function load() {
  if (!userId.value) return;
  loading.value = true;
  try {
    const [list, profile] = await Promise.all([
      totpGetDevices(userId.value),
      getProfile(),
    ]);
    devices.value = list ?? [];
    mfaEnabled.value = Boolean(profile?.mfa);
  } catch {
    devices.value = [];
  } finally {
    loading.value = false;
  }
}

function openAdd() {
  newDevice.value = { device_name: '', account_name: '', code: '' };
  generatedQR.value = '';
  generatedQRDataUrl.value = '';
  generatedSecret.value = null;
  addStep.value = 'create';
  showAddModal.value = true;
}

function isZeroTime(v: any) {
  if (!v) return true;
  const s = String(v);
  return s.startsWith('0001-01-01') || s === '0000-00-00 00:00:00';
}

function formatTime(v: any) {
  if (!v || isZeroTime(v)) return '-';
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return String(v);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

async function renderQR(otpauth: string) {
  if (!otpauth) {
    generatedQRDataUrl.value = '';
    return;
  }
  try {
    generatedQRDataUrl.value = await QRCode.toDataURL(otpauth, {
      width: 220,
      margin: 1,
      errorCorrectionLevel: 'M',
    });
  } catch {
    generatedQRDataUrl.value = '';
  }
}

async function handleGenerate() {
  if (!newDevice.value.device_name) {
    message.warning('请输入设备名称');
    return;
  }
  adding.value = true;
  try {
    const res = await totpGenerateSecret({
      user: userId.value,
      device_name: newDevice.value.device_name,
      account_name: newDevice.value.account_name || undefined,
    } as any);
    generatedQR.value = (res as any).qr_code || '';
    generatedSecret.value = (res as any).totp || null;
    await renderQR(generatedQR.value);
    addStep.value = 'verify';
  } catch (error: any) {
    message.error(error?.message || '生成密钥失败');
  } finally {
    adding.value = false;
  }
}

async function handleVerify() {
  if (!newDevice.value.code) {
    message.warning('请输入验证码');
    return;
  }
  verifying.value = true;
  try {
    const res: any = await totpVerify({
      user: userId.value,
      code: newDevice.value.code,
    });
    if (!res?.valid) {
      message.error('验证码错误');
      return;
    }
    message.success('设备绑定成功');
    showAddModal.value = false;
    await load();
  } catch (error: any) {
    message.error(error?.message || '验证失败');
  } finally {
    verifying.value = false;
  }
}

async function handleDelete(id: string) {
  try {
    await totpDeleteDevice(userId.value, id);
    message.success('设备已移除');
    await load();
  } catch (error: any) {
    message.error(error?.message || '移除失败');
  }
}

async function handleToggleMfa(enable: boolean) {
  try {
    if (enable) {
      await totpEnable(userId.value);
      message.success('已开启 MFA 强制验证');
    } else {
      await totpDisable(userId.value);
      message.success('已关闭 MFA 强制验证');
    }
    await load();
  } catch (error: any) {
    message.error(error?.message || '操作失败');
  }
}

onMounted(load);
</script>

<template>
  <NSpin :show="loading">
    <NAlert
      :type="mfaEnabled ? 'success' : 'warning'"
      class="mb-4"
      :show-icon="true"
    >
      <div class="flex items-center justify-between gap-2">
        <span>
          {{
            mfaEnabled
              ? 'MFA 二步验证已开启。登录与敏感操作时将要求输入 TOTP 验证码。'
              : '当前未开启 MFA 二步验证，建议开启以增强账号安全。'
          }}
        </span>
        <NSpace size="small">
          <NButton
            v-if="mfaEnabled"
            size="small"
            type="warning"
            @click="handleToggleMfa(false)"
          >
            关闭 MFA
          </NButton>
          <NButton
            v-else
            size="small"
            type="primary"
            :disabled="devices.length === 0"
            @click="handleToggleMfa(true)"
          >
            开启 MFA
          </NButton>
        </NSpace>
      </div>
    </NAlert>

    <div class="mb-3 flex items-center justify-between">
      <div class="text-base font-medium">已绑定设备</div>
      <NButton type="primary" size="small" @click="openAdd">
        添加设备
      </NButton>
    </div>

    <NList v-if="devices.length > 0" bordered hoverable>
      <NListItem v-for="d in devices" :key="d.id">
        <NThing
          :title="d.device_name || d.name || '未命名设备'"
          :description="d.account_name || d.account || ''"
        >
          <template #header-extra>
            <NTag size="small" :type="d.is_active ? 'success' : 'default'">
              {{ d.is_active ? '已激活' : '未激活' }}
            </NTag>
            <NTag
              v-if="d.verified"
              size="small"
              type="info"
              class="ml-1"
            >
              已验证
            </NTag>
          </template>
          <div class="text-muted-foreground text-sm">
            创建时间：{{ formatTime(d.created_at) }}
          </div>
          <div
            v-if="d.last_used_at && !isZeroTime(d.last_used_at)"
            class="text-muted-foreground text-sm"
          >
            最后使用：{{ formatTime(d.last_used_at) }}
          </div>
        </NThing>
        <template #suffix>
          <NPopconfirm @positive-click="handleDelete(d.id)">
            <template #trigger>
              <NButton size="small" type="error" ghost>移除</NButton>
            </template>
            确定移除该设备？移除后将无法使用此设备进行二步验证。
          </NPopconfirm>
        </template>
      </NListItem>
    </NList>
    <NEmpty v-else description="尚未绑定 TOTP 设备" />

    <NModal
      v-model:show="showAddModal"
      preset="card"
      :title="addStep === 'create' ? '添加 TOTP 设备' : '验证 TOTP 设备'"
      style="width: 480px"
    >
      <NForm
        v-if="addStep === 'create'"
        label-placement="left"
        label-width="100"
      >
        <NFormItem label="设备名称" required>
          <NInput
            v-model:value="newDevice.device_name"
            placeholder="如：iPhone Authenticator"
          />
        </NFormItem>
        <NFormItem label="账户名称">
          <NInput
            v-model:value="newDevice.account_name"
            placeholder="可选，用于在认证器中区分"
          />
        </NFormItem>
      </NForm>

      <div v-else class="flex flex-col items-center gap-3">
        <div
          v-if="generatedQRDataUrl"
          class="rounded bg-white p-2"
          style="line-height: 0"
        >
          <img
            :src="generatedQRDataUrl"
            alt="TOTP QR"
            style="display: block; width: 220px; height: 220px"
          />
        </div>
        <div class="text-muted-foreground text-center text-sm">
          使用 Authenticator / Google Authenticator / 1Password 等扫描二维码
        </div>
        <div
          v-if="generatedSecret?.secret"
          class="text-muted-foreground select-all text-xs"
        >
          密钥：<code>{{ generatedSecret.secret }}</code>
        </div>
        <NInput
          v-model:value="newDevice.code"
          placeholder="输入认证器中显示的 6 位验证码"
          maxlength="6"
          style="width: 200px"
        />
      </div>

      <template #footer>
        <NSpace v-if="addStep === 'create'" justify="end">
          <NButton @click="showAddModal = false">取消</NButton>
          <NButton type="primary" :loading="adding" @click="handleGenerate">
            生成密钥
          </NButton>
        </NSpace>
        <NSpace v-else justify="end">
          <NButton @click="addStep = 'create'">上一步</NButton>
          <NButton type="primary" :loading="verifying" @click="handleVerify">
            确认绑定
          </NButton>
        </NSpace>
      </template>
    </NModal>
  </NSpin>
</template>
