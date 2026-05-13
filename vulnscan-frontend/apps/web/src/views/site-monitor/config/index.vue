<script lang="ts" setup>
import type {
  AlertConfig,
  DimensionConfig,
  FileLibrary,
  MonitorDefaultConfig,
  WordLibrary,
} from '#/api/sitemonitor';

import { onMounted, reactive, ref } from 'vue';

import { Page } from '@vben/common-ui';

import {
  NButton,
  NCard,
  NDivider,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NSelect,
  NSpace,
  NSpin,
  NSwitch,
  NTabPane,
  NTabs,
  NTimePicker,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import {
  getAlertConfig,
  getDefaultConfigList,
  getFileLibraryList,
  getWordLibraryList,
  updateAlertConfig,
  updateDefaultConfig,
} from '#/api/sitemonitor';

defineOptions({ name: 'MonitorConfig' });

const loading = ref(false);
const saving = ref(false);
const activeTab = ref('availability');

const alertConfig = reactive<AlertConfig>({
  alert_enabled: true,
  dingtalk_enabled: false,
  dingtalk_secret: '',
  dingtalk_webhook: '',
  email_enabled: false,
  email_receivers: '',
  max_alerts_per_hour: 100,
  silence_duration_minutes: 60,
  webhook_secret: '',
  webhook_url: '',
  wechat_enabled: false,
  wechat_webhook: '',
});

const dimensionMeta: Record<string, string> = {
  availability: '可用性监测',
  blacklink: '暗链/恶意监测',
  domain_hijack: '域名劫持监测',
  sensitive_file: '敏感文件监测',
  sensitive_word: '敏感词监测',
  tamper: '篡改监测',
};
const dimensionKeys = Object.keys(dimensionMeta);

const configs = reactive<Record<string, DimensionConfig>>({});
const wordLibraries = ref<WordLibrary[]>([]);
const fileLibraries = ref<FileLibrary[]>([]);

const cycleTypeOptions = [
  { label: '每天', value: 'daily' },
  { label: '每周', value: 'weekly' },
  { label: '每月', value: 'monthly' },
  { label: '每季', value: 'quarterly' },
  { label: '半年', value: 'semi_annual' },
];

async function loadConfigs() {
  loading.value = true;
  try {
    const res = await getDefaultConfigList();
    const list: MonitorDefaultConfig[] = Array.isArray(res) ? res : ((res as any)?.data || []);
    for (const item of list) {
      configs[item.dimension] = { ...item.config_json };
    }
  } finally {
    loading.value = false;
  }
}

async function loadLibraries() {
  try {
    const [wRes, fRes] = await Promise.all([
      getWordLibraryList({ size: 100 }),
      getFileLibraryList({ size: 100 }),
    ]);
    wordLibraries.value = wRes?.data || [];
    fileLibraries.value = fRes?.data || [];
  } catch {
    /* ignore */
  }
}

async function loadAlertConfig() {
  try {
    const res = await getAlertConfig();
    const cfg = (res as any)?.data ?? res;
    if (cfg) Object.assign(alertConfig, cfg);
  } catch {
    /* ignore */
  }
}

async function handleSave(dim: string) {
  saving.value = true;
  try {
    await updateDefaultConfig(dim, { config_json: configs[dim] || {} });
    message.success(`${dimensionMeta[dim]} 默认配置已保存`);
  } catch (e: any) {
    message.error(e?.msg || '保存失败');
  } finally {
    saving.value = false;
  }
}

async function handleSaveAll() {
  saving.value = true;
  let ok = 0;
  let fail = 0;
  for (const dim of dimensionKeys) {
    const cfg = configs[dim];
    if (!cfg) continue;
    try {
      await updateDefaultConfig(dim, { config_json: cfg });
      ok++;
    } catch {
      fail++;
    }
  }
  saving.value = false;
  if (fail === 0) message.success(`全部 ${ok} 个维度默认配置已保存`);
  else message.warning(`${ok} 个成功，${fail} 个失败`);
}

async function handleSaveAlertConfig() {
  saving.value = true;
  try {
    await updateAlertConfig(alertConfig);
    message.success('告警配置已保存');
  } catch (e: any) {
    message.error(e?.msg || '保存告警配置失败');
  } finally {
    saving.value = false;
  }
}

function getField<T = any>(dim: string, field: string, fallback: T): T {
  return ((configs[dim]?.[field] as T) ?? fallback) as T;
}

function setField(dim: string, field: string, val: any) {
  if (!configs[dim]) configs[dim] = {};
  configs[dim][field] = val;
}

onMounted(() => {
  loadConfigs();
  loadLibraries();
  loadAlertConfig();
});
</script>

<template>
  <Page title="监测配置" description="6 大维度的默认配置 + 告警通道配置">
    <NSpin :show="loading">
      <NCard>
        <template #header-extra>
          <NButton :loading="saving" @click="handleSaveAll">全部保存</NButton>
        </template>

        <div class="text-muted-foreground mb-4 text-sm">
          新建任务时，各维度配置将自动从这里的默认值复制。修改此处不会影响已创建的任务。
        </div>

        <NTabs v-model:value="activeTab" type="line">
          <NTabPane v-for="dim in dimensionKeys" :key="dim" :name="dim" :tab="dimensionMeta[dim]">
            <NForm
              label-placement="left"
              :label-width="140"
              style="max-width: 700px"
            >
              <NFormItem label="启用告警">
                <NSwitch
                  :value="getField(dim, 'alert_enabled', false)"
                  @update:value="(v: boolean) => setField(dim, 'alert_enabled', v)"
                />
              </NFormItem>

              <!-- 固定周期 -->
              <template
                v-if="['availability', 'domain_hijack', 'tamper'].includes(dim)"
              >
                <NFormItem label="监测间隔(分钟)">
                  <NInputNumber
                    :value="getField(dim, 'cycle_minutes', 5)"
                    :min="1"
                    :max="1440"
                    @update:value="(v: number | null) => setField(dim, 'cycle_minutes', v)"
                  />
                </NFormItem>
              </template>

              <!-- 复杂周期 -->
              <template
                v-if="
                  ['sensitive_file', 'sensitive_word', 'blacklink'].includes(
                    dim,
                  )
                "
              >
                <NFormItem label="执行周期">
                  <NSelect
                    style="width: 200px"
                    :value="getField(dim, 'cycle_type', 'daily')"
                    :options="cycleTypeOptions"
                    @update:value="(v: string) => setField(dim, 'cycle_type', v)"
                  />
                </NFormItem>
                <NFormItem label="执行时间">
                  <NTimePicker
                    format="HH:mm"
                    value-format="HH:mm"
                    :formatted-value="getField(dim, 'cycle_time', '02:00')"
                    @update:formatted-value="(v: string | null) => setField(dim, 'cycle_time', v ?? '02:00')"
                  />
                </NFormItem>
                <NFormItem label="仅执行一次">
                  <NSwitch
                    :value="getField(dim, 'run_once', false)"
                    @update:value="(v: boolean) => setField(dim, 'run_once', v)"
                  />
                </NFormItem>
              </template>

              <!-- 可用性专属 -->
              <template v-if="dim === 'availability'">
                <NFormItem label="超时(秒)">
                  <NInputNumber
                    :value="getField(dim, 'timeout_seconds', 60)"
                    :min="5"
                    :max="300"
                    @update:value="(v: number | null) => setField(dim, 'timeout_seconds', v)"
                  />
                </NFormItem>
                <NFormItem label="免检时段">
                  <NSwitch
                    :value="getField(dim, 'exclude_time_enabled', false)"
                    @update:value="(v: boolean) => setField(dim, 'exclude_time_enabled', v)"
                  />
                </NFormItem>
                <NFormItem
                  v-if="getField(dim, 'exclude_time_enabled', false)"
                  label="免检开始"
                >
                  <NTimePicker
                    format="HH:mm"
                    value-format="HH:mm"
                    :formatted-value="getField(dim, 'exclude_time_start', '00:00')"
                    @update:formatted-value="(v: string | null) => setField(dim, 'exclude_time_start', v ?? '00:00')"
                  />
                </NFormItem>
                <NFormItem
                  v-if="getField(dim, 'exclude_time_enabled', false)"
                  label="免检结束"
                >
                  <NTimePicker
                    format="HH:mm"
                    value-format="HH:mm"
                    :formatted-value="getField(dim, 'exclude_time_end', '06:00')"
                    @update:formatted-value="(v: string | null) => setField(dim, 'exclude_time_end', v ?? '06:00')"
                  />
                </NFormItem>
                <NFormItem label="排除状态码">
                  <NInput
                    placeholder="如: 403,502"
                    :value="getField(dim, 'exclude_status_codes', '')"
                    @update:value="(v: string) => setField(dim, 'exclude_status_codes', v)"
                  />
                </NFormItem>
              </template>

              <!-- 敏感词专属 -->
              <template v-if="dim === 'sensitive_word'">
                <NFormItem label="默认词库">
                  <NSelect
                    multiple
                    placeholder="请选择词库"
                    :value="getField(dim, 'word_library_ids', [])"
                    :options="wordLibraries.map((l) => ({ label: l.name, value: l.id }))"
                    @update:value="(v: string[]) => setField(dim, 'word_library_ids', v)"
                  />
                  <div class="text-muted-foreground mt-1 text-xs">
                    未配置词库的任务将跳过敏感词检测
                  </div>
                </NFormItem>
              </template>

              <!-- 敏感文件专属 -->
              <template v-if="dim === 'sensitive_file'">
                <NFormItem label="默认文件库">
                  <NSelect
                    multiple
                    placeholder="请选择文件库"
                    :value="getField(dim, 'file_library_ids', [])"
                    :options="fileLibraries.map((l) => ({ label: l.name, value: l.id }))"
                    @update:value="(v: string[]) => setField(dim, 'file_library_ids', v)"
                  />
                  <div class="text-muted-foreground mt-1 text-xs">
                    未配置文件库的任务将跳过敏感文件检测
                  </div>
                </NFormItem>
              </template>

              <!-- 篡改专属 -->
              <template v-if="dim === 'tamper'">
                <NFormItem label="搜索引擎UA">
                  <NSpace align="center">
                    <NSwitch
                      :value="getField(dim, 'search_engine_ua', true)"
                      @update:value="(v: boolean) => setField(dim, 'search_engine_ua', v)"
                    />
                    <span class="text-muted-foreground text-xs">
                      使用搜索引擎UA访问，监测SEO劫持
                    </span>
                  </NSpace>
                </NFormItem>
              </template>

              <NFormItem class="mt-4">
                <NButton
                  type="primary"
                  :loading="saving"
                  @click="handleSave(dim)"
                >
                  保存 {{ dimensionMeta[dim] }} 配置
                </NButton>
              </NFormItem>
            </NForm>
          </NTabPane>

          <!-- 告警配置 Tab -->
          <NTabPane name="alert" tab="告警配置">
            <NForm
              label-placement="left"
              :label-width="140"
              style="max-width: 700px"
            >
              <NFormItem label="全局告警开关">
                <NSpace align="center">
                  <NSwitch v-model:value="alertConfig.alert_enabled" />
                  <span class="text-muted-foreground text-xs">
                    关闭后所有告警都不会发送
                  </span>
                </NSpace>
              </NFormItem>

              <NDivider title-placement="left">告警收敛</NDivider>

              <NFormItem label="静默期(分钟)">
                <NSpace align="center">
                  <NInputNumber
                    v-model:value="alertConfig.silence_duration_minutes"
                    :min="1"
                    :max="1440"
                  />
                  <span class="text-muted-foreground text-xs">
                    同一问题在静默期内不重复告警
                  </span>
                </NSpace>
              </NFormItem>
              <NFormItem label="每小时最大告警">
                <NSpace align="center">
                  <NInputNumber
                    v-model:value="alertConfig.max_alerts_per_hour"
                    :min="1"
                    :max="1000"
                  />
                  <span class="text-muted-foreground text-xs">防止告警风暴</span>
                </NSpace>
              </NFormItem>

              <NDivider title-placement="left">Webhook</NDivider>

              <NFormItem label="Webhook URL">
                <NInput
                  v-model:value="alertConfig.webhook_url"
                  placeholder="https://example.com/webhook"
                  clearable
                />
              </NFormItem>
              <NFormItem label="Webhook Secret">
                <NInput
                  v-model:value="alertConfig.webhook_secret"
                  type="password"
                  show-password-on="click"
                  placeholder="签名密钥（可选）"
                  clearable
                />
              </NFormItem>

              <NDivider title-placement="left">钉钉机器人</NDivider>

              <NFormItem label="启用钉钉告警">
                <NSwitch v-model:value="alertConfig.dingtalk_enabled" />
              </NFormItem>
              <NFormItem
                v-if="alertConfig.dingtalk_enabled"
                label="钉钉 Webhook"
              >
                <NInput
                  v-model:value="alertConfig.dingtalk_webhook"
                  placeholder="https://oapi.dingtalk.com/robot/send?access_token=xxx"
                  clearable
                />
              </NFormItem>
              <NFormItem
                v-if="alertConfig.dingtalk_enabled"
                label="钉钉 Secret"
              >
                <NInput
                  v-model:value="alertConfig.dingtalk_secret"
                  type="password"
                  show-password-on="click"
                  placeholder="加签密钥（可选）"
                  clearable
                />
              </NFormItem>

              <NDivider title-placement="left">企业微信机器人</NDivider>

              <NFormItem label="启用企微告警">
                <NSwitch v-model:value="alertConfig.wechat_enabled" />
              </NFormItem>
              <NFormItem v-if="alertConfig.wechat_enabled" label="企微 Webhook">
                <NInput
                  v-model:value="alertConfig.wechat_webhook"
                  placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx"
                  clearable
                />
              </NFormItem>

              <NDivider title-placement="left">邮件告警</NDivider>

              <NFormItem label="启用邮件告警">
                <NSwitch v-model:value="alertConfig.email_enabled" />
              </NFormItem>
              <NFormItem v-if="alertConfig.email_enabled" label="收件人">
                <NInput
                  v-model:value="alertConfig.email_receivers"
                  placeholder="多个邮箱用逗号分隔"
                  clearable
                />
              </NFormItem>

              <NFormItem class="mt-4">
                <NButton
                  type="primary"
                  :loading="saving"
                  @click="handleSaveAlertConfig"
                >
                  保存告警配置
                </NButton>
              </NFormItem>
            </NForm>
          </NTabPane>
        </NTabs>
      </NCard>
    </NSpin>
  </Page>
</template>
