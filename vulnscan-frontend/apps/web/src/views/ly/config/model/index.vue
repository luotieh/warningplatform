<script lang="ts" setup>
import { onMounted, reactive, ref } from 'vue';

import {
  NButton,
  NCard,
  NCheckbox,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NSpace,
  NTag,
  useMessage,
} from 'naive-ui';

import { IconifyIcon } from '@vben/icons';

import {
  lyLLMConfigGet,
  lyLLMConfigSave,
lyLLMHealth,
  lyLLMHealthCheck,
  lyLLMConfigTest,
  lyStoreConfigGet,
  lyStoreConfigSave,
  lyStoreConfigTest,
} from '#/api/ly';

defineOptions({ name: 'LyConfigModel' });

const message = useMessage();
const llmSaving = ref(false);
const llmTesting = ref(false);
const llmLoading = ref(false);
const llmChecking = ref(false);
const llmKeyMasked = ref('');
const llmConfigPath = ref('');
const health = ref<null | Record<string, any>>(null);
const storeLoading = ref(false);
const storeSaving = ref(false);
const storeTesting = ref(false);
const storeKeyMasked = ref('');
const storeConfigPath = ref('');
const storeBackend = ref('mysql');

const llmForm = reactive({
  api_key: '',
  disable_thinking: false,
  max_tokens: 6000,
  base_url: '',
  model: 'deepseek-chat',
  timeout_seconds: 60,
});

const storeForm = reactive({
  host: '127.0.0.1',
  port: 3306,
  user: '',
  password: '',
  db_name: 'traffic',
  auto_migrate: true,
  db_wait_seconds: 30,
});

async function loadLLMConfig() {
  llmLoading.value = true;
  try {
    const data = await lyLLMConfigGet();
    llmForm.base_url = String(data?.base_url || '');
    llmForm.model = String(data?.model || 'deepseek-chat');
    llmForm.timeout_seconds = Number(data?.timeout_seconds || 60);
    llmForm.max_tokens = Number(data?.max_tokens || 6000);
    llmForm.disable_thinking = Boolean(data?.disable_thinking);
    llmForm.api_key = '';
    llmKeyMasked.value = String(data?.api_key_masked || '');
    llmConfigPath.value = String(data?.config_path || '');
  } catch (error) {
    message.warning(error instanceof Error ? error.message : '获取LLM配置失败');
  } finally {
    llmLoading.value = false;
  }
}

async function saveLLMConfig() {
  if (!llmForm.base_url) {
    message.warning('请输入LLM服务地址');
    return;
  }
  if (!llmForm.model) {
    message.warning('请输入模型名称');
    return;
  }
  llmSaving.value = true;
  try {
    const payload: Record<string, any> = {
      base_url: llmForm.base_url,
      model: llmForm.model,
      timeout_seconds: llmForm.timeout_seconds || 60,
    };
    if (llmForm.api_key.trim()) {
      payload.api_key = llmForm.api_key.trim();
    }
    payload.max_tokens = llmForm.max_tokens || 6000;
    payload.disable_thinking = llmForm.disable_thinking;
    const data = await lyLLMConfigSave(payload);
    llmForm.api_key = '';
    llmKeyMasked.value = String(data?.api_key_masked || llmKeyMasked.value || '');
    llmConfigPath.value = String(data?.config_path || llmConfigPath.value || '');
    message.success('LLM配置已保存');
  } catch (error) {
    message.error(error instanceof Error ? error.message : '保存LLM配置失败');
  } finally {
    llmSaving.value = false;
  }
}

// 健康检查：用表单当前值（无需先保存）测连通性 + 发一条测试对话。
// api_key 留空时后端沿用已保存密钥，与保存接口语义一致。
async function checkLLMHealth() {
  if (!llmForm.base_url) {
    message.warning('请输入LLM服务地址');
    return;
  }
  llmChecking.value = true;
  health.value = null;
  try {
    const payload: Record<string, any> = {
      base_url: llmForm.base_url,
      model: llmForm.model,
      timeout_seconds: llmForm.timeout_seconds || 60,
    };
    if (llmForm.api_key.trim()) {
      payload.api_key = llmForm.api_key.trim();
    }
    const data = await lyLLMHealthCheck(payload);
    health.value = data ?? {};
    if (data?.ok) {
      message.success('健康检查通过：服务连通，对话测试成功');
    } else if (data?.connectivity?.ok) {
      message.warning('服务可达，但对话测试未通过');
    } else {
      message.error('无法连接LLM服务');
    }
  } catch (error) {
    message.error(error instanceof Error ? error.message : 'LLM健康检查失败');
  } finally {
    llmChecking.value = false;
  }
}

async function testLLMConfig() {
  if (!llmForm.base_url || !llmForm.model) {
    message.warning('请先填写LLM服务地址和模型');
    return;
  }
  llmTesting.value = true;
  try {
    const payload: Record<string, any> = {
      base_url: llmForm.base_url.trim(),
      model: llmForm.model.trim(),
      timeout_seconds: llmForm.timeout_seconds || 60,
    };
    if (llmForm.api_key.trim()) {
      payload.api_key = llmForm.api_key.trim();
    }
    const result = await lyLLMConfigTest(payload);
    if (result?.ok) {
      message.success(
        `LLM连接正常（${result.latency_ms ?? '-'}ms），模型：${result.model || llmForm.model}`,
      );
    } else {
      message.error(result?.message || result?.error || 'LLM连接失败');
    }
  } catch (error) {
    message.error(error instanceof Error ? error.message : 'LLM连接测试失败');
  } finally {
    llmTesting.value = false;
  }
}

async function loadStoreConfig() {
  storeLoading.value = true;
  try {
    const data = await lyStoreConfigGet();
    storeBackend.value = String(data?.store_backend || 'mysql');
    storeForm.host = String(data?.host || '127.0.0.1');
    storeForm.port = Number(data?.port || 3306);
    storeForm.user = String(data?.user || '');
    storeForm.db_name = String(data?.db_name || 'traffic');
    storeForm.auto_migrate = Boolean(data?.auto_migrate ?? true);
    storeForm.db_wait_seconds = Number(data?.db_wait_seconds || 30);
    storeForm.password = '';
    storeKeyMasked.value = String(data?.password_masked || '');
    storeConfigPath.value = String(data?.config_path || '');
  } catch (error) {
    message.warning(error instanceof Error ? error.message : '获取MySQL配置失败');
  } finally {
    storeLoading.value = false;
  }
}

async function saveStoreConfig() {
  if (!storeForm.host || !storeForm.user || !storeForm.db_name) {
    message.warning('请填写完整的MySQL连接信息');
    return;
  }
  storeSaving.value = true;
  try {
    const payload: Record<string, any> = {
      store_backend: 'mysql',
      host: storeForm.host,
      port: storeForm.port || 3306,
      user: storeForm.user,
      db_name: storeForm.db_name,
      auto_migrate: storeForm.auto_migrate,
      db_wait_seconds: storeForm.db_wait_seconds || 30,
    };
    if (storeForm.password.trim()) {
      payload.password = storeForm.password.trim();
    }
    const data = await lyStoreConfigSave(payload);
    storeForm.password = '';
    storeKeyMasked.value = String(data?.password_masked || storeKeyMasked.value || '');
    storeConfigPath.value = String(data?.config_path || storeConfigPath.value || '');
    storeBackend.value = String(data?.store_backend || 'mysql');
    message.success('MySQL配置已保存，存储后端变更需重启后生效');
  } catch (error) {
    message.error(error instanceof Error ? error.message : '保存MySQL配置失败');
  } finally {
    storeSaving.value = false;
  }
}

async function testStoreConfig() {
  if (!storeForm.host || !storeForm.user || !storeForm.db_name) {
    message.warning('请先填写完整的MySQL连接信息');
    return;
  }
  storeTesting.value = true;
  try {
    const result = await lyStoreConfigTest({
      host: storeForm.host,
      port: storeForm.port || 3306,
      user: storeForm.user,
      db_name: storeForm.db_name,
      ...(storeForm.password.trim() ? { password: storeForm.password.trim() } : {}),
    });
    if (result?.ok) {
      const tables = result.tables?.length
        ? `，已建表：${result.tables.join('、')}`
        : '，核心表尚未创建（保存后重启自动迁移）';
      message.success(
        `MySQL连接正常（${result.latency_ms ?? '-'}ms）${tables}`,
      );
    } else {
      message.error(result?.error || 'MySQL连接失败');
    }
  } catch (error) {
    message.error(error instanceof Error ? error.message : 'MySQL连接测试失败');
  } finally {
    storeTesting.value = false;
  }
}

onMounted(loadLLMConfig);
onMounted(loadStoreConfig);
</script>

<template>
  <div class="ly-page">
    <NCard class="content-card llm-card" size="small" title="LLM参数配置">
      <NForm label-placement="left" label-width="112">
        <div class="llm-form-grid">
          <NFormItem label="服务地址">
            <NInput
              v-model:value="llmForm.base_url"
              :loading="llmLoading"
              placeholder="https://api.deepseek.com"
            />
          </NFormItem>
          <NFormItem label="模型">
            <NInput v-model:value="llmForm.model" placeholder="deepseek-chat" />
          </NFormItem>
          <NFormItem label="API Key">
            <NInput
              v-model:value="llmForm.api_key"
              type="password"
              show-password-on="click"
              :placeholder="llmKeyMasked ? `当前：${llmKeyMasked}，留空不修改` : '请输入API Key'"
            />
          </NFormItem>
          <NFormItem label="超时秒数">
            <NInputNumber
              v-model:value="llmForm.timeout_seconds"
              class="full-input"
              :min="1"
              :max="6000"
            />
          </NFormItem>
          <NFormItem label="最大输出Token">
            <NInputNumber
              v-model:value="llmForm.max_tokens"
              class="full-input"
              :min="256"
              :max="262144"
              :step="1024"
              placeholder="6000"
            />
          </NFormItem>
          <NFormItem label="思考模式">
            <NCheckbox v-model:checked="llmForm.disable_thinking">
              关闭思考（推理链会占用输出额度，本地Qwen模型建议开启）
            </NCheckbox>
          </NFormItem>
        </div>
      </NForm>
      <div class="llm-actions">
        <span class="config-path">{{ llmConfigPath || 'config.toml' }}</span>
        <NSpace>
          <NButton :loading="llmLoading" @click="loadLLMConfig">刷新</NButton>
<NButton
            secondary
            type="primary"
            :loading="llmChecking"
            @click="checkLLMHealth"
          >
            健康检查
          </NButton>
          <NButton type="primary" :loading="llmSaving" @click="saveLLMConfig">
            保存LLM配置
          </NButton>
        </NSpace>
      </div>

      <div v-if="health" class="health-result">
        <div class="health-row">
          <IconifyIcon
            :icon="health.connectivity?.ok ? 'lucide:circle-check' : 'lucide:circle-x'"
            class="health-icon"
            :class="health.connectivity?.ok ? 'health-icon-ok' : 'health-icon-fail'"
          />
          <span class="health-label">连通性</span>
          <NTag size="small" :type="health.connectivity?.ok ? 'success' : 'error'">
            {{ health.connectivity?.ok ? '可达' : '不可达' }}
          </NTag>
          <span v-if="health.connectivity?.ok" class="health-meta">
            {{ health.connectivity.endpoint }} · HTTP
            {{ health.connectivity.status_code }} ·
            {{ health.connectivity.latency_ms }}ms
          </span>
          <span v-else class="health-meta health-error-text">
            {{ health.connectivity?.error || '-' }}
          </span>
        </div>
        <div v-if="health.connectivity?.hint" class="health-hint">
          <IconifyIcon icon="lucide:lightbulb" /> {{ health.connectivity.hint }}
        </div>

        <div class="health-row">
          <IconifyIcon
            :icon="health.chat?.ok ? 'lucide:circle-check' : 'lucide:circle-x'"
            class="health-icon"
            :class="health.chat?.ok ? 'health-icon-ok' : 'health-icon-fail'"
          />
          <span class="health-label">对话测试</span>
          <NTag size="small" :type="health.chat?.ok ? 'success' : 'error'">
            {{ health.chat?.ok ? '通过' : '失败' }}
          </NTag>
          <span v-if="health.chat?.latency_ms" class="health-meta">
            {{ health.model }} · {{ health.chat.latency_ms }}ms
          </span>
        </div>
        <div v-if="health.chat?.ok" class="health-chat">
          <div class="chat-line">
            <span class="chat-role">问</span>
            <span class="chat-text">{{ health.chat.question }}</span>
          </div>
          <div class="chat-line">
            <span class="chat-role chat-role-ai">答</span>
            <span class="chat-text">{{ health.chat.reply || '（空回复）' }}</span>
          </div>
        </div>
        <div v-else-if="health.chat?.error" class="health-error-detail">
          {{ health.chat.error }}
        </div>
        <div v-if="health.chat?.hint" class="health-hint">
          <IconifyIcon icon="lucide:lightbulb" /> {{ health.chat.hint }}
        </div>
      </div>
    </NCard>
    <NCard class="content-card llm-card store-card" size="small" title="MySQL存储配置">
      <NForm label-placement="left" label-width="112">
        <div class="llm-form-grid">
          <NFormItem label="存储后端">
            <NInput :value="storeBackend" disabled />
          </NFormItem>
          <NFormItem label="主机地址">
            <NInput
              v-model:value="storeForm.host"
              :loading="storeLoading"
              placeholder="127.0.0.1"
            />
          </NFormItem>
          <NFormItem label="端口">
            <NInputNumber
              v-model:value="storeForm.port"
              class="full-input"
              :min="1"
              :max="65535"
            />
          </NFormItem>
          <NFormItem label="用户名">
            <NInput v-model:value="storeForm.user" placeholder="db" />
          </NFormItem>
          <NFormItem label="密码">
            <NInput
              v-model:value="storeForm.password"
              type="password"
              show-password-on="click"
              :placeholder="storeKeyMasked ? `当前：${storeKeyMasked}，留空不修改` : '请输入MySQL密码'"
            />
          </NFormItem>
          <NFormItem label="数据库名">
            <NInput v-model:value="storeForm.db_name" placeholder="traffic" />
          </NFormItem>
          <NFormItem label="自动迁移">
            <NCheckbox v-model:checked="storeForm.auto_migrate">
              启动时自动建库/建表/补列
            </NCheckbox>
          </NFormItem>
          <NFormItem label="等待秒数">
            <NInputNumber
              v-model:value="storeForm.db_wait_seconds"
              class="full-input"
              :min="1"
              :max="300"
            />
          </NFormItem>
        </div>
      </NForm>
      <div class="llm-actions">
        <span class="config-path">{{ storeConfigPath || 'config.toml' }}</span>
        <NSpace>
          <NButton :loading="storeLoading" @click="loadStoreConfig">刷新</NButton>
          <NButton :loading="storeTesting" @click="testStoreConfig">测试连接</NButton>
          <NButton type="primary" :loading="storeSaving" @click="saveStoreConfig">
            保存MySQL配置
          </NButton>
        </NSpace>
      </div>
    </NCard>
  </div>
</template>

<style scoped>
.ly-page {
  min-height: 100%;
  padding: 16px;
}

.content-card :deep(.n-card__content) {
  padding: 18px;
}

.store-card {
  margin-top: 16px;
}

.llm-form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  column-gap: 28px;
}

.full-input {
  width: 100%;
}

.llm-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.config-path {
  min-width: 0;
  overflow: hidden;
  color: #64748b;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.health-result {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px 14px;
  margin-top: 14px;
  font-size: 13px;
  background: hsl(var(--muted) / 40%);
  border-radius: 8px;
}

.health-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}

.health-icon {
  flex: none;
  font-size: 16px;
}

.health-icon-ok {
  color: #18a058;
}

.health-icon-fail {
  color: #d03050;
}

.health-label {
  font-weight: 600;
}

.health-meta {
  color: hsl(var(--muted-foreground));
  font-size: 12px;
  word-break: break-all;
}

.health-error-text {
  color: #d03050;
}

.health-hint {
  display: flex;
  gap: 6px;
  align-items: center;
  padding-left: 24px;
  font-size: 12px;
  color: #f0a020;
}

.health-chat {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 10px 12px;
  margin-left: 24px;
  background: hsl(var(--muted) / 60%);
  border-radius: 6px;
}

.chat-line {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  line-height: 1.6;
}

.chat-role {
  flex: none;
  width: 20px;
  height: 20px;
  font-size: 12px;
  line-height: 20px;
  color: #fff;
  text-align: center;
  background: #2080f0;
  border-radius: 50%;
}

.chat-role-ai {
  background: #18a058;
}

.chat-text {
  word-break: break-word;
  white-space: pre-wrap;
}

.health-error-detail {
  padding-left: 24px;
  font-size: 12px;
  color: #d03050;
  word-break: break-all;
}

@media (max-width: 720px) {
  .llm-form-grid {
    grid-template-columns: 1fr;
  }

  .llm-actions {
    align-items: stretch;
    flex-direction: column;
  }
}

@media (max-width: 640px) {
  .ly-page {
    padding: 12px;
  }
}
</style>
