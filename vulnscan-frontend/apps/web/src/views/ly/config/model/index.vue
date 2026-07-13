<script lang="ts" setup>
import { onMounted, reactive, ref } from 'vue';

import {
  NButton,
  NCard,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NSpace,
  NTag,
  useMessage,
} from 'naive-ui';

import { IconifyIcon } from '@vben/icons';

import { lyLLMConfigGet, lyLLMConfigSave, lyLLMHealthCheck } from '#/api/ly';

defineOptions({ name: 'LyConfigModel' });

const message = useMessage();
const llmSaving = ref(false);
const llmLoading = ref(false);
const llmChecking = ref(false);
const llmKeyMasked = ref('');
const llmConfigPath = ref('');
const health = ref<null | Record<string, any>>(null);

const llmForm = reactive({
  api_key: '',
  base_url: '',
  model: 'deepseek-chat',
  timeout_seconds: 60,
});

async function loadLLMConfig() {
  llmLoading.value = true;
  try {
    const data = await lyLLMConfigGet();
    llmForm.base_url = String(data?.base_url || '');
    llmForm.model = String(data?.model || 'deepseek-chat');
    llmForm.timeout_seconds = Number(data?.timeout_seconds || 60);
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

onMounted(loadLLMConfig);
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
              :max="600"
            />
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
