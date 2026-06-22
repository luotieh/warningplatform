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
  useMessage,
} from 'naive-ui';

import { lyLLMConfigGet, lyLLMConfigSave } from '#/api/ly';

defineOptions({ name: 'LyConfigModel' });

const message = useMessage();
const llmSaving = ref(false);
const llmLoading = ref(false);
const llmKeyMasked = ref('');
const llmConfigPath = ref('');

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
          <NButton type="primary" :loading="llmSaving" @click="saveLLMConfig">
            保存LLM配置
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
