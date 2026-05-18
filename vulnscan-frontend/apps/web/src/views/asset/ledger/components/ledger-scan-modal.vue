<script lang="ts" setup>
import { NButton, NForm, NFormItem, NInput, NModal, NSelect, NSpace, NTag } from 'naive-ui';

import type { Asset } from '#/api/asset';

import type { ScanExecutorOption } from '../../scan/scan-executor';
import type { LedgerOption, LedgerScanForm } from '../types';

defineOptions({ name: 'LedgerScanModal' });

defineProps<{
  show: boolean;
  creating?: boolean;
  showAdvanced?: boolean;
  form: LedgerScanForm;
  assets: Asset[];
  templateOptions: LedgerOption[];
  enginePresetOptions: LedgerOption[];
  executorNodeOptions: ScanExecutorOption[];
  executorNodesLoading?: boolean;
  moduleConfigCount: number;
}>();

const emit = defineEmits<{
  close: [];
  submit: [];
  advanced: [];
  moduleConfig: [];
  'update:show': [value: boolean];
  'update:template': [value: string];
}>();

const priorityOptions = [
  { label: '最高(1)', value: 1 },
  { label: '高(3)', value: 3 },
  { label: '中(5)', value: 5 },
  { label: '低(7)', value: 7 },
  { label: '最低(10)', value: 10 },
];

const verificationOptions = [
  { label: '双向校验', value: 'both' },
  { label: '原理验证', value: 'principle' },
  { label: '利用验证', value: 'exploit' },
];
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    title="发起资产扫描"
    style="width: min(720px, calc(100vw - 32px))"
    @update:show="(value) => emit('update:show', value)"
  >
    <NForm label-placement="top">
      <NFormItem label="扫描模板" required>
        <NSelect
          :value="form.templateId"
          :options="templateOptions"
          placeholder="请选择扫描模板"
          @update:value="(value) => emit('update:template', value)"
        />
      </NFormItem>

      <NFormItem label="任务名称">
        <NInput v-model:value="form.name" placeholder="请输入任务名称" />
      </NFormItem>

      <NFormItem label="执行节点" required>
        <NSelect
          v-model:value="form.executorNodeIds"
          :options="executorNodeOptions"
          :loading="executorNodesLoading"
          multiple
          filterable
          placeholder="默认在本机执行引擎运行"
          :max-tag-count="2"
        />
      </NFormItem>

      <NFormItem :label="`扫描资产（${assets.length} 项）`">
        <NSpace>
          <NTag v-for="asset in assets" :key="asset.id" :bordered="false" type="info">
            {{ asset.name || asset.address || asset.ipv4 || asset.id }}
          </NTag>
        </NSpace>
      </NFormItem>

      <div class="ledger-scan-modal__toggle" @click="emit('advanced')">
        <span>{{ showAdvanced ? '收起高级配置' : '展开高级配置' }}</span>
      </div>

      <div v-if="showAdvanced" class="ledger-scan-modal__advanced">
        <NFormItem label="优先级">
          <NSelect v-model:value="form.priority" :options="priorityOptions" />
        </NFormItem>

        <NFormItem label="验证级别">
          <NSelect v-model:value="form.verificationLevel" :options="verificationOptions" />
        </NFormItem>

        <NFormItem label="引擎预设" class="ledger-scan-modal__preset">
          <NSelect
            v-model:value="form.enginePreset"
            :options="enginePresetOptions"
            placeholder="可选：与扫描任务页相同的内置预设"
            filterable
            clearable
          />
        </NFormItem>
      </div>

      <div class="ledger-scan-modal__module">
        <NButton text type="primary" @click="emit('moduleConfig')">模块参数微调</NButton>
        <NTag v-if="moduleConfigCount > 0" :bordered="false" type="success">
          已配置 {{ moduleConfigCount }} 个模块
        </NTag>
      </div>
    </NForm>

    <template #footer>
      <NSpace justify="end">
        <NButton @click="emit('close')">取消</NButton>
        <NButton type="primary" :loading="creating" @click="emit('submit')">开始扫描</NButton>
      </NSpace>
    </template>
  </NModal>
</template>

<style scoped>
.ledger-scan-modal__toggle {
  color: var(--n-primary-color);
  cursor: pointer;
  font-size: 13px;
  margin-bottom: 12px;
}

.ledger-scan-modal__advanced {
  display: grid;
  gap: 12px;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.ledger-scan-modal__preset {
  grid-column: 1 / -1;
}

.ledger-scan-modal__module {
  align-items: center;
  border-top: 1px dashed var(--n-border-color);
  display: flex;
  gap: 10px;
  margin-top: 8px;
  padding-top: 12px;
}
</style>
