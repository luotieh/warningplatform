<script lang="ts" setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';

import {
  NButton,
  NCard,
  NEmpty,
  NModal,
  NRadioButton,
  NRadioGroup,
  NSpace,
  NSpin,
  NTabPane,
  NTabs,
  NTag,
  NUpload,
  NUploadDragger,
  type UploadFileInfo,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import { getRuleData, importRuleData, putRuleData } from '#/api/sitemonitor';

import RuleSectionEditor from './components/RuleSectionEditor.vue';
import { MODULE_REGISTRY } from './registry';

defineOptions({ name: 'RuleDataDetail' });

const route = useRoute();
const router = useRouter();
const moduleKey = route.params.key as string;

const moduleDef = computed(() => MODULE_REGISTRY[moduleKey]);
const loading = ref(false);
const saving = ref(false);
const updatedAt = ref('');

const sectionData = reactive<Record<string, Record<string, any>[]>>({});
const activeTab = ref('');

async function fetchData() {
  if (!moduleDef.value) {
    message.error(`未知模块: ${moduleKey}`);
    return;
  }
  loading.value = true;
  try {
    const res = await getRuleData(moduleKey);
    const raw = (res as any)?.data ?? res;
    updatedAt.value = raw?.updated_at || '';

    let parsed: Record<string, any> = {};
    if (raw?.data) {
      try {
        parsed = JSON.parse(raw.data);
      } catch {
        parsed = {};
      }
    }

    for (const sec of moduleDef.value.sections) {
      sectionData[sec.key] = Array.isArray(parsed[sec.key])
        ? parsed[sec.key]
        : [];
    }

    if (moduleDef.value.sections.length > 0 && !activeTab.value) {
      activeTab.value = moduleDef.value.sections[0]!.key;
    }
  } catch (e: any) {
    message.error(e?.msg || '获取规则数据失败');
  } finally {
    loading.value = false;
  }
}

async function handleSave() {
  if (!moduleDef.value) return;
  saving.value = true;
  try {
    const payload: Record<string, any> = {};
    for (const sec of moduleDef.value.sections) {
      payload[sec.key] = sectionData[sec.key] || [];
    }
    await putRuleData(moduleKey, JSON.stringify(payload));
    message.success('保存成功，规则已同步到 Agent');
    await fetchData();
  } catch (e: any) {
    message.error(e?.msg || '保存失败');
  } finally {
    saving.value = false;
  }
}

function handleSectionUpdate(
  sectionKey: string,
  items: Record<string, any>[],
) {
  sectionData[sectionKey] = items;
}

const totalItems = computed(() => {
  let total = 0;
  for (const key of Object.keys(sectionData)) {
    total += (sectionData[key] || []).length;
  }
  return total;
});

const importVisible = ref(false);
const importMerge = ref<'replace' | 'merge'>('merge');
const importFile = ref<File | null>(null);
const importing = ref(false);

function handleExport() {
  if (!moduleDef.value) return;
  const payload: Record<string, any> = {};
  for (const sec of moduleDef.value.sections) {
    payload[sec.key] = sectionData[sec.key] || [];
  }
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: 'application/json',
  });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `rule-${moduleKey}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function handleImportFileChange({
  fileList,
}: {
  fileList: UploadFileInfo[];
}) {
  importFile.value = fileList[0]?.file ?? null;
}

async function handleSubmitImport() {
  if (!importFile.value) {
    message.warning('请选择 JSON 文件');
    return;
  }
  importing.value = true;
  try {
    const text = await importFile.value.text();
    const data = JSON.parse(text);
    if (typeof data !== 'object' || Array.isArray(data)) {
      message.error('JSON 格式错误：应为对象 { section_key: [...] }');
      return;
    }
    await importRuleData(moduleKey, data, importMerge.value === 'merge');
    message.success('导入成功');
    importVisible.value = false;
    importFile.value = null;
    await fetchData();
  } catch (e: any) {
    message.error(e?.msg || '导入失败: ' + (e?.message || ''));
  } finally {
    importing.value = false;
  }
}

onMounted(() => fetchData());
</script>

<template>
  <Page :title="moduleDef?.name || moduleKey" :description="moduleDef?.description">
    <template #extra>
      <NSpace align="center">
        <span class="text-muted-foreground text-sm">
          共 {{ totalItems }} 条规则
          <template v-if="updatedAt"> · 更新于 {{ updatedAt }}</template>
        </span>
        <NTag
          v-if="moduleDef"
          :type="moduleDef.type === 'engine' ? 'primary' : 'success'"
          size="small"
          :bordered="false"
        >
          {{ moduleDef.type === 'engine' ? '引擎规则' : '数据字典' }}
        </NTag>
        <NButton @click="handleExport">导出 JSON</NButton>
        <NButton @click="importVisible = true">导入 JSON</NButton>
        <NButton @click="router.back()">返回</NButton>
        <NButton type="primary" :loading="saving" @click="handleSave">
          保存并同步
        </NButton>
      </NSpace>
    </template>

    <NCard v-if="!moduleDef">
      <NEmpty :description="`未知模块: ${moduleKey}`" />
    </NCard>

    <NSpin v-else :show="loading">
      <NCard>
        <NTabs v-model:value="activeTab" type="line" animated>
          <NTabPane
            v-for="sec in moduleDef.sections"
            :key="sec.key"
            :name="sec.key"
            :tab="`${sec.label} (${(sectionData[sec.key] || []).length})`"
          >
            <RuleSectionEditor
              :section-key="sec.key"
              :label="sec.label"
              :fields="sec.fields"
              :model-value="sectionData[sec.key] || []"
              @update:model-value="handleSectionUpdate(sec.key, $event)"
            />
          </NTabPane>
        </NTabs>
      </NCard>
    </NSpin>
    <NModal
      v-model:show="importVisible"
      title="导入规则数据"
      preset="dialog"
      :positive-text="importing ? '导入中...' : '确认导入'"
      negative-text="取消"
      :positive-button-props="{ loading: importing, disabled: !importFile }"
      @positive-click="handleSubmitImport"
    >
      <div class="space-y-4">
        <div>
          <span class="mb-1 block text-sm font-medium">导入模式</span>
          <NRadioGroup v-model:value="importMerge">
            <NRadioButton value="merge">合并（追加到现有数据）</NRadioButton>
            <NRadioButton value="replace">替换（覆盖现有数据）</NRadioButton>
          </NRadioGroup>
        </div>
        <NUpload
          :max="1"
          accept=".json"
          :default-upload="false"
          @change="handleImportFileChange"
        >
          <NUploadDragger>
            <p class="mb-2 text-sm">点击或拖拽 JSON 文件到此处</p>
            <p class="text-muted-foreground text-xs">
              JSON 格式示例：{ "section_key": [{ "field1": "value1" }] }
            </p>
          </NUploadDragger>
        </NUpload>
        <p class="text-muted-foreground text-xs">
          提示：可先导出当前数据作为模板参考
        </p>
      </div>
    </NModal>
  </Page>
</template>
