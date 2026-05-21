<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import {
  NDrawer, NDrawerContent, NCollapse, NCollapseItem,
  NForm, NFormItem, NInputNumber, NSwitch, NSelect, NInput,
  NTag, NSpace, NButton, NEmpty, NSpin
} from 'naive-ui';
import { getModuleConfigs, type ModuleConfigInfo } from '#/api/pipeline';

const props = defineProps<{
  show: boolean;
  moduleConfigs?: Record<string, Record<string, any>>;
  /** 仅展示模板/任务涉及的模块；为空则加载全部主模块 */
  moduleIds?: string[];
}>();

const emit = defineEmits<{
  (e: 'update:show', val: boolean): void;
  (e: 'save', configs: Record<string, Record<string, any>>): void;
}>();

const loading = ref(false);
const modules = ref<ModuleConfigInfo[]>([]);
const configValues = ref<Record<string, Record<string, any>>>({});

const categoryGroups = computed(() => {
  const groups: Record<string, ModuleConfigInfo[]> = {};
  for (const m of modules.value) {
    const cat = m.category || '其他';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(m);
  }
  return groups;
});

const categoryLabels: Record<string, string> = {
  discover: '资产发现',
  recon: '信息收集',
  vuln: '漏洞检测',
  attack: '漏洞利用',
};

async function loadConfigs() {
  loading.value = true;
  try {
    modules.value = await getModuleConfigs(
      props.moduleIds?.length ? { moduleIds: props.moduleIds } : undefined,
    );
    const initial: Record<string, Record<string, any>> = {};
    for (const m of modules.value) {
      const entry: Record<string, any> = {};
      for (const p of m.params) {
        entry[p.key] = props.moduleConfigs?.[m.id]?.[p.key] ?? p.default_value;
      }
      initial[m.id] = entry;
    }
    configValues.value = initial;
  } finally {
    loading.value = false;
  }
}

function handleSave() {
  const result: Record<string, Record<string, any>> = {};
  for (const [modId, params] of Object.entries(configValues.value)) {
    const mod = modules.value.find(m => m.id === modId);
    if (!mod) continue;

    const changed: Record<string, any> = {};
    for (const p of mod.params) {
      if (params[p.key] !== p.default_value) {
        changed[p.key] = params[p.key];
      }
    }
    if (Object.keys(changed).length > 0) {
      result[modId] = changed;
    }
  }
  emit('save', result);
  emit('update:show', false);
}

function resetAll() {
  for (const m of modules.value) {
    const entry = configValues.value[m.id];
    if (!entry) continue;
    for (const p of m.params) {
      entry[p.key] = p.default_value;
    }
  }
}

watch(() => props.show, (val) => {
  if (val) loadConfigs();
});

watch(() => props.moduleIds?.join(','), () => {
  if (props.show) loadConfigs();
});

function onShow(val: boolean) {
  emit('update:show', val);
}

const headerExtraSlot = 'header-extra';
</script>

<template>
  <NDrawer :show="show" :width="520" @update:show="onShow">
    <NDrawerContent title="模块参数配置" :native-scrollbar="false">
      <template #[headerExtraSlot]>
        <NSpace>
          <NButton size="small" quaternary @click="resetAll">重置默认</NButton>
          <NButton size="small" type="primary" @click="handleSave">保存配置</NButton>
        </NSpace>
      </template>

      <NSpin :show="loading">
        <NEmpty v-if="modules.length === 0 && !loading" description="暂无模块配置" />

        <NCollapse v-else :default-expanded-names="Object.keys(categoryGroups)">
          <NCollapseItem
            v-for="(mods, cat) in categoryGroups"
            :key="cat"
            :name="cat"
          >
            <template #header>
              <NSpace align="center">
                <span>{{ categoryLabels[cat] || cat }}</span>
                <NTag size="small" :bordered="false">{{ mods.length }}个模块</NTag>
              </NSpace>
            </template>

            <NCollapse>
              <NCollapseItem
                v-for="mod in mods"
                :key="mod.id"
                :name="mod.id"
              >
                <template #header>
                  <NSpace align="center">
                    <span>{{ mod.name }}</span>
                    <NTag size="tiny" type="info" :bordered="false">{{ mod.id }}</NTag>
                  </NSpace>
                </template>

                <NForm
                  v-if="configValues[mod.id]"
                  label-placement="left"
                  label-width="110"
                  size="small"
                >
                  <NFormItem
                    v-for="param in mod.params"
                    :key="param.key"
                    :label="param.name"
                  >
                    <template v-if="param.type === 'number'">
                      <NInputNumber
                        v-model:value="(configValues[mod.id] as Record<string, any>)[param.key]"
                        :min="param.min"
                        :max="param.max"
                        style="width: 100%"
                      />
                    </template>

                    <template v-else-if="param.type === 'boolean'">
                      <NSwitch v-model:value="(configValues[mod.id] as Record<string, any>)[param.key]" />
                    </template>

                    <template v-else-if="param.type === 'select' && param.options">
                      <NSelect
                        v-model:value="(configValues[mod.id] as Record<string, any>)[param.key]"
                        :options="param.options.map(o => ({ label: o.label, value: o.value }))"
                      />
                    </template>

                    <template v-else>
                      <NInput v-model:value="(configValues[mod.id] as Record<string, any>)[param.key]" />
                    </template>

                    <template #feedback>
                      <span style="color: #999; font-size: 12px">{{ param.description }}</span>
                    </template>
                  </NFormItem>
                </NForm>
              </NCollapseItem>
            </NCollapse>
          </NCollapseItem>
        </NCollapse>
      </NSpin>
    </NDrawerContent>
  </NDrawer>
</template>
