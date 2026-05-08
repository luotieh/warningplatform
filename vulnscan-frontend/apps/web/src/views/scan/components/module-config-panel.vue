<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import {
  NDrawer, NDrawerContent, NCollapse, NCollapseItem,
  NForm, NFormItem, NInputNumber, NSwitch, NSelect, NInput,
  NTag, NSpace, NButton, NEmpty, NSpin
} from 'naive-ui';
import { getModuleConfigs, type ModuleConfigInfo, type ModuleParam } from '#/api/pipeline';

const props = defineProps<{
  show: boolean;
  moduleConfigs?: Record<string, Record<string, any>>;
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
  discover: '发现',
  host: '主机',
  probe: '探测',
  'recon-fast': '快速侦察',
  'recon-deep': '深度侦察',
  vuln: '漏洞检测',
};

async function loadConfigs() {
  loading.value = true;
  try {
    modules.value = await getModuleConfigs();
    const initial: Record<string, Record<string, any>> = {};
    for (const m of modules.value) {
      initial[m.id] = {};
      for (const p of m.params) {
        initial[m.id][p.key] = props.moduleConfigs?.[m.id]?.[p.key] ?? p.default_value;
      }
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
    for (const p of m.params) {
      configValues.value[m.id][p.key] = p.default_value;
    }
  }
}

watch(() => props.show, (val) => {
  if (val && modules.value.length === 0) loadConfigs();
});

function onShow(val: boolean) {
  emit('update:show', val);
}
</script>

<template>
  <NDrawer :show="show" :width="520" @update:show="onShow">
    <NDrawerContent title="模块参数配置" :native-scrollbar="false">
      <template #header-extra>
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
                        v-model:value="configValues[mod.id][param.key]"
                        :min="param.min"
                        :max="param.max"
                        style="width: 100%"
                      />
                    </template>

                    <template v-else-if="param.type === 'boolean'">
                      <NSwitch v-model:value="configValues[mod.id][param.key]" />
                    </template>

                    <template v-else-if="param.type === 'select' && param.options">
                      <NSelect
                        v-model:value="configValues[mod.id][param.key]"
                        :options="param.options.map(o => ({ label: o.label, value: o.value }))"
                      />
                    </template>

                    <template v-else>
                      <NInput v-model:value="configValues[mod.id][param.key]" />
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
