<script lang="ts" setup>
import { computed, h, onMounted, ref } from 'vue';

import {
  NButton,
  NCard,
  NSpace,
  NTag,
  NEmpty,
  NGrid,
  NGi,
  NCollapse,
  NCollapseItem,
  NTooltip,
  NAlert,
  NSelect,
  NInput,
  useMessage,
} from 'naive-ui';

import {
  getPipelineModules,
  getPipelineStages,
  getPipelineProfiles,
  type ModuleInfo,
  type StageInfo,
  type ProfileInfo,
} from '#/api/pipeline';

defineOptions({ name: 'PipelineEditor' });

const message = useMessage();
const allModules = ref<ModuleInfo[]>([]);
const defaultStages = ref<StageInfo[]>([]);
const profiles = ref<ProfileInfo[]>([]);

const customStages = ref<{ name: string; modules: ModuleInfo[] }[]>([]);
const selectedProfile = ref('');
const pipelineName = ref('自定义扫描流程');

const categoryColors: Record<string, string> = {
  discover: '#1890ff',
  host: '#52c41a',
  probe: '#722ed1',
  recon: '#fa8c16',
  vuln: '#f5222d',
  test: '#999',
};

const categoryLabels: Record<string, string> = {
  discover: '发现',
  host: '主机',
  probe: '探测',
  recon: '侦察',
  vuln: '漏洞',
};

const modulesByCategory = computed(() => {
  const map = new Map<string, ModuleInfo[]>();
  for (const m of allModules.value) {
    const cat = m.category || 'other';
    if (!map.has(cat)) map.set(cat, []);
    map.get(cat)!.push(m);
  }
  return map;
});

const usedModuleIds = computed(() => {
  const ids = new Set<string>();
  for (const stage of customStages.value) {
    for (const m of stage.modules) {
      ids.add(m.id);
    }
  }
  return ids;
});

const totalModuleCount = computed(() => {
  return customStages.value.reduce((sum, s) => sum + s.modules.length, 0);
});

async function loadData() {
  try {
    const [mods, stages, profs] = await Promise.all([
      getPipelineModules(),
      getPipelineStages(),
      getPipelineProfiles(),
    ]);
    allModules.value = mods;
    defaultStages.value = stages;
    profiles.value = profs;
    customStages.value = stages.map(s => ({
      name: s.name,
      modules: [...s.modules],
    }));
  } catch (e: any) {
    message.error('加载 Pipeline 数据失败');
  }
}

function addStage() {
  customStages.value.push({ name: `stage-${customStages.value.length + 1}`, modules: [] });
}

function removeStage(index: number) {
  customStages.value.splice(index, 1);
}

function addModuleToStage(stageIndex: number, mod: ModuleInfo) {
  const stage = customStages.value[stageIndex];
  if (!stage) return;
  if (stage.modules.some(m => m.id === mod.id)) {
    message.warning(`模块 "${mod.name}" 已在此阶段中`);
    return;
  }
  stage.modules.push({ ...mod });
}

function removeModuleFromStage(stageIndex: number, modIndex: number) {
  customStages.value[stageIndex]?.modules.splice(modIndex, 1);
}

function moveStage(index: number, direction: 'up' | 'down') {
  const newIndex = direction === 'up' ? index - 1 : index + 1;
  if (newIndex < 0 || newIndex >= customStages.value.length) return;
  const temp = customStages.value[index]!;
  customStages.value[index] = customStages.value[newIndex]!;
  customStages.value[newIndex] = temp;
}

function loadProfile(profileId: string) {
  selectedProfile.value = profileId;
  const stages = defaultStages.value;
  if (!stages.length) return;

  customStages.value = stages.map(s => ({
    name: s.name,
    modules: [...s.modules],
  }));
  message.success(`已加载 "${profileId}" 配置`);
}

function resetPipeline() {
  customStages.value = defaultStages.value.map(s => ({
    name: s.name,
    modules: [...s.modules],
  }));
  message.info('已重置为默认配置');
}

function exportConfig() {
  const config = {
    name: pipelineName.value,
    stages: customStages.value.map(s => ({
      name: s.name,
      modules: s.modules.map(m => m.id),
    })),
  };
  navigator.clipboard.writeText(JSON.stringify(config, null, 2));
  message.success('Pipeline 配置已复制到剪贴板');
}

onMounted(loadData);
</script>

<template>
  <div style="padding: 16px; display: flex; gap: 16px; height: calc(100vh - 120px)">
    <!-- 左侧：模块面板 -->
    <NCard title="可用模块" size="small" style="width: 280px; flex-shrink: 0; overflow-y: auto">
      <template #header-extra>
        <NTag size="small" :bordered="false">{{ allModules.length }} 个</NTag>
      </template>

      <NCollapse>
        <NCollapseItem
          v-for="[cat, mods] in modulesByCategory"
          :key="cat"
          :title="(categoryLabels[cat] || cat) + ` (${mods.length})`"
          :name="cat"
        >
          <div style="display: flex; flex-direction: column; gap: 4px">
            <div
              v-for="mod in mods"
              :key="mod.id"
              :style="{
                padding: '6px 10px',
                borderRadius: '6px',
                background: usedModuleIds.has(mod.id) ? '#f0f0f0' : '#fafafa',
                border: `1px solid ${usedModuleIds.has(mod.id) ? '#d9d9d9' : categoryColors[cat] || '#ddd'}`,
                cursor: 'grab',
                opacity: usedModuleIds.has(mod.id) ? 0.5 : 1,
                fontSize: '13px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }"
            >
              <span>{{ mod.name }}</span>
              <NTag :bordered="false" size="tiny" :color="{ color: (categoryColors[cat] || '#999') + '20', textColor: categoryColors[cat] || '#999' }">
                {{ mod.id }}
              </NTag>
            </div>
          </div>
        </NCollapseItem>
      </NCollapse>
    </NCard>

    <!-- 中间：Pipeline 编辑器 -->
    <div style="flex: 1; display: flex; flex-direction: column; gap: 12px; overflow-y: auto">
      <!-- 工具栏 -->
      <NCard size="small">
        <NSpace align="center" :size="12">
          <NInput v-model:value="pipelineName" placeholder="流程名称" size="small" style="width: 200px" />
          <NSelect
            :value="selectedProfile"
            :options="profiles.map(p => ({ label: p.name + ` (${p.modules_count})`, value: p.id }))"
            placeholder="加载预设"
            size="small"
            style="width: 180px"
            @update:value="loadProfile"
          />
          <NButton size="small" @click="addStage">添加阶段</NButton>
          <NButton size="small" @click="resetPipeline">重置</NButton>
          <NButton size="small" type="primary" @click="exportConfig">导出配置</NButton>
          <NTag size="small" :bordered="false">
            {{ customStages.length }} 个阶段 / {{ totalModuleCount }} 个模块
          </NTag>
        </NSpace>
      </NCard>

      <!-- Pipeline 可视化 -->
      <div v-if="customStages.length === 0">
        <NEmpty description="暂无阶段，点击"添加阶段"开始编排" />
      </div>

      <div v-else style="display: flex; flex-direction: column; gap: 0">
        <template v-for="(stage, si) in customStages" :key="si">
          <!-- 连接线 -->
          <div v-if="si > 0" style="display: flex; justify-content: center; padding: 4px 0">
            <div style="width: 2px; height: 24px; background: linear-gradient(#1890ff, #722ed1); border-radius: 1px" />
          </div>

          <!-- 阶段卡片 -->
          <NCard
            size="small"
            :style="{
              borderLeft: `4px solid ${categoryColors[stage.modules[0]?.category] || '#1890ff'}`,
            }"
          >
            <template #header>
              <NSpace align="center" :size="8">
                <NInput
                  v-model:value="stage.name"
                  size="tiny"
                  style="width: 140px; font-weight: 600"
                />
                <NTag size="tiny" :bordered="false">{{ stage.modules.length }} 模块</NTag>
              </NSpace>
            </template>
            <template #header-extra>
              <NSpace :size="4">
                <NButton size="tiny" text :disabled="si === 0" @click="moveStage(si, 'up')">↑</NButton>
                <NButton size="tiny" text :disabled="si === customStages.length - 1" @click="moveStage(si, 'down')">↓</NButton>
                <NButton size="tiny" text type="error" @click="removeStage(si)">×</NButton>
              </NSpace>
            </template>

            <div v-if="stage.modules.length === 0" style="color: #999; font-size: 12px; padding: 8px 0; text-align: center">
              从左侧拖入模块，或点击下方添加
            </div>

            <div style="display: flex; flex-wrap: wrap; gap: 6px">
              <NTooltip v-for="(mod, mi) in stage.modules" :key="mod.id" trigger="hover">
                <template #trigger>
                  <NTag
                    closable
                    size="small"
                    :bordered="true"
                    :color="{ borderColor: categoryColors[mod.category] || '#999', textColor: categoryColors[mod.category] || '#999' }"
                    @close="removeModuleFromStage(si, mi)"
                  >
                    {{ mod.name }}
                  </NTag>
                </template>
                {{ mod.id }} · {{ categoryLabels[mod.category] || mod.category }}
              </NTooltip>
            </div>

            <!-- 快速添加模块 -->
            <div style="margin-top: 8px">
              <NSelect
                filterable
                placeholder="添加模块..."
                size="tiny"
                :options="allModules.filter(m => !stage.modules.some(sm => sm.id === m.id)).map(m => ({ label: m.name, value: m.id }))"
                @update:value="(id: string) => {
                  const mod = allModules.find(m => m.id === id);
                  if (mod) addModuleToStage(si, mod);
                }"
                :value="null"
                style="max-width: 250px"
              />
            </div>
          </NCard>
        </template>
      </div>

      <!-- 执行流说明 -->
      <NAlert title="执行说明" type="info" :bordered="false" style="margin-top: 8px">
        阶段按从上到下的顺序<b>串行</b>执行，每个阶段内的模块<b>并行</b>执行。
        上一阶段发现的新目标会自动传递给下一阶段。
      </NAlert>
    </div>
  </div>
</template>
