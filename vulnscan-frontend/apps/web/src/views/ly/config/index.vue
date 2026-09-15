<script lang="ts" setup>
import { ref, watch } from 'vue';

import { useRoute } from 'vue-router';

import ModelView from './model/index.vue';
import NodeView from './node/index.vue';
import RulesView from './rules/index.vue';

defineOptions({ name: 'LyConfig' });

const route = useRoute();

const tabDefs = [
  { key: 'rules', label: '规则查看' },
  { key: 'node', label: '节点配置' },
  { key: 'model', label: '模型配置' },
];
const tabKeys = tabDefs.map((t) => t.key);

function normalizeTab(value: unknown) {
  return tabKeys.includes(value as string) ? (value as string) : 'rules';
}

const activeTab = ref(normalizeTab(route.query.tab));

// 仅在组件内切换页签，不修改 URL —— 避免触发路由变化导致整页重新挂载（刷新）
function onTabChange(tab: string) {
  activeTab.value = tab;
}

watch(
  () => route.query.tab,
  (value) => {
    const next = normalizeTab(value);
    if (next !== activeTab.value) {
      activeTab.value = next;
    }
  },
);
</script>

<template>
  <div class="ly-workstation">
    <div class="ly-workstation-tabs" role="tablist">
      <button
        v-for="tab in tabDefs"
        :key="tab.key"
        class="ly-workstation-tab"
        :class="{ active: activeTab === tab.key }"
        type="button"
        role="tab"
        :aria-selected="activeTab === tab.key"
        @click="onTabChange(tab.key)"
      >
        {{ tab.label }}
      </button>
    </div>
    <RulesView v-if="activeTab === 'rules'" />
    <NodeView v-else-if="activeTab === 'node'" />
    <ModelView v-else-if="activeTab === 'model'" />
  </div>
</template>

<style scoped>
.ly-workstation-tabs {
  display: flex;
  gap: 24px;
  padding: 8px 16px 0;
  border-bottom: 1px solid var(--n-border-color, #e5e7eb);
}

.ly-workstation-tab {
  padding: 10px 4px;
  border: 0;
  border-bottom: 2px solid transparent;
  background: transparent;
  color: #666;
  cursor: pointer;
  font: inherit;
}

.ly-workstation-tab.active {
  border-bottom-color: #2080f0;
  color: #2080f0;
}
</style>
