<script lang="ts" setup>
import { ref, watch } from 'vue';

import { NTabPane, NTabs } from 'naive-ui';
import { useRoute } from 'vue-router';

import MaView from './ma/index.vue';
import OmView from './om/index.vue';
import SearchView from '../search/index.vue';

defineOptions({ name: 'LyOverview' });

const route = useRoute();

const tabDefs = [
  { key: 'om', label: '运维总览' },
  { key: 'ma', label: '管理总览' },
  { key: 'search', label: '搜索' },
];
const tabKeys = tabDefs.map((t) => t.key);

function normalizeTab(value: unknown) {
  return tabKeys.includes(value as string) ? (value as string) : 'om';
}

const activeTab = ref(normalizeTab(route.query.tab));

// 仅在组件内切换页签，不修改 URL —— 避免触发路由变化导致整页重新挂载（刷新）
function onTabChange(tab: string) {
  activeTab.value = tab;
}

// 支持外部带 ?tab= 的深链（如 /ly/search 兼容跳转）在同一路由内切换页签
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
    <NTabs
      :value="activeTab"
      type="line"
      animated
      class="ly-workstation-tabs"
      @update:value="onTabChange"
    >
      <NTabPane v-for="tab in tabDefs" :key="tab.key" :name="tab.key" :tab="tab.label" />
    </NTabs>
    <OmView v-if="activeTab === 'om'" />
    <MaView v-else-if="activeTab === 'ma'" />
    <SearchView v-else-if="activeTab === 'search'" />
  </div>
</template>

<style scoped>
.ly-workstation-tabs {
  padding: 8px 16px 0;
}
</style>
