<script lang="ts" setup>
import { ref } from 'vue';
import { NCard, NTabPane, NTabs } from 'naive-ui';
import TagPanel from './tag.vue';
import OrganizePanel from './organize.vue';
import ConstructionPanel from './construction.vue';

defineOptions({ name: 'AssetOrgTag' });

const activeTab = ref('organize');
</script>

<template>
  <div style="padding: 16px">
    <NCard :bordered="false" size="small">
      <NTabs v-model:value="activeTab" type="line">
        <NTabPane name="organize" tab="组织管理"><OrganizePanel /></NTabPane>
        <NTabPane name="construction" tab="建设运维单位"><ConstructionPanel /></NTabPane>
        <NTabPane name="tag" tab="标签管理"><TagPanel /></NTabPane>
      </NTabs>
    </NCard>
  </div>
</template>
