<script lang="ts" setup>
import { ref } from 'vue';
import { NCard, NTabPane, NTabs } from 'naive-ui';
import RiskPanel from './risk.vue';
import AlertPanel from './alert.vue';

defineOptions({ name: 'AssetSecurity' });

const activeTab = ref('risk');
</script>

<template>
  <div style="padding: 16px">
    <NCard :bordered="false" size="small">
      <NTabs v-model:value="activeTab" type="line">
        <NTabPane name="risk" tab="风险评估"><RiskPanel /></NTabPane>
        <NTabPane name="alert" tab="安全告警"><AlertPanel /></NTabPane>
      </NTabs>
    </NCard>
  </div>
</template>
