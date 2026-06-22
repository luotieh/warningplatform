<script lang="ts" setup>
import { onMounted } from 'vue';
import { useRouter } from 'vue-router';

import { NButton, NCard, NSpace, NText } from 'naive-ui';

import { useLyStore } from '#/store/ly';

defineOptions({ name: 'LyOverviewAN' });

const router = useRouter();
const lyStore = useLyStore();

onMounted(async () => {
  if (!lyStore.events.length) {
    await lyStore.loadEvents();
  }
});
</script>

<template>
  <div class="ly-page">
    <NCard title="分析总览" size="small">
      <NSpace vertical :size="12">
        <NText depth="3">
          当前已完成风险探测主链路迁移，分析入口沿用原业务逻辑，统一跳转到全局搜索与事件列表视图。
        </NText>
        <NSpace>
          <NButton type="primary" @click="router.push('/ly/search')">进入搜索</NButton>
          <NButton @click="router.push('/ly/event/list')">查看事件</NButton>
        </NSpace>
      </NSpace>
    </NCard>
  </div>
</template>

<style scoped>
.ly-page {
  padding: 12px;
}
</style>
