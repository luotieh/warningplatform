<script lang="ts" setup>
import { computed, onBeforeUnmount } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';
import { useTabs } from '@vben/hooks';

import { NButton } from 'naive-ui';

import RecordDetailContent from './RecordDetailContent.vue';

defineOptions({ name: 'MonitorRecordDetail' });

const route = useRoute();
const router = useRouter();
const { resetTabTitle } = useTabs();

const recordId = computed(() => String(route.params.id ?? ''));
const returnTaskId = computed(() => String(route.query.taskId ?? '').trim());

function goBack() {
  if (returnTaskId.value) {
    router.push(`/monitor/records/${returnTaskId.value}`);
    return;
  }
  router.back();
}

onBeforeUnmount(() => resetTabTitle());
</script>

<template>
  <Page title="监测记录详情" description="来自独立路由页">
    <template #extra>
      <NButton @click="goBack">返回</NButton>
    </template>
    <RecordDetailContent v-if="recordId" :record-id="recordId" @close="goBack" />
  </Page>
</template>
