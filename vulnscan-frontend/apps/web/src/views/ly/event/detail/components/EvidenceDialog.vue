<script setup lang="ts">
import { ref, watch } from 'vue';
import { NAlert, NModal, NSpin } from 'naive-ui';
import { deepflowGetOccurrences } from '#/api/ly/deepflow';

const props = defineProps<{ eventId: string; hitId: string; visible: boolean; version?: number }>();
const emit = defineEmits<{ (event: 'update:visible', value: boolean): void }>();
const loading = ref(false);
const error = ref('');
const evidence = ref<Record<string, any>>({});
let request = 0;
watch(() => [props.visible, props.eventId, props.hitId, props.version], async () => {
  const current = ++request;
  if (!props.visible || !props.hitId) return;
  loading.value = true;
  error.value = '';
  evidence.value = {};
  try {
    const page = await deepflowGetOccurrences(props.eventId, '', props.hitId, props.version || 0);
    if (current === request) evidence.value = page.items[0] || {};
  } catch (e) {
    if (current === request) error.value = e instanceof Error ? e.message : '证据读取失败';
  } finally {
    if (current === request) loading.value = false;
  }
});
</script>

<template>
  <NModal :show="visible" preset="card" title="关键证据 · 原始命中明细" style="width:900px;max-width:95vw" @update:show="emit('update:visible', $event)">
    <NSpin :show="loading">
      <NAlert v-if="error" type="warning">{{ error }}</NAlert>
      <template v-else>
        <div>事件：{{ eventId }}</div>
        <div style="overflow-wrap:anywhere">明细 ID：{{ hitId }}</div>
        <pre style="max-height:65vh;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere">{{ JSON.stringify(evidence, null, 2) }}</pre>
      </template>
    </NSpin>
  </NModal>
</template>
