<script lang="ts" setup>
import { NDrawer, NDrawerContent } from 'naive-ui';
import ScanTaskDetail from './detail.vue';

const props = defineProps<{
  visible: boolean;
  taskId: string;
}>();

const emit = defineEmits<{
  (e: 'update:visible', val: boolean): void;
  (e: 'close'): void;
}>();

function handleClose() {
  emit('update:visible', false);
  emit('close');
}
</script>

<template>
  <NDrawer
    :show="visible"
    :width="'85%'"
    placement="right"
    @update:show="(v) => emit('update:visible', v)"
  >
    <NDrawerContent :native-scrollbar="false" closable @close="handleClose">
      <template #header>
        <span style="font-size: 15px; font-weight: 600">扫描任务详情</span>
      </template>
      <ScanTaskDetail
        v-if="visible && taskId"
        :task-id="taskId"
        @close="handleClose"
      />
    </NDrawerContent>
  </NDrawer>
</template>
