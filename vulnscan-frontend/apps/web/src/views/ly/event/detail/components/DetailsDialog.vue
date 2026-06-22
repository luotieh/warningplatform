<script lang="ts" setup>
import { computed } from 'vue';

import { NButton, NModal, NSpace } from 'naive-ui';

const props = withDefaults(
  defineProps<{
    cancelButtonText?: string;
    closeOnOverlayClick?: boolean;
    confirmButtonText?: string;
    showFooter?: boolean;
    title?: string;
    visible?: boolean;
  }>(),
  {
    cancelButtonText: '取消',
    closeOnOverlayClick: true,
    confirmButtonText: '确定',
    showFooter: false,
    title: '详情',
    visible: false,
  },
);

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'confirm'): void;
  (e: 'update:visible', value: boolean): void;
}>();

const show = computed({
  get: () => props.visible,
  set: (value: boolean) => emit('update:visible', value),
});

function close() {
  show.value = false;
  emit('close');
}

function confirm() {
  show.value = false;
  emit('confirm');
}
</script>

<template>
  <NModal v-model:show="show" preset="card" :title="title" :mask-closable="closeOnOverlayClick" style="width: min(680px, 92vw)">
    <slot />
    <template v-if="showFooter" #footer>
      <NSpace justify="end">
        <NButton @click="close">{{ cancelButtonText }}</NButton>
        <NButton type="primary" @click="confirm">{{ confirmButtonText }}</NButton>
      </NSpace>
    </template>
  </NModal>
</template>
