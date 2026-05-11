<script setup lang="ts">
import { computed, ref, watch } from 'vue';

import type { Api } from '@form-create/naive-ui';
import { NEmpty } from 'naive-ui';

import { normalizeFormOptions, normalizeFormRule } from '#/api/form';

defineOptions({ name: 'DynamicFormRenderer' });

const props = withDefaults(defineProps<{
  disabled?: boolean;
  modelValue?: Record<string, any>;
  options?: Record<string, any>;
  readonly?: boolean;
  schema?: Record<string, any> | any[];
}>(), {
  disabled: false,
  modelValue: () => ({}),
  options: () => ({}),
  readonly: false,
  schema: () => ({}),
});

const emit = defineEmits<{
  'update:modelValue': [value: Record<string, any>];
}>();

const api = ref<Api | null>(null);
const formData = ref<Record<string, any>>({ ...props.modelValue });

const rule = computed(() => normalizeFormRule(props.schema as Record<string, any>));
const option = computed(() => ({
  ...normalizeFormOptions(props.schema as Record<string, any>, props.options),
  disabled: props.disabled || props.readonly,
}));

watch(
  () => props.modelValue,
  value => {
    formData.value = { ...(value ?? {}) };
  },
  { deep: true },
);

watch(
  formData,
  value => emit('update:modelValue', { ...value }),
  { deep: true },
);

async function validate() {
  if (!api.value) return true;
  return api.value.validate();
}

function getFormData() {
  return api.value?.formData?.() ?? formData.value;
}

defineExpose({ getFormData, validate });
</script>

<template>
  <div class="dynamic-form-renderer">
    <form-create
      v-if="rule.length"
      v-model:api="api"
      v-model="formData"
      :option="option"
      :rule="rule"
    />
    <NEmpty v-else description="暂无动态表单字段" />
  </div>
</template>

<style scoped>
.dynamic-form-renderer {
  min-width: 0;
}

.dynamic-form-renderer :deep(.fc-form) {
  color: var(--n-text-color);
}
</style>
