<script setup lang="ts">
import { computed, ref, watch } from 'vue';

import { NEmpty } from 'naive-ui';

import { normalizeFormOptions, normalizeRuntimeFormRule } from '#/api/formdesign';

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

const api = ref<any>(null);
const formData = ref<Record<string, any>>({ ...props.modelValue });
let syncingFromProps = false;

function cloneRecord(value?: Record<string, any>) {
  return { ...(value ?? {}) };
}

function isSameRecord(
  left?: Record<string, any>,
  right?: Record<string, any>,
) {
  return JSON.stringify(left ?? {}) === JSON.stringify(right ?? {});
}

const rule = computed(() => normalizeRuntimeFormRule(props.schema as Record<string, any>));
const option = computed(() => ({
  ...normalizeFormOptions(props.schema as Record<string, any>, props.options),
  disabled: props.disabled || props.readonly,
}));

watch(
  () => props.modelValue,
  value => {
    if (isSameRecord(value, formData.value)) {
      return;
    }
    syncingFromProps = true;
    formData.value = cloneRecord(value);
  },
  { deep: true },
);

watch(
  formData,
  value => {
    if (syncingFromProps) {
      syncingFromProps = false;
      return;
    }
    if (isSameRecord(value, props.modelValue)) {
      return;
    }
    emit('update:modelValue', cloneRecord(value));
  },
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
