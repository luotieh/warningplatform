<script setup lang="ts">
import { computed, ref, watch } from 'vue';

import { NEmpty } from 'naive-ui';

import {
  normalizeFormOptions,
  normalizeRuntimeFormRule,
  parseFormSchema,
} from '#/api/formdesign';

defineOptions({ name: 'DynamicFormRenderer' });

const props = withDefaults(defineProps<{
  disabled?: boolean;
  layout?: 'horizontal' | 'vertical';
  modelValue?: Record<string, any>;
  options?: Record<string, any>;
  readonly?: boolean;
  schema?: Record<string, any> | any[] | string;
}>(), {
  disabled: false,
  layout: 'horizontal',
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

const parsedSchema = computed(() => parseFormSchema(props.schema));
const rule = computed(() => normalizeRuntimeFormRule(parsedSchema.value));
const option = computed(() => ({
  ...normalizeFormOptions(parsedSchema.value, props.options, props.layout),
  disabled: props.disabled || props.readonly,
}));
const formKey = computed(() => JSON.stringify({ rule: rule.value, option: option.value }));

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
  <div class="dynamic-form-renderer" :class="`dynamic-form-renderer--${layout}`">
    <form-create
      v-if="rule.length"
      :key="formKey"
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
  width: 100%;
  min-width: 0;
}

.dynamic-form-renderer :deep(.fc-form) {
  width: 100%;
  color: var(--n-text-color);
}

.dynamic-form-renderer :deep(.n-form) {
  width: 100%;
}

.dynamic-form-renderer :deep(.n-form-item) {
  width: 100%;
  margin-bottom: 16px;
}

.dynamic-form-renderer--vertical :deep(.n-form-item) {
  margin-bottom: 14px;
}

.dynamic-form-renderer :deep(.n-form-item-label) {
  font-weight: 500;
  padding-bottom: 4px;
}

.dynamic-form-renderer :deep(.n-form-item-blank) {
  width: 100%;
  max-width: 100%;
}

.dynamic-form-renderer :deep(.n-input),
.dynamic-form-renderer :deep(.n-input-number),
.dynamic-form-renderer :deep(.n-select),
.dynamic-form-renderer :deep(.n-date-picker),
.dynamic-form-renderer :deep(.n-cascader) {
  width: 100%;
}

.dynamic-form-renderer :deep(.n-row) {
  width: 100%;
  margin-left: 0 !important;
  margin-right: 0 !important;
}

.dynamic-form-renderer :deep(.n-col) {
  max-width: 100%;
}
</style>
