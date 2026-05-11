<script setup lang="ts">
import { ref } from 'vue';

import formCreate from '@form-create/element-ui';

defineOptions({ name: 'FormPreview' });

const props = withDefaults(defineProps<{
  modelValue?: Record<string, any>;
  options?: Record<string, any>;
  rule?: any[];
}>(), {
  modelValue: () => ({}),
  options: () => ({}),
  rule: () => [],
});

const emit = defineEmits<{
  'update:modelValue': [value: Record<string, any>];
}>();

const formData = ref<Record<string, any>>({ ...props.modelValue });
const api = ref<any>(null);
</script>

<template>
  <div class="form-preview">
    <form-create
      v-if="rule.length"
      v-model:api="api"
      v-model="formData"
      :option="options"
      :rule="rule"
    />
    <el-empty v-else description="暂无表单字段" />
  </div>
</template>

<style scoped>
.form-preview {
  padding: 16px;
}
</style>
