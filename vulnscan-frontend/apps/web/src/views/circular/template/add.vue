<script lang="ts" setup>
import { ref } from 'vue';
import { NButton, NCard, NForm, NFormItem, NInput, NSelect, NSpace, NSwitch, useMessage } from 'naive-ui';
import { useRouter } from 'vue-router';
import { createTemplate, type CircularTemplateType, TemplateTypeLabels } from '#/api/circular';

defineOptions({ name: 'CircularTemplateAdd' });

const router = useRouter();
const message = useMessage();
const form = ref({ template_name: '', type: 'input' as CircularTemplateType, template_description: '', template_data: '', default_flag: false });
const typeOptions = Object.entries(TemplateTypeLabels).map(([v, l]) => ({ label: l, value: v }));

async function handleSave() {
  if (!form.value.template_name) { message.warning('请输入模板名称'); return; }
  try { await createTemplate(form.value); message.success('创建成功'); router.push('/circular/template'); }
  catch (e: any) { message.error(e?.message || '创建失败'); }
}
</script>

<template>
  <div style="padding:16px;max-width:800px;margin:0 auto">
    <NCard title="新建模板" size="small">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="模板名称" required><NInput v-model:value="form.template_name" placeholder="请输入模板名称" /></NFormItem>
        <NFormItem label="模板类型"><NSelect v-model:value="form.type" :options="typeOptions" /></NFormItem>
        <NFormItem label="描述"><NInput v-model:value="form.template_description" type="textarea" :rows="2" /></NFormItem>
        <NFormItem label="模板数据"><NInput v-model:value="form.template_data" type="textarea" placeholder="JSON格式" :rows="6" /></NFormItem>
        <NFormItem label="设为默认"><NSwitch v-model:value="form.default_flag" /></NFormItem>
      </NForm>
      <NSpace justify="end">
        <NButton @click="router.back()">取消</NButton>
        <NButton type="primary" @click="handleSave">创建</NButton>
      </NSpace>
    </NCard>
  </div>
</template>
