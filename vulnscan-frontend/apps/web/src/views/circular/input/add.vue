<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { NButton, NCard, NForm, NFormItem, NInput, NSelect, NSpace, useMessage } from 'naive-ui';
import { useRoute, useRouter } from 'vue-router';
import { createInput, updateInput, getInputDetail, getTemplateList, type CircularTemplate } from '#/api/circular';

defineOptions({ name: 'CircularInputAdd' });

const route = useRoute();
const router = useRouter();
const message = useMessage();
const editId = ref(route.query.id as string || '');
const templates = ref<CircularTemplate[]>([]);
const form = ref({ title: '', circular_template: '', organize: '', processing_deadline: '', source: 'manual_input' });

async function loadTemplates() {
  try { const r = await getTemplateList({ size: 100 }); templates.value = r.items; } catch {}
}

async function loadDetail() {
  if (!editId.value) return;
  try {
    const d = await getInputDetail(editId.value) as any;
    form.value = { title: d.title || '', circular_template: d.circular_template || '', organize: d.organize || '', processing_deadline: d.processing_deadline || '', source: d.source || 'manual_input' };
  } catch {}
}

async function handleSave() {
  if (!form.value.title) { message.warning('请输入标题'); return; }
  try {
    if (editId.value) { await updateInput(editId.value, form.value); message.success('更新成功'); }
    else { await createInput(form.value); message.success('创建成功'); }
    router.push('/circular/input');
  } catch (e: any) { message.error(e?.message || '保存失败'); }
}

onMounted(() => { loadTemplates(); loadDetail(); });
</script>

<template>
  <div style="padding:16px;max-width:800px;margin:0 auto">
    <NCard :title="editId ? '编辑通报' : '新建通报'" size="small">
      <NForm label-placement="left" label-width="100">
        <NFormItem label="通报标题" required><NInput v-model:value="form.title" placeholder="请输入标题" /></NFormItem>
        <NFormItem label="录入模板"><NSelect v-model:value="form.circular_template" :options="templates.map(t=>({label:t.template_name,value:t.id}))" placeholder="选择模板" clearable /></NFormItem>
        <NFormItem label="所属组织"><NInput v-model:value="form.organize" placeholder="请输入组织" /></NFormItem>
        <NFormItem label="处置期限"><NInput v-model:value="form.processing_deadline" placeholder="YYYY-MM-DD" /></NFormItem>
      </NForm>
      <NSpace justify="end">
        <NButton @click="router.back()">取消</NButton>
        <NButton type="primary" @click="handleSave">{{ editId ? '保存' : '创建' }}</NButton>
      </NSpace>
    </NCard>
  </div>
</template>
