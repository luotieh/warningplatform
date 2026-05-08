<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { NButton, NCard, NDescriptions, NDescriptionsItem, NForm, NFormItem, NInput, NSpace, NTag, NSpin, useMessage } from 'naive-ui';
import { useRoute, useRouter } from 'vue-router';
import { getInputDetail, disposeCircular, CircularStatusLabels, CircularStatusTypes, type CircularDetailResp } from '#/api/circular';

defineOptions({ name: 'CircularDisposalHandle' });

const route = useRoute();
const router = useRouter();
const message = useMessage();
const loading = ref(true);
const detail = ref<CircularDetailResp | null>(null);
const form = ref({ disposal_result: '', disposal_question: '' });

async function fetchData() {
  try { detail.value = await getInputDetail(route.params.id as string); } finally { loading.value = false; }
}

async function handleSubmit() {
  if (!form.value.disposal_result) { message.warning('请填写处置结果'); return; }
  try {
    await disposeCircular(route.params.id as string, form.value);
    message.success('处置提交成功'); router.push('/circular/disposal');
  } catch (e: any) { message.error(e?.message || '处置失败'); }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px;max-width:800px;margin:0 auto">
    <NSpin :show="loading">
      <NCard title="处置通报" size="small" v-if="detail">
        <NDescriptions label-placement="left" bordered :column="2" size="small" style="margin-bottom:20px">
          <NDescriptionsItem label="通报编号">{{ detail.code }}</NDescriptionsItem>
          <NDescriptionsItem label="标题">{{ detail.title }}</NDescriptionsItem>
          <NDescriptionsItem label="状态"><NTag :type="(CircularStatusTypes[detail.status]||'default') as any" size="small" :bordered="false">{{ CircularStatusLabels[detail.status] ?? detail.status }}</NTag></NDescriptionsItem>
          <NDescriptionsItem label="处置期限">{{ detail.processing_deadline || '-' }}</NDescriptionsItem>
        </NDescriptions>
        <NForm label-placement="left" label-width="80">
          <NFormItem label="处置结果" required><NInput v-model:value="form.disposal_result" type="textarea" placeholder="请填写处置结果" :rows="4" /></NFormItem>
          <NFormItem label="遗留问题"><NInput v-model:value="form.disposal_question" type="textarea" placeholder="如有遗留问题请填写" :rows="3" /></NFormItem>
        </NForm>
        <NSpace justify="end">
          <NButton @click="router.back()">取消</NButton>
          <NButton type="primary" @click="handleSubmit">提交处置</NButton>
        </NSpace>
      </NCard>
    </NSpin>
  </div>
</template>
