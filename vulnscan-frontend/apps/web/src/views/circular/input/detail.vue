<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { NButton, NCard, NDescriptions, NDescriptionsItem, NSpace, NSteps, NStep, NTag, NTimeline, NTimelineItem, NEmpty, NSpin } from 'naive-ui';
import { useRoute, useRouter } from 'vue-router';
import { getInputDetail, getCircularOplogs, CircularStatusLabels, CircularStatusTypes, DataSourceLabels, OperationTypeLabels, type CircularDetailResp, type CircularOplog } from '#/api/circular';

defineOptions({ name: 'CircularInputDetail' });

const route = useRoute();
const router = useRouter();
const loading = ref(true);
const detail = ref<CircularDetailResp | null>(null);
const oplogs = ref<CircularOplog[]>([]);

const stepMap: Record<string, number> = { to_be_submit: 0, to_be_verified: 1, to_be_distributed: 2, to_be_processed: 3, to_be_reviewed: 4, completed: 5 };

async function fetchData() {
  try {
    const id = route.params.id as string;
    detail.value = await getInputDetail(id) as unknown as CircularDetailResp;
    try { oplogs.value = (await getCircularOplogs(id) as unknown as CircularOplog[]) ?? []; } catch { oplogs.value = []; }
  } finally { loading.value = false; }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px;max-width:960px;margin:0 auto">
    <NSpin :show="loading">
      <template v-if="detail">
        <NCard size="small" style="margin-bottom:16px">
          <template #header>
            <NSpace align="center" :size="12">
              <NButton text @click="router.back()">← 返回</NButton>
              <span style="font-size:16px;font-weight:600">{{ detail.title }}</span>
              <NTag :type="(CircularStatusTypes[detail.status]||'default') as any" size="small" :bordered="false">{{ CircularStatusLabels[detail.status] ?? detail.status }}</NTag>
            </NSpace>
          </template>
          <NSteps :current="stepMap[detail.status] ?? 0" size="small" style="margin-bottom:20px">
            <NStep title="录入" /><NStep title="核验" /><NStep title="派发" /><NStep title="处置" /><NStep title="审核" /><NStep title="归档" />
          </NSteps>
          <NDescriptions label-placement="left" bordered :column="2" size="small">
            <NDescriptionsItem label="通报编号">{{ detail.code }}</NDescriptionsItem>
            <NDescriptionsItem label="数据来源">{{ DataSourceLabels[detail.source] ?? detail.source }}</NDescriptionsItem>
            <NDescriptionsItem label="所属组织">{{ detail.organize || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="处置期限">{{ detail.processing_deadline || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="创建时间">{{ detail.created_at }}</NDescriptionsItem>
            <NDescriptionsItem label="更新时间">{{ detail.updated_at }}</NDescriptionsItem>
          </NDescriptions>
        </NCard>

        <NCard title="操作日志" size="small">
          <NTimeline v-if="oplogs.length">
            <NTimelineItem v-for="log in oplogs" :key="log.id" :title="OperationTypeLabels[log.operation_type] ?? log.operation_type" :time="log.created_at" :type="log.operation_result === '成功' ? 'success' : 'default'">
              <div v-if="log.operator" style="font-size:12px;color:#666">操作人: {{ log.operator }}</div>
            </NTimelineItem>
          </NTimeline>
          <NEmpty v-else description="暂无操作记录" />
        </NCard>
      </template>
    </NSpin>
  </div>
</template>
