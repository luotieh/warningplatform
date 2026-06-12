<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import {
  NCard, NDescriptions, NDescriptionsItem, NTag, NButton, NSpace,
  NTimeline, NTimelineItem, NModal, NForm, NFormItem, NInput,
  NSwitch, NSpin, NDivider, NAlert, NEmpty,
  useMessage,
} from 'naive-ui';
import { useRoute, useRouter } from 'vue-router';
import {
  getOrderDetail, getOrderOplogs, acceptOrder, rejectOrder,
  submitResult, reviewOrder, cancelOrder,
  type DispatchOrder, type DispatchOplog,
  DispatchStatusLabels, DispatchStatusTypes,
  DispatchTypeLabels, PriorityLabels, PriorityColors,
  SourceTypeLabels,
} from '#/api/dispatch';

const route = useRoute();
const router = useRouter();
const message = useMessage();

const orderId = computed(() => route.params.id as string);
const order = ref<DispatchOrder | null>(null);
const oplogs = ref<DispatchOplog[]>([]);
const loading = ref(false);

async function fetchDetail() {
  loading.value = true;
  try {
    const res = await getOrderDetail(orderId.value);
    order.value = (res as any)?.data ?? res;
    const logRes = await getOrderOplogs(orderId.value);
    oplogs.value = Array.isArray(logRes) ? logRes : ((logRes as any)?.data ?? []);
  } catch (e: any) {
    message.error(e?.message || '加载失败');
  } finally {
    loading.value = false;
  }
}

onMounted(fetchDetail);

function fmtTime(t: string | null | undefined) {
  if (!t) return '-';
  return new Date(t).toLocaleString('zh-CN');
}

const actionTimelineType: Record<string, 'success' | 'warning' | 'error' | 'info' | 'default'> = {
  create: 'info',
  assign: 'info',
  accept: 'success',
  reject: 'error',
  submit: 'success',
  review_pass: 'success',
  review_reject: 'warning',
  cancel: 'error',
  external_submit: 'success',
  comment: 'default',
};

// ─── 接收/拒绝 ───

async function handleAccept() {
  try {
    await acceptOrder(orderId.value);
    message.success('已接收');
    fetchDetail();
  } catch (e: any) { message.error(e?.message || '操作失败'); }
}

const showReject = ref(false);
const rejectReason = ref('');
async function handleReject() {
  try {
    await rejectOrder(orderId.value, rejectReason.value);
    message.success('已拒绝');
    showReject.value = false;
    fetchDetail();
  } catch (e: any) { message.error(e?.message || '操作失败'); }
}

// ─── 提交结果 ───

const showSubmit = ref(false);
const submitForm = ref({ result: '' });
async function handleSubmit() {
  if (!submitForm.value.result) {
    message.warning('请填写处理结果');
    return;
  }
  try {
    await submitResult(orderId.value, submitForm.value);
    message.success('已提交');
    showSubmit.value = false;
    fetchDetail();
  } catch (e: any) { message.error(e?.message || '提交失败'); }
}

// ─── 审核 ───

const showReview = ref(false);
const reviewForm = ref({ approved: true, comment: '' });
async function handleReview() {
  try {
    await reviewOrder(orderId.value, reviewForm.value);
    message.success(reviewForm.value.approved ? '审核通过' : '已驳回');
    showReview.value = false;
    fetchDetail();
  } catch (e: any) { message.error(e?.message || '审核失败'); }
}

// ─── 取消 ───

async function handleCancel() {
  try {
    await cancelOrder(orderId.value);
    message.success('已取消');
    fetchDetail();
  } catch (e: any) { message.error(e?.message || '操作失败'); }
}
</script>

<template>
  <div class="p-4">
    <NSpin :show="loading">
      <template v-if="order">
        <!-- 基本信息 -->
        <NCard :bordered="false">
          <template #header>
            <NSpace align="center">
              <NButton quaternary size="small" @click="router.back()">← 返回</NButton>
              <span style="font-size: 18px; font-weight: 600">{{ order.title }}</span>
              <NTag size="small" :bordered="false">{{ order.code }}</NTag>
              <NTag :type="(DispatchStatusTypes[order.status] as any)" :bordered="false">
                {{ DispatchStatusLabels[order.status] || order.status }}
              </NTag>
            </NSpace>
          </template>
          <template #header-extra>
            <NSpace>
              <NButton v-if="order.status === 'pending'" type="success" size="small" @click="handleAccept">接收</NButton>
              <NButton v-if="order.status === 'pending'" type="warning" size="small" @click="showReject = true">拒绝</NButton>
              <NButton v-if="order.status === 'in_progress'" type="primary" size="small" @click="showSubmit = true">提交结果</NButton>
              <NButton v-if="order.status === 'submitted'" type="info" size="small" @click="showReview = true">审核</NButton>
              <NButton v-if="order.status !== 'completed' && order.status !== 'cancelled'" quaternary type="error" size="small" @click="handleCancel">取消</NButton>
            </NSpace>
          </template>

          <NDescriptions :column="3" label-placement="left" bordered size="small">
            <NDescriptionsItem label="类型">
              <NTag size="small" :bordered="false">{{ DispatchTypeLabels[order.type] || order.type }}</NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="优先级">
              <NTag size="small" :bordered="false"
                :style="{ color: PriorityColors[order.priority], backgroundColor: PriorityColors[order.priority] + '18' }">
                {{ PriorityLabels[order.priority] || `P${order.priority}` }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="来源">
              {{ SourceTypeLabels[order.source_type] || order.source_type || '-' }}
              <span v-if="order.source_title" style="margin-left: 4px; color: #666">
                ({{ order.source_title }})
              </span>
            </NDescriptionsItem>
            <NDescriptionsItem label="处理人">
              {{ order.assignee_name || '-' }}
              <NTag v-if="order.assignee_type" size="small" :bordered="false" style="margin-left: 4px">
                {{ order.assignee_type === 'internal' ? '内部' : '外部' }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="联系方式">{{ order.assignee_contact || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="截止时间">{{ fmtTime(order.deadline) }}</NDescriptionsItem>
            <NDescriptionsItem label="接收时间">{{ fmtTime(order.accepted_at) }}</NDescriptionsItem>
            <NDescriptionsItem label="提交时间">{{ fmtTime(order.submitted_at) }}</NDescriptionsItem>
            <NDescriptionsItem label="完成时间">{{ fmtTime(order.completed_at) }}</NDescriptionsItem>
            <NDescriptionsItem label="创建时间">{{ fmtTime(order.created_at) }}</NDescriptionsItem>
          </NDescriptions>
        </NCard>

        <!-- 描述 -->
        <NCard v-if="order.description" title="详细描述" :bordered="false" style="margin-top: 16px" size="small">
          <div style="white-space: pre-wrap; line-height: 1.6">{{ order.description }}</div>
        </NCard>

        <!-- 处理结果 -->
        <NCard v-if="order.result" title="处理结果" :bordered="false" style="margin-top: 16px" size="small">
          <div style="white-space: pre-wrap; line-height: 1.6">{{ order.result }}</div>
        </NCard>

        <!-- 审核意见 -->
        <NCard v-if="order.review_comment" title="审核意见" :bordered="false" style="margin-top: 16px" size="small">
          <NAlert :type="order.status === 'completed' ? 'success' : 'warning'">
            {{ order.review_comment }}
          </NAlert>
        </NCard>

        <!-- 拒绝原因 -->
        <NCard v-if="order.reject_reason" title="拒绝原因" :bordered="false" style="margin-top: 16px" size="small">
          <NAlert type="error">{{ order.reject_reason }}</NAlert>
        </NCard>

        <!-- 操作日志 -->
        <NCard title="操作日志" :bordered="false" style="margin-top: 16px" size="small">
          <NTimeline v-if="oplogs.length > 0">
            <NTimelineItem v-for="log in oplogs" :key="log.id"
              :type="actionTimelineType[log.action] || 'default'"
              :title="log.content"
              :time="fmtTime(log.created_at)">
              <template #header>
                <span style="font-weight: 500">{{ log.content }}</span>
                <NTag size="tiny" :bordered="false" style="margin-left: 8px">{{ log.operator }}</NTag>
              </template>
            </NTimelineItem>
          </NTimeline>
          <NEmpty v-else description="暂无操作记录" />
        </NCard>
      </template>
      <NEmpty v-else-if="!loading" description="未找到该派发单" />
    </NSpin>

    <!-- 拒绝弹窗 -->
    <NModal v-model:show="showReject" preset="dialog" title="拒绝接收" style="width: 480px"
      positive-text="确认拒绝" negative-text="取消" @positive-click="handleReject">
      <NFormItem label="拒绝原因" style="margin-top: 16px">
        <NInput v-model:value="rejectReason" type="textarea" :rows="3" placeholder="请填写拒绝原因" />
      </NFormItem>
    </NModal>

    <!-- 提交结果弹窗 -->
    <NModal v-model:show="showSubmit" preset="dialog" title="提交处理结果" style="width: 560px"
      positive-text="提交" negative-text="取消" @positive-click="handleSubmit">
      <NForm :model="submitForm" label-placement="left" label-width="auto" style="margin-top: 16px">
        <NFormItem label="处理结果" required>
          <NInput v-model:value="submitForm.result" type="textarea" :rows="5" placeholder="请详细描述处理结果" />
        </NFormItem>
      </NForm>
    </NModal>

    <!-- 审核弹窗 -->
    <NModal v-model:show="showReview" preset="dialog" title="审核处理结果" style="width: 560px"
      positive-text="确认" negative-text="取消" @positive-click="handleReview">
      <NForm :model="reviewForm" label-placement="left" label-width="auto" style="margin-top: 16px">
        <NFormItem label="审核结果">
          <NSpace>
            <NButton :type="reviewForm.approved ? 'success' : 'default'" size="small"
              @click="reviewForm.approved = true">通过</NButton>
            <NButton :type="!reviewForm.approved ? 'error' : 'default'" size="small"
              @click="reviewForm.approved = false">驳回</NButton>
          </NSpace>
        </NFormItem>
        <NFormItem label="审核意见">
          <NInput v-model:value="reviewForm.comment" type="textarea" :rows="3" placeholder="请填写审核意见" />
        </NFormItem>
      </NForm>
    </NModal>
  </div>
</template>
