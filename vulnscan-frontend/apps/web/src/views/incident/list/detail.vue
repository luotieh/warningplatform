<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { NButton, NCard, NDescriptions, NDescriptionsItem, NSpace, NSteps, NStep, NTag, NTabPane, NTabs, NTimeline, NTimelineItem, NEmpty, NSpin, NProgress, NModal, NForm, NFormItem, NInput, NRadioGroup, NRadio, useMessage } from 'naive-ui';
import { useRoute, useRouter } from 'vue-router';
import { getIncidentDetail, getOplogList, getCommentList, createComment, deleteComment, manualAudit, aiPreAudit, submitRemediation, verifyRemediation, closeIncident, type SecurityIncident, type IncidentComment } from '#/api/incident';

defineOptions({ name: 'IncidentDetail' });

const route = useRoute();
const router = useRouter();
const message = useMessage();
const loading = ref(true);
const incident = ref<SecurityIncident | null>(null);
const oplogs = ref<any[]>([]);
const comments = ref<IncidentComment[]>([]);
const newComment = ref('');

const statusLabels: Record<number, string> = { 1: '待审核', 2: 'AI预审中', 3: '待人工审核', 4: '审核通过', 5: '审核不通过', 6: '整改中', 7: '已关闭' };
const statusTypes: Record<number, string> = { 1: 'default', 2: 'info', 3: 'warning', 4: 'success', 5: 'error', 6: 'warning', 7: 'default' };
const levelLabels: Record<number, string> = { 1: '低', 2: '中', 3: '高', 4: '紧急' };
const levelColors: Record<number, string> = { 1: '#18a058', 2: '#2080f0', 3: '#f0a020', 4: '#d03050' };

const stepMap: Record<number, number> = { 1: 0, 2: 1, 3: 1, 4: 2, 5: 2, 6: 3, 7: 5 };

const showAuditModal = ref(false);
const auditForm = ref({ passed: true, opinion: '' });
const showRemModal = ref(false);
const remForm = ref({ plan: '', result: '' });

async function fetchData() {
  try {
    const id = route.params.id as string;
    incident.value = await getIncidentDetail(id) as any;
    try { const r = await getOplogList({ incident_id: id }); oplogs.value = r.items ?? []; } catch { oplogs.value = []; }
    try { const r = await getCommentList({ incident_id: id }); comments.value = r.items ?? []; } catch { comments.value = []; }
  } finally { loading.value = false; }
}

async function handleAiAudit() {
  try { await aiPreAudit(route.params.id as string); message.success('AI预审完成'); await fetchData(); } catch (e: any) { message.error(e?.message || 'AI预审失败'); }
}

async function handleManualAudit() {
  try { await manualAudit(route.params.id as string, auditForm.value); message.success('审核完成'); showAuditModal.value = false; await fetchData(); } catch (e: any) { message.error(e?.message || '审核失败'); }
}

async function handleRemediation() {
  try { await submitRemediation(route.params.id as string, remForm.value); message.success('整改提交成功'); showRemModal.value = false; await fetchData(); } catch (e: any) { message.error(e?.message || '提交失败'); }
}

async function handleVerify() {
  try { await verifyRemediation(route.params.id as string, { passed: true }); message.success('验证通过'); await fetchData(); } catch (e: any) { message.error(e?.message || '验证失败'); }
}

async function handleClose() {
  try { await closeIncident(route.params.id as string); message.success('事件已关闭'); await fetchData(); } catch (e: any) { message.error(e?.message || '关闭失败'); }
}

async function handleAddComment() {
  if (!newComment.value.trim()) return;
  try { await createComment({ incident_id: route.params.id as string, content: newComment.value }); newComment.value = ''; message.success('评论已添加'); await fetchData(); } catch (e: any) { message.error(e?.message || '评论失败'); }
}

async function handleDeleteComment(id: string) {
  try { await deleteComment(id); message.success('已删除'); await fetchData(); } catch (e: any) { message.error(e?.message || '删除失败'); }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px;max-width:1000px;margin:0 auto">
    <NSpin :show="loading">
      <template v-if="incident">
        <NCard size="small" style="margin-bottom:16px">
          <template #header>
            <NSpace align="center" :size="12">
              <NButton text @click="router.back()">← 返回</NButton>
              <span style="font-size:16px;font-weight:600">{{ incident.name }}</span>
              <span :style="{padding:'2px 8px',borderRadius:'4px',fontSize:'12px',fontWeight:'600',color:'#fff',background:levelColors[incident.level]??'#999'}">{{ levelLabels[incident.level] ?? '-' }}</span>
              <NTag :type="(statusTypes[incident.status]||'default') as any" size="small" :bordered="false">{{ statusLabels[incident.status] ?? '-' }}</NTag>
            </NSpace>
          </template>
          <template #header-extra>
            <NSpace :size="8">
              <NButton v-if="incident.status<=3" size="small" type="info" @click="handleAiAudit">AI预审</NButton>
              <NButton v-if="incident.status===3" size="small" type="primary" @click="showAuditModal=true">人工审核</NButton>
              <NButton v-if="incident.status===4||incident.status===6" size="small" type="warning" @click="showRemModal=true">提交整改</NButton>
              <NButton v-if="incident.status===6" size="small" type="success" @click="handleVerify">验证整改</NButton>
              <NButton v-if="incident.status===4||incident.status===6" size="small" @click="handleClose">关闭事件</NButton>
            </NSpace>
          </template>
          <NSteps :current="stepMap[incident.status] ?? 0" size="small" :status="incident.status===5?'error':'process'" style="margin-bottom:20px">
            <NStep title="录入" /><NStep title="AI预审" /><NStep title="人工审核" /><NStep title="整改" /><NStep title="验证" /><NStep title="关闭" />
          </NSteps>
        </NCard>

        <NTabs type="line" animated>
          <NTabPane name="basic" tab="基本信息">
            <NDescriptions label-placement="left" bordered :column="2" size="small">
              <NDescriptionsItem label="事件编号">{{ incident.incident_no }}</NDescriptionsItem>
              <NDescriptionsItem label="来源系统">{{ incident.source_system || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="源IP">{{ incident.source_ip || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="目标IP">{{ incident.target_ip || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="攻击类型">{{ incident.attack_type || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="事件时间">{{ incident.event_time || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="SLA等级">{{ incident.sla_level || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="SLA期限">
                <span v-if="incident.sla_deadline" :style="new Date(incident.sla_deadline)<new Date()?'color:#d03050;font-weight:600':''">{{ incident.sla_deadline }}</span>
                <span v-else>-</span>
              </NDescriptionsItem>
              <NDescriptionsItem label="创建时间">{{ incident.created_at }}</NDescriptionsItem>
              <NDescriptionsItem label="关闭时间">{{ incident.closed_at || '-' }}</NDescriptionsItem>
            </NDescriptions>
            <div v-if="incident.description" style="margin-top:16px;padding:12px;background:#f8f8fa;border-radius:6px;line-height:1.8;font-size:13px">{{ incident.description }}</div>
          </NTabPane>

          <NTabPane name="ai" tab="AI 分析">
            <template v-if="incident.ai_pre_status===1">
              <NCard size="small" style="margin-bottom:12px">
                <NSpace :size="24">
                  <div><div style="font-size:12px;color:#999;margin-bottom:4px">置信度</div><NProgress type="circle" :percentage="Math.round((incident.ai_confidence??0)*100)" :stroke-width="6" style="width:80px" /></div>
                  <div><div style="font-size:12px;color:#999;margin-bottom:4px">风险评分</div><NProgress type="line" :percentage="incident.risk_score??0" :indicator-placement="'inside'" style="width:200px" /></div>
                  <div><div style="font-size:12px;color:#999;margin-bottom:4px">AI分类</div><NTag size="small" type="info">{{ incident.ai_category || '-' }}</NTag></div>
                </NSpace>
              </NCard>
              <NCard title="AI标签" size="small" style="margin-bottom:12px" v-if="incident.ai_tags?.length">
                <NSpace :size="4"><NTag v-for="t in incident.ai_tags" :key="t" size="small" :bordered="false">{{ t }}</NTag></NSpace>
              </NCard>
              <NCard title="AI 审核意见" size="small" v-if="incident.ai_opinion">
                <div style="line-height:1.8;font-size:13px;white-space:pre-wrap">{{ incident.ai_opinion }}</div>
              </NCard>
            </template>
            <NEmpty v-else description="暂未进行AI预审" />
          </NTabPane>

          <NTabPane name="remediation" tab="整改信息">
            <NDescriptions label-placement="left" bordered :column="1" size="small" v-if="incident.remediation_plan||incident.remediation_result">
              <NDescriptionsItem label="整改方案">{{ incident.remediation_plan || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="整改结果">{{ incident.remediation_result || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="提交时间">{{ incident.remediation_submitted_at || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="验证时间">{{ incident.verified_at || '-' }}</NDescriptionsItem>
            </NDescriptions>
            <NEmpty v-else description="暂无整改信息" />
          </NTabPane>

          <NTabPane name="comments" tab="评论">
            <NSpace vertical :size="12">
              <NSpace :size="8">
                <NInput v-model:value="newComment" placeholder="输入评论..." style="width:400px" @keyup.enter="handleAddComment" />
                <NButton type="primary" size="small" @click="handleAddComment">发送</NButton>
              </NSpace>
              <div v-for="c in comments" :key="c.id" style="padding:8px 12px;background:#f8f8fa;border-radius:6px">
                <div style="font-size:12px;color:#999;margin-bottom:4px">{{ c.author }} · {{ c.created_at }}</div>
                <div style="font-size:13px">{{ c.content }}</div>
                <NButton text type="error" size="tiny" @click="handleDeleteComment(c.id)" style="margin-top:4px">删除</NButton>
              </div>
              <NEmpty v-if="!comments.length" description="暂无评论" />
            </NSpace>
          </NTabPane>

          <NTabPane name="oplogs" tab="操作日志">
            <NTimeline v-if="oplogs.length">
              <NTimelineItem v-for="log in oplogs" :key="log.id" :title="log.action" :time="log.created_at" type="info">
                <div v-if="log.operator" style="font-size:12px;color:#666">操作人: {{ log.operator }}</div>
                <div v-if="log.detail" style="font-size:12px;color:#666">{{ log.detail }}</div>
              </NTimelineItem>
            </NTimeline>
            <NEmpty v-else description="暂无操作记录" />
          </NTabPane>
        </NTabs>

        <NModal v-model:show="showAuditModal" preset="dialog" title="人工审核" positive-text="确认" negative-text="取消" @positive-click="handleManualAudit">
          <NForm label-placement="left" label-width="80">
            <NFormItem label="审核结果"><NRadioGroup v-model:value="auditForm.passed"><NRadio :value="true">通过</NRadio><NRadio :value="false">不通过</NRadio></NRadioGroup></NFormItem>
            <NFormItem label="审核意见"><NInput v-model:value="auditForm.opinion" type="textarea" :rows="3" /></NFormItem>
          </NForm>
        </NModal>

        <NModal v-model:show="showRemModal" preset="dialog" title="提交整改" positive-text="提交" negative-text="取消" @positive-click="handleRemediation">
          <NForm label-placement="left" label-width="80">
            <NFormItem label="整改方案"><NInput v-model:value="remForm.plan" type="textarea" :rows="3" /></NFormItem>
            <NFormItem label="整改结果"><NInput v-model:value="remForm.result" type="textarea" :rows="3" /></NFormItem>
          </NForm>
        </NModal>
      </template>
    </NSpin>
  </div>
</template>
