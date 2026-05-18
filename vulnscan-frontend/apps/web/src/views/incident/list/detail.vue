<script lang="ts" setup>
import { computed, onMounted, ref } from 'vue';
import {
  NButton, NCard, NDescriptions, NDescriptionsItem, NSpace, NSteps, NStep,
  NTag, NTabPane, NTabs, NTimeline, NTimelineItem, NEmpty, NSpin, NProgress,
  NModal, NForm, NFormItem, NInput, NRadioGroup, NRadio, NAlert,
  NGrid, NGridItem,
  useMessage,
} from 'naive-ui';
import { useRoute, useRouter } from 'vue-router';
import {
  getIncidentDetail, getOplogList, getCommentList, createComment,
  deleteComment, manualAudit, aiPreAudit, submitRemediation,
  verifyRemediation, closeIncident, getKnowledgeRecommend,
  transferToCircular,
  type SecurityIncident, type IncidentComment, type OpLog,
} from '#/api/incident';
import { getVulnList, type Vulnerability } from '#/api/vuln';

defineOptions({ name: 'IncidentDetail' });

const route = useRoute();
const router = useRouter();
const message = useMessage();
const loading = ref(true);
const incident = ref<SecurityIncident | null>(null);
const oplogs = ref<OpLog[]>([]);
const comments = ref<IncidentComment[]>([]);
const knowledgeRecs = ref<any[]>([]);
const relatedVulns = ref<Vulnerability[]>([]);
const newComment = ref('');

const levelLabels: Record<number, string> = { 1: '低危', 2: '中危', 3: '高危', 4: '紧急' };
const levelColors: Record<number, string> = { 1: '#18a058', 2: '#2080f0', 3: '#f0a020', 4: '#d03050' };

const statusLabels: Record<number, string> = {
  1: '待人工复核', 2: '复核通过', 3: '复核失败',
  4: '待整改', 5: '整改中', 6: '待验证', 7: '已关闭',
};
const statusTypes: Record<number, string> = {
  1: 'default', 2: 'success', 3: 'error', 4: 'warning', 5: 'info', 6: 'warning', 7: 'default',
};

const sourceLabels: Record<number, string> = {
  1: '站点监测', 2: '漏洞扫描', 3: '流量分析', 4: '风险探测',
};

const slaLevelLabels: Record<number, string> = {
  1: 'P4', 2: 'P3', 3: 'P2', 4: 'P1',
};

const vulnSeverityColors: Record<string, string> = {
  critical: '#d03050', high: '#f0a020', medium: '#2080f0', low: '#18a058', info: '#999',
};
const vulnSeverityLabels: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
};

const statusStepMap: Record<number, number> = {
  1: 0, 2: 1, 3: 1, 4: 2, 5: 2, 6: 3, 7: 5,
};

const stepTitles = ['录入', '智能预审', '人工复核', '整改', '验证', '关闭'];

const currentStep = computed(() => {
  if (incident.value?.current_step != null) return incident.value.current_step;
  return statusStepMap[incident.value?.status ?? 1] ?? 0;
});

const eventTags = computed(() => {
  const tags = incident.value?.ai_tags;
  if (!tags) return [];
  if (Array.isArray(tags)) return tags;
  return tags.split(',').map(t => t.trim()).filter(Boolean);
});

const isOverdue = computed(() => {
  const d = incident.value?.sla_deadline;
  if (!d) return false;
  return new Date(d) < new Date();
});

const cvssColor = computed(() => {
  const s = incident.value?.event_metadata?.cvss_score ?? 0;
  if (s >= 9) return '#d03050';
  if (s >= 7) return '#f0a020';
  if (s >= 4) return '#2080f0';
  return '#18a058';
});

const targetForSearch = computed(() => {
  const a = incident.value?.asset_detail;
  return a?.domain_ip || a?.site_ip || a?.asset_name || '';
});

const showAuditModal = ref(false);
const auditForm = ref({ passed: true, opinion: '' });
const showRemModal = ref(false);
const remForm = ref({ plan: '', result: '' });

async function fetchData() {
  loading.value = true;
  try {
    const id = route.params.id as string;
    incident.value = await getIncidentDetail(id) as any;

    try {
      const r = await getOplogList({ incident_id: id });
      oplogs.value = (r as any).items ?? [];
    } catch { oplogs.value = []; }

    try {
      const r = await getCommentList({ incident_id: id });
      comments.value = (r as any).items ?? [];
    } catch { comments.value = []; }

    try {
      knowledgeRecs.value = await getKnowledgeRecommend({ incident_id: id }) as any[];
    } catch { knowledgeRecs.value = []; }

    const kw = targetForSearch.value;
    if (kw) {
      try {
        const r = await getVulnList({ keyword: kw, page_size: 8 }) as any;
        relatedVulns.value = r?.items ?? [];
      } catch { relatedVulns.value = []; }
    }
  } finally {
    loading.value = false;
  }
}

async function handleAiAudit() {
  try { await aiPreAudit(route.params.id as string); message.success('预审完成'); await fetchData(); }
  catch (e: any) { message.error(e?.message || '预审失败'); }
}

async function handleManualAudit() {
  try { await manualAudit(route.params.id as string, auditForm.value); message.success('复核完成'); showAuditModal.value = false; await fetchData(); }
  catch (e: any) { message.error(e?.message || '复核失败'); }
}

async function handleRemediation() {
  try { await submitRemediation(route.params.id as string, remForm.value); message.success('整改方案已提交'); showRemModal.value = false; await fetchData(); }
  catch (e: any) { message.error(e?.message || '提交失败'); }
}

async function handleVerify() {
  try { await verifyRemediation(route.params.id as string, { passed: true }); message.success('整改验证通过'); await fetchData(); }
  catch (e: any) { message.error(e?.message || '验证失败'); }
}

async function handleClose() {
  try { await closeIncident(route.params.id as string); message.success('事件已关闭'); await fetchData(); }
  catch (e: any) { message.error(e?.message || '关闭失败'); }
}

const transferring = ref(false);
async function handleTransferToCircular() {
  if (!incident.value) return;
  const inc = incident.value;
  transferring.value = true;
  try {
    const payload: any = {
      incident_no: inc.incident_no,
      name: inc.name,
      level: inc.level,
      ai_opinion: inc.ai_opinion ?? '',
      ai_confidence: inc.ai_confidence ?? 0,
      source_system: 'incident',
    };
    if (inc.asset_detail) {
      payload.asset_info = {
        asset_name: inc.asset_detail.asset_name,
        system_name: inc.asset_detail.system_name,
        domain_ip: inc.asset_detail.domain_ip,
        site_ip: inc.asset_detail.site_ip,
        unit: inc.asset_detail.unit,
        unit_type: inc.asset_detail.unit_type,
        industry: inc.asset_detail.industry,
        mlps_record_no: inc.asset_detail.mlps_record_no,
        mlps_level: inc.asset_detail.mlps_level,
        region: inc.asset_detail.region,
      };
    }
    if (inc.event_metadata) {
      payload.metadata_info = {
        data_no: inc.event_metadata.data_no,
        incident_type: inc.event_metadata.incident_type,
        incident_url: inc.event_metadata.incident_url,
        incident_description: inc.event_metadata.incident_description,
        cvss_score: inc.event_metadata.cvss_score,
        cve_id: inc.event_metadata.cve_id,
      };
    }
    const result = await transferToCircular(payload);
    message.success('已成功流转为通报');
    router.push(`/circular/input/${(result as any).circular_code ?? (result as any).data?.circular_code}`);
  } catch (e: any) {
    message.error(e?.message || '流转失败');
  } finally {
    transferring.value = false;
  }
}

async function handleAddComment() {
  if (!newComment.value.trim()) return;
  try { await createComment({ incident_id: route.params.id as string, content: newComment.value }); newComment.value = ''; message.success('评论已添加'); await fetchData(); }
  catch (e: any) { message.error(e?.message || '添加失败'); }
}

async function handleDeleteComment(id: string) {
  try { await deleteComment(id); message.success('已删除'); await fetchData(); }
  catch (e: any) { message.error(e?.message || '删除失败'); }
}

function formatTime(t?: string) {
  if (!t) return '-';
  try { return new Date(t).toLocaleString('zh-CN'); }
  catch { return t; }
}

function formatDate(t?: string) {
  if (!t) return '-';
  try { return new Date(t).toLocaleDateString('zh-CN'); }
  catch { return t; }
}

function goVulnDetail(id: string) {
  router.push(`/scan/vulns/${id}`);
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px;max-width:1100px;margin:0 auto">
    <NSpin :show="loading">
      <template v-if="incident">
        <!-- 头部 -->
        <NCard size="small" style="margin-bottom:16px">
          <template #header>
            <NSpace align="center" :size="12">
              <NButton text @click="router.back()">返回</NButton>
              <span style="font-size:16px;font-weight:600">{{ incident.name }}</span>
              <span
                :style="{padding:'2px 8px',borderRadius:'4px',fontSize:'12px',fontWeight:'600',color:'#fff',background:levelColors[incident.level]??'#999'}"
              >{{ levelLabels[incident.level] ?? '-' }}</span>
              <NTag :type="(statusTypes[incident.status]||'default') as any" size="small" :bordered="false">
                {{ statusLabels[incident.status] ?? '-' }}
              </NTag>
              <NTag v-if="incident.source" size="small" :bordered="false" type="info">
                {{ sourceLabels[incident.source] ?? incident.source }}
              </NTag>
            </NSpace>
          </template>
          <template #header-extra>
            <NSpace :size="8">
              <NButton v-if="incident.status<=2" size="small" type="info" @click="handleAiAudit">智能预审</NButton>
              <NButton v-if="incident.status===2" size="small" type="primary" @click="showAuditModal=true">人工复核</NButton>
              <NButton v-if="incident.status===4||incident.status===6" size="small" type="warning" @click="showRemModal=true">提交整改</NButton>
              <NButton v-if="incident.status===6" size="small" type="success" @click="handleVerify">验证整改</NButton>
              <NButton v-if="incident.status===4||incident.status===5||incident.status===6" size="small" @click="handleClose">关闭事件</NButton>
              <NButton size="small" type="error" :loading="transferring" @click="handleTransferToCircular">转为通报</NButton>
            </NSpace>
          </template>
          <NSteps
            :current="currentStep"
            size="small"
            :status="incident.status===3?'error':'process'"
            style="margin-bottom:20px"
          >
            <NStep v-for="t in stepTitles" :key="t" :title="t" />
          </NSteps>
        </NCard>

        <!-- Tab -->
        <NTabs type="line" animated>

          <!-- 事件概况 -->
          <NTabPane name="overview" tab="事件概况">
            <NGrid :cols="2" :x-gap="16" :y-gap="16" responsive="screen">
              <!-- 事件信息 -->
              <NGridItem span="2">
                <NCard title="事件信息" size="small">
                  <NDescriptions label-placement="left" bordered :column="2" size="small">
                    <NDescriptionsItem label="事件编号">{{ incident.incident_no }}</NDescriptionsItem>
                    <NDescriptionsItem label="当前状态">
                      <NTag :type="(statusTypes[incident.status]||'default') as any" size="small" :bordered="false">
                        {{ statusLabels[incident.status] ?? '-' }}
                      </NTag>
                    </NDescriptionsItem>
                    <NDescriptionsItem label="事件等级">
                      <span :style="{padding:'2px 8px',borderRadius:'4px',fontSize:'12px',fontWeight:'600',color:'#fff',background:levelColors[incident.level]??'#999'}">
                        {{ levelLabels[incident.level] ?? '-' }}
                      </span>
                    </NDescriptionsItem>
                    <NDescriptionsItem label="发现途径">
                      {{ sourceLabels[incident.source] ?? '-' }}
                    </NDescriptionsItem>
                    <NDescriptionsItem label="发现时间">{{ formatTime(incident.report_time) }}</NDescriptionsItem>
                    <NDescriptionsItem label="创建时间">{{ formatTime(incident.created_at) }}</NDescriptionsItem>
                    <NDescriptionsItem
                      v-if="incident.event_metadata?.incident_type"
                      label="事件类型"
                    >{{ incident.event_metadata.incident_type }}</NDescriptionsItem>
                    <NDescriptionsItem
                      v-if="incident.event_metadata?.incident_url"
                      label="隐患地址"
                      :span="2"
                    ><span style="word-break:break-all;font-family:monospace;font-size:12px">{{ incident.event_metadata.incident_url }}</span></NDescriptionsItem>
                  </NDescriptions>
                </NCard>
              </NGridItem>

              <!-- 涉事资产 -->
              <NGridItem v-if="incident.asset_detail" span="2 m:1">
                <NCard title="涉事资产" size="small">
                  <NDescriptions label-placement="left" bordered :column="1" size="small">
                    <NDescriptionsItem label="资产名称">{{ incident.asset_detail.asset_name || '-' }}</NDescriptionsItem>
                    <NDescriptionsItem label="系统名称">{{ incident.asset_detail.system_name || '-' }}</NDescriptionsItem>
                    <NDescriptionsItem label="地址">{{ incident.asset_detail.domain_ip || '-' }}</NDescriptionsItem>
                    <NDescriptionsItem label="IP">{{ incident.asset_detail.site_ip || '-' }}</NDescriptionsItem>
                    <NDescriptionsItem label="所属单位">{{ incident.asset_detail.unit || '-' }}</NDescriptionsItem>
                    <NDescriptionsItem label="单位类型">{{ incident.asset_detail.unit_type || '-' }}</NDescriptionsItem>
                    <NDescriptionsItem label="行业">{{ incident.asset_detail.industry || '-' }}</NDescriptionsItem>
                    <NDescriptionsItem label="归属地">{{ incident.asset_detail.region || '-' }}</NDescriptionsItem>
                    <NDescriptionsItem label="等保等级">{{ incident.asset_detail.mlps_level || '-' }}</NDescriptionsItem>
                    <NDescriptionsItem label="等保备案号">{{ incident.asset_detail.mlps_record_no || '-' }}</NDescriptionsItem>
                    <NDescriptionsItem label="工信部备案">{{ incident.asset_detail.miit_record_no || '-' }}</NDescriptionsItem>
                  </NDescriptions>
                </NCard>
              </NGridItem>

              <!-- 漏洞技术详情 -->
              <NGridItem v-if="incident.event_metadata" span="2 m:1">
                <NCard title="漏洞详情" size="small">
                  <NDescriptions label-placement="left" bordered :column="1" size="small">
                    <NDescriptionsItem v-if="incident.event_metadata.cve_id" label="CVE 编号">
                      <NTag size="small" type="error" :bordered="false">{{ incident.event_metadata.cve_id }}</NTag>
                    </NDescriptionsItem>
                    <NDescriptionsItem v-if="incident.event_metadata.cvss_score>0" label="CVSS 评分">
                      <span :style="{fontSize:'18px',fontWeight:'700',color:cvssColor}">
                        {{ incident.event_metadata.cvss_score.toFixed(1) }}
                      </span>
                    </NDescriptionsItem>
                    <NDescriptionsItem v-if="incident.event_metadata.owasp_category" label="OWASP 分类">
                      {{ incident.event_metadata.owasp_category }}
                    </NDescriptionsItem>
                    <NDescriptionsItem v-if="incident.event_metadata.exploit_difficulty" label="利用难度">
                      {{ incident.event_metadata.exploit_difficulty }}
                    </NDescriptionsItem>
                    <NDescriptionsItem v-if="incident.event_metadata.affect_scope" label="影响范围">
                      {{ incident.event_metadata.affect_scope }}
                    </NDescriptionsItem>
                  </NDescriptions>
                </NCard>
              </NGridItem>
            </NGrid>

            <!-- 事件描述 -->
            <NCard
              v-if="incident.event_metadata?.incident_description"
              title="事件描述"
              size="small"
              style="margin-top:16px"
            >
              <div style="line-height:1.8;font-size:13px;white-space:pre-wrap">
                {{ incident.event_metadata.incident_description }}
              </div>
              <NSpace v-if="incident.event_metadata?.vendor_name" :size="24" style="margin-top:12px">
                <span style="font-size:12px;color:#999">
                  上报方: {{ incident.event_metadata.vendor_name }}
                </span>
                <span
                  v-if="incident.event_metadata.vendor_time"
                  style="font-size:12px;color:#999"
                >
                  上报时间: {{ formatTime(incident.event_metadata.vendor_time) }}
                </span>
              </NSpace>
            </NCard>

            <!-- 关联漏洞 -->
            <NCard
              v-if="relatedVulns.length"
              title="关联漏洞 ({{ relatedVulns.length }})"
              size="small"
              style="margin-top:16px"
            >
              <div style="display:flex;flex-direction:column;gap:8px">
                <div
                  v-for="v in relatedVulns.slice(0, 6)"
                  :key="v.id"
                  style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:#f8f8fa;border-radius:6px;cursor:pointer"
                  @click="goVulnDetail(v.id)"
                >
                  <div style="flex:1;min-width:0">
                    <div style="font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                      {{ v.title }}
                    </div>
                    <div style="font-size:11px;color:#999;margin-top:2px">
                      {{ v.target }}{{ v.port ? ':' + v.port : '' }}
                      <span v-if="v.task_id" style="margin-left:8px">· 任务 {{ v.task_id.slice(0,8) }}</span>
                    </div>
                  </div>
                  <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;margin-left:12px">
                    <span
                      :style="{padding:'1px 6px',borderRadius:3,fontSize:11,fontWeight:500,color:'#fff',background:vulnSeverityColors[v.severity]||'#999'}"
                    >{{ vulnSeverityLabels[v.severity] || v.severity }}</span>
                    <NTag size="tiny" :bordered="false">{{ v.status }}</NTag>
                  </div>
                </div>
              </div>
            </NCard>

            <!-- 历史同类事件 -->
            <NCard
              v-if="knowledgeRecs.length"
              title="历史同类事件"
              size="small"
              style="margin-top:16px"
            >
              <NSpace :size="8">
                <NTag
                  v-for="rec in knowledgeRecs"
                  :key="rec.id"
                  size="small"
                  type="info"
                  :bordered="false"
                >
                  {{ rec.title || rec.summary }}
                  <template v-if="rec.level">
                    <span
                      :style="{padding:'1px 4px',borderRadius:3,fontSize:10,color:'#fff',marginLeft:6,background:levelColors[rec.level]||'#999'}"
                    >{{ levelLabels[rec.level] }}</span>
                  </template>
                </NTag>
              </NSpace>
            </NCard>
          </NTabPane>

          <!-- 智能分析 -->
          <NTabPane name="analysis" tab="智能分析">
            <template v-if="incident.ai_pre_status===1">
              <NCard size="small" style="margin-bottom:12px">
                <NSpace :size="24">
                  <div>
                    <div style="font-size:12px;color:#999;margin-bottom:4px">置信度</div>
                    <NProgress
                      type="circle"
                      :percentage="Math.round((incident.ai_confidence??0)*100)"
                      :stroke-width="6"
                      style="width:80px"
                    />
                  </div>
                  <div>
                    <div style="font-size:12px;color:#999;margin-bottom:4px">风险评分</div>
                    <NProgress
                      type="line"
                      :percentage="incident.risk_score??0"
                      :indicator-placement="'inside'"
                      style="width:200px"
                    />
                  </div>
                  <div>
                    <div style="font-size:12px;color:#999;margin-bottom:4px">事件分类</div>
                    <NTag size="small" type="info">{{ incident.ai_category || '-' }}</NTag>
                  </div>
                </NSpace>
              </NCard>
              <NCard title="事件标签" size="small" style="margin-bottom:12px" v-if="eventTags.length">
                <NSpace :size="4">
                  <NTag v-for="t in eventTags" :key="t" size="small" :bordered="false">{{ t }}</NTag>
                </NSpace>
              </NCard>
              <NCard title="预审意见" size="small" v-if="incident.ai_opinion">
                <div style="line-height:1.8;font-size:13px;white-space:pre-wrap">{{ incident.ai_opinion }}</div>
              </NCard>
            </template>
            <NEmpty v-else description="暂未执行智能预审" />
          </NTabPane>

          <!-- 处置跟踪 -->
          <NTabPane name="remediation" tab="处置跟踪">
            <NCard title="整改记录" size="small" style="margin-bottom:16px">
              <template v-if="incident.remediation_plan||incident.remediation_result||incident.remediation_assignee">
                <NDescriptions label-placement="left" bordered :column="2" size="small">
                  <NDescriptionsItem label="整改方案" :span="2">{{ incident.remediation_plan || '-' }}</NDescriptionsItem>
                  <NDescriptionsItem label="整改结果" :span="2">{{ incident.remediation_result || '-' }}</NDescriptionsItem>
                  <NDescriptionsItem label="责任人">{{ incident.remediation_assignee || '-' }}</NDescriptionsItem>
                  <NDescriptionsItem label="截止日期">
                    <span
                      v-if="incident.remediation_deadline"
                      :style="new Date(incident.remediation_deadline)<new Date()?'color:#d03050;font-weight:600':''"
                    >{{ formatDate(incident.remediation_deadline) }}</span>
                    <span v-else>-</span>
                  </NDescriptionsItem>
                  <NDescriptionsItem label="提交时间">{{ formatTime(incident.remediation_submit_at) }}</NDescriptionsItem>
                  <NDescriptionsItem label="验证时间">{{ formatTime(incident.verified_at) }}</NDescriptionsItem>
                </NDescriptions>
              </template>
              <NEmpty v-else description="暂无整改记录" />
            </NCard>

            <NCard title="SLA 跟踪" size="small">
              <template v-if="incident.sla_level||incident.sla_deadline">
                <NDescriptions label-placement="left" bordered :column="2" size="small">
                  <NDescriptionsItem label="SLA 等级">
                    <NTag
                      size="small"
                      :type="(incident.sla_level ?? 0) >= 3 ? 'error' : (incident.sla_level ?? 0) >= 2 ? 'warning' : 'info'"
                      :bordered="false"
                    >{{ slaLevelLabels[incident.sla_level ?? 0] || `P${incident.sla_level}` }}</NTag>
                  </NDescriptionsItem>
                  <NDescriptionsItem label="响应期限">
                    <span :style="isOverdue?'color:#d03050;font-weight:600':''">
                      {{ formatTime(incident.sla_deadline) }}
                    </span>
                    <NTag
                      v-if="isOverdue"
                      size="tiny"
                      type="error"
                      :bordered="false"
                      style="margin-left:8px"
                    >已超期</NTag>
                  </NDescriptionsItem>
                  <NDescriptionsItem label="催办次数">{{ incident.sla_reminder_count ?? 0 }}</NDescriptionsItem>
                  <NDescriptionsItem label="最近催办">{{ formatTime(incident.sla_last_reminder) }}</NDescriptionsItem>
                  <NDescriptionsItem v-if="incident.sla_escalated_to" label="已升级通知" :span="2">
                    {{ incident.sla_escalated_to }}
                    <span style="font-size:12px;color:#999;margin-left:8px">
                      (升级时间: {{ formatTime(incident.sla_escalated_at) }})
                    </span>
                  </NDescriptionsItem>
                </NDescriptions>
                <NAlert
                  v-if="isOverdue&&incident.status!==7"
                  type="error"
                  :bordered="false"
                  style="margin-top:12px"
                >
                  该事件已超过 SLA 响应期限，请尽快处理。
                </NAlert>
              </template>
              <NEmpty v-else description="未配置 SLA" />
            </NCard>
          </NTabPane>

          <!-- 评论 -->
          <NTabPane name="comments" tab="评论">
            <NSpace vertical :size="12">
              <NSpace :size="8">
                <NInput
                  v-model:value="newComment"
                  placeholder="输入评论..."
                  style="width:400px"
                  @keyup.enter="handleAddComment"
                />
                <NButton type="primary" size="small" @click="handleAddComment">发送</NButton>
              </NSpace>
              <div
                v-for="c in comments"
                :key="c.id"
                style="padding:8px 12px;background:#f8f8fa;border-radius:6px"
              >
                <div style="font-size:12px;color:#999;margin-bottom:4px">
                  {{ c.author_name || c.author || '-' }} · {{ formatTime(c.created_at) }}
                </div>
                <div style="font-size:13px;white-space:pre-wrap">{{ c.content }}</div>
                <NButton text type="error" size="tiny" @click="handleDeleteComment(c.id)" style="margin-top:4px">
                  删除
                </NButton>
              </div>
              <NEmpty v-if="!comments.length" description="暂无评论" />
            </NSpace>
          </NTabPane>

          <!-- 操作日志 -->
          <NTabPane name="oplogs" tab="操作日志">
            <NTimeline v-if="oplogs.length">
              <NTimelineItem
                v-for="log in oplogs"
                :key="log.id"
                :title="log.operation_type_zh || log.operation_type"
                :time="formatTime(log.operation_time)"
                type="info"
              >
                <div style="font-size:12px;color:#666">
                  操作人: {{ log.operator_name || log.operator_id || '-' }}
                </div>
                <div v-if="log.result" style="font-size:12px;color:#666;margin-top:2px">
                  结果: {{ log.result }}
                </div>
                <div
                  v-if="log.detail"
                  style="font-size:12px;color:#999;margin-top:2px;white-space:pre-wrap"
                >{{ log.detail }}</div>
              </NTimelineItem>
            </NTimeline>
            <NEmpty v-else description="暂无操作记录" />
          </NTabPane>
        </NTabs>

        <!-- 弹窗 -->
        <NModal
          v-model:show="showAuditModal"
          preset="dialog"
          title="人工复核"
          positive-text="确认"
          negative-text="取消"
          @positive-click="handleManualAudit"
        >
          <NForm label-placement="left" label-width="80">
            <NFormItem label="审核结果">
              <NRadioGroup v-model:value="auditForm.passed">
                <NRadio :value="true">通过</NRadio>
                <NRadio :value="false">不通过</NRadio>
              </NRadioGroup>
            </NFormItem>
            <NFormItem label="审核意见">
              <NInput v-model:value="auditForm.opinion" type="textarea" :rows="3" />
            </NFormItem>
          </NForm>
        </NModal>

        <NModal
          v-model:show="showRemModal"
          preset="dialog"
          title="提交整改"
          positive-text="提交"
          negative-text="取消"
          @positive-click="handleRemediation"
        >
          <NForm label-placement="left" label-width="80">
            <NFormItem label="整改方案">
              <NInput v-model:value="remForm.plan" type="textarea" :rows="3" />
            </NFormItem>
            <NFormItem label="整改结果">
              <NInput v-model:value="remForm.result" type="textarea" :rows="3" />
            </NFormItem>
          </NForm>
        </NModal>
      </template>
    </NSpin>
  </div>
</template>
