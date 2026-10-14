<script setup lang="ts">
import { computed, ref } from 'vue';
import { markdownToHtml } from '#/utils/markdown';
import EvidenceDialog from './EvidenceDialog.vue';
const props = defineProps<{ document?: Record<string, any> | null; legacyMarkdown?: string; eventId: string }>();
const html = computed(() => markdownToHtml(props.document?.markdown || props.legacyMarkdown || ''));
const evidence = computed(() => props.document?.evidence || {});
const factRows = computed(() => evidence.value.fact_checks?.length ? evidence.value.fact_checks : evidence.value.fact_coverage || []);
const sourceDialogVisible = ref(false);
const sourceHitId = ref('');
const selectedRows = computed(() => (evidence.value.entries || []).filter((entry: Record<string, any>) => evidence.value.selected_ids?.includes(entry.id)));
function savedHitIds(entry: Record<string, any>): string[] { return (entry.source_ids || []).filter((id: string) => /^hit-[a-f0-9]{64}$/.test(id)); }
function openSource(hitId: string) { sourceHitId.value = hitId; sourceDialogVisible.value = true; }
const statuses: Record<string, string> = { observed: '成立', not_observed: '当前范围未满足', missing: '材料不足', accepted: '引用校验通过', skipped: '未执行', unavailable: '不可用', rejected: '结果拒绝' };
</script>

<template>
  <article class="evidence-report">
    <div v-if="document" class="report-version">报告版本 {{ document.analysis_version }} · 快照版本 {{ evidence.snapshot_version }} · 依据及引用已校验</div>
    <div v-else-if="legacyMarkdown" class="legacy-note">历史报告：没有绑定新版结构化证据清单，保留原报告内容。</div>
    <div class="report-content" v-html="html"></div>
    <template v-if="!['five-part-v1', 'five-part-v2'].includes(document?.layout_version)">
    <details v-if="evidence.normalized_evidence?.items" class="audit">
      <summary>查看统一证据索引（事实、语义及全部执行状态）</summary>
      <p>共 {{ evidence.normalized_evidence.items.length }} 个证据实例；正文采用 {{ evidence.selected_ids?.length || 0 }} 项精华。省略的结果与来源仍完整保存。</p>
      <div class="audit-table"><table><thead><tr><th>规则 / 槽位</th><th>状态 / 质量</th><th>证据性质</th><th>正文引用</th><th>结果 / 原因</th><th>来源</th></tr></thead><tbody>
        <tr v-for="row in evidence.normalized_evidence.items" :key="row.id"><td>{{ row.rule_id }}</td><td>{{ statuses[row.status] || row.status }} / {{ row.quality }}</td><td>{{ row.role }}</td><td>{{ row.report_id || '附录' }}</td><td>{{ row.interpretation || row.measurements?.values || row.reason }}</td><td>{{ row.source_ids?.join('、') }}</td></tr>
      </tbody></table></div>
    </details>
    <details v-if="document" class="audit"><summary>查看正文证据的原始来源与核验范围</summary>
      <div v-for="entry in selectedRows" :key="entry.id" class="source-entry">
        <strong>{{ entry.id }} · {{ entry.name }}</strong>
        <p v-if="entry.scope?.asset_id">资产 {{ entry.scope.asset_id }}；端点 {{ entry.scope.endpoint_id }}</p>
        <p v-if="entry.window">核验窗口 {{ entry.window.start }} 至 {{ entry.window.end }}</p>
        <button v-for="(hitId, index) in savedHitIds(entry).slice(0, 8)" :key="hitId" @click="openSource(hitId)">查看原始命中 {{ index + 1 }}</button>
        <p v-if="savedHitIds(entry).length > 8">共 {{ savedHitIds(entry).length }} 条来源，展示前8条定位入口。</p>
      </div>
    </details>
    <details v-if="evidence.platform_history" class="audit"><summary>查看平台历史活动（关联不等于同战役或恶意结论）</summary>
      <p>检索状态：{{ evidence.platform_history.status }}；{{ evidence.platform_history.reason }}</p>
      <div class="audit-table"><table><thead><tr><th>历史事件</th><th>活动时间</th><th>匹配关系</th><th>资产 / IOC</th></tr></thead><tbody>
        <tr v-for="row in evidence.platform_history.rows || []" :key="row.event_id"><td>{{ row.event_id }}</td><td>{{ row.first_time }} 至 {{ row.last_time }}</td><td>{{ ({ same_asset_ioc: '同资产且同IOC', same_ioc: '仅同IOC', same_asset: '仅同资产' } as Record<string,string>)[row.relation] }}</td><td>{{ row.all_asset_ids?.join('、') }} / {{ row.activity_iocs?.map((ioc: Record<string, any>) => ioc.value).join('、') }}</td></tr>
      </tbody></table></div>
    </details>
    <details v-if="document" class="audit">
      <summary>查看完整事实与语义检查清单（正文省略不等于未执行）</summary>
      <div class="audit-table">
        <table><thead><tr><th>事实规则</th><th>资产 / 端点</th><th>核验状态</th><th>原因</th></tr></thead>
          <tbody><tr v-for="(fact, index) in factRows" :key="index"><td>{{ fact.fact_id }}</td><td>{{ fact.scope?.asset_id }} / {{ fact.scope?.endpoint_id }}</td><td>{{ statuses[fact.status] || fact.status }}</td><td>{{ fact.reason_code }}</td></tr></tbody>
        </table>
        <table><thead><tr><th>语义槽位</th><th>命题</th><th>执行状态</th><th>原因</th></tr></thead>
          <tbody><tr v-for="(task, index) in evidence.semantic_checks || []" :key="index"><td>{{ task.slot?.id }} / {{ task.slot?.target }}</td><td>{{ task.subject_id }}</td><td>{{ statuses[task.status] || task.status }}</td><td>{{ task.reason }}</td></tr></tbody>
        </table>
      </div>
    </details>
    </template>
  </article>
  <EvidenceDialog v-model:visible="sourceDialogVisible" :event-id="eventId" :hit-id="sourceHitId" :version="Number(evidence.snapshot_version || 0)" />
</template>

<style scoped>
.evidence-report { padding: 24px 28px; line-height: 1.8; background: hsl(var(--card)); color: hsl(var(--foreground)); }
.report-version, .legacy-note { margin-bottom: 18px; padding: 10px 14px; background: hsl(var(--muted)); border-radius: 6px; font-size: 13px; }
.report-content :deep(h2) { margin: 28px 0 12px; padding-bottom: 8px; border-bottom: 1px solid hsl(var(--border)); font-size: 19px; }
.report-content :deep(h3) { margin: 20px 0 8px; font-size: 16px; }
.report-content :deep(p) { margin: 10px 0; }
.report-content :deep(table), .audit table { width: 100%; border-collapse: collapse; font-size: 13px; margin: 16px 0; }
.report-content :deep(th), .report-content :deep(td), .audit th, .audit td { border: 1px solid hsl(var(--border)); padding: 10px 12px; vertical-align: top; text-align: left; overflow-wrap: anywhere; }
.report-content :deep(th), .audit th { background: hsl(var(--muted)); font-weight: 600; }
.report-content :deep(li) { margin: 8px 0; }
.audit { margin-top: 24px; border-top: 1px solid hsl(var(--border)); padding-top: 16px; }
.audit summary { cursor: pointer; font-weight: 600; }
.audit-table { overflow-x: auto; }
.source-entry { padding: 12px 0; border-bottom: 1px solid hsl(var(--border)); }
.source-entry button { margin: 6px 8px 0 0; padding: 4px 8px; border: 1px solid hsl(var(--border)); border-radius: 4px; }
@media (max-width: 768px) { .evidence-report { padding: 16px; } .report-content { overflow-x: auto; } }
</style>
