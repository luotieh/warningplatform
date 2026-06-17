<script lang="ts" setup>
import { computed, ref, watch } from 'vue';
import {
  NButton,
  NDrawer,
  NDrawerContent,
  NSpace,
  NSpin,
  useMessage,
} from 'naive-ui';

import { previewIncidentReport, type IncidentReportData } from '#/api/incident';
import { downloadOneIncidentExport } from '../incident-export';

const props = defineProps<{
  incidentId: string;
  show: boolean;
}>();

const emit = defineEmits<{
  'update:show': [value: boolean];
}>();

const message = useMessage();
const loading = ref(false);
const exporting = ref(false);
const report = ref<IncidentReportData | null>(null);

function dash(v?: string) {
  return v?.trim() ? v : '-';
}

interface EvidenceGroup {
  title: string;
  items: Array<{ key: string; value: string }>;
}

function parseEvidenceText(text: string): EvidenceGroup[] | null {
  if (!text?.trim()) return null;
  const lines = text.split('\n');
  const groups: EvidenceGroup[] = [];
  let current: EvidenceGroup | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const sectionMatch = trimmed.match(/^(.+?)：$/);
    if (sectionMatch && !trimmed.includes('  ')) {
      current = { title: sectionMatch[1]!, items: [] };
      groups.push(current);
      continue;
    }

    const kvMatch = trimmed.match(/^\s*(.+?)[:：]\s*(.+)$/);
    if (kvMatch) {
      let val = kvMatch[2]!.trim();
      try {
        const parsed = JSON.parse(val);
        if (typeof parsed === 'object' && parsed !== null) {
          val = JSON.stringify(parsed, null, 2);
        }
      } catch { /* not JSON, keep as-is */ }
      const item = { key: kvMatch[1]!.trim(), value: val };
      if (current) {
        current.items.push(item);
      } else {
        current = { title: '基本信息', items: [item] };
        groups.push(current);
      }
      continue;
    }

    if (current) {
      current.items.push({ key: '', value: trimmed });
    }
  }
  return groups.length > 0 ? groups : null;
}

const detailGroups = computed(() => {
  const detail = report.value?.description_sections?.detail;
  if (!detail?.trim()) return null;
  return parseEvidenceText(detail);
});

async function loadPreview() {
  if (!props.incidentId) return;
  loading.value = true;
  try {
    report.value = await previewIncidentReport(props.incidentId);
  } catch (e: any) {
    message.error(e?.message || '加载报告预览失败');
    report.value = null;
  } finally {
    loading.value = false;
  }
}

async function handleDownload(format: 'word' | 'docx' | 'pdf') {
  if (!props.incidentId) return;
  exporting.value = true;
  try {
    await downloadOneIncidentExport(
      props.incidentId,
      format,
      report.value?.incident_no,
      report.value,
    );
    message.success('报告已下载');
  } catch (e: any) {
    message.error(e?.message || '导出失败');
  } finally {
    exporting.value = false;
  }
}

watch(
  () => [props.show, props.incidentId],
  ([visible]) => {
    if (visible) loadPreview();
  },
);
</script>

<template>
  <NDrawer
    :show="show"
    :width="920"
    placement="right"
    @update:show="emit('update:show', $event)"
  >
    <NDrawerContent title="网络安全隐患详情" closable>
      <template #header-extra>
        <NSpace>
          <NButton size="small" :loading="exporting" @click="handleDownload('docx')">
            导出 Word
          </NButton>
          <NButton size="small" type="primary" :loading="exporting" @click="handleDownload('pdf')">
            导出 PDF
          </NButton>
        </NSpace>
      </template>

      <NSpin :show="loading">
        <template v-if="report">
          <div class="hazard-doc">
            <h1 class="hazard-doc__title">网络安全隐患详情</h1>
            <table class="hazard-table">
              <tbody>
                <tr>
                  <th>隐患编号</th><td>{{ dash(report.incident_no) }}</td>
                  <th>数据编号</th><td>{{ dash(report.data_no) }}</td>
                </tr>
                <tr>
                  <th>隐患名称</th><td colspan="3">{{ dash(report.name || report.title) }}</td>
                </tr>
                <tr>
                  <th>厂商上报归属地</th><td colspan="3">{{ dash(report.vendor_region) }}</td>
                </tr>
                <tr>
                  <th>隐患URL</th><td colspan="3" class="break-all">{{ dash(report.incident_url) }}</td>
                </tr>
                <tr>
                  <th>网站名称</th><td>{{ dash(report.asset_name) }}</td>
                  <th>网站域名IP</th><td>{{ dash(report.domain_ip) }}</td>
                </tr>
                <tr>
                  <th>网站IP</th><td>{{ dash(report.site_ip) }}</td>
                  <th>归属地</th><td>{{ dash(report.region) }}</td>
                </tr>
                <tr>
                  <th>隐患类型</th><td>{{ dash(report.incident_type) }}</td>
                  <th>预警级别</th><td>{{ dash(report.warning_level) }}</td>
                </tr>
                <tr>
                  <th>隐患级别</th><td>{{ dash(report.level) }}</td>
                  <th>发现时间</th><td>{{ dash(report.discovery_time) }}</td>
                </tr>
                <tr>
                  <th>上报厂商</th><td>{{ dash(report.vendor_name) }}</td>
                  <th>厂商上报时间</th><td>{{ dash(report.vendor_time) }}</td>
                </tr>
                <tr>
                  <th>涉及信息数量</th><td>{{ dash(report.affected_count) }}</td>
                  <th>涉及信息类型</th><td>{{ dash(report.affected_type) }}</td>
                </tr>
                <tr>
                  <th>隶属单位</th><td>{{ dash(report.unit) }}</td>
                  <th>单位类型</th><td>{{ dash(report.unit_type) }}</td>
                </tr>
                <tr>
                  <th>所属行业</th><td>{{ dash(report.industry) }}</td>
                  <th>工信部备案号</th><td>{{ dash(report.miit_record_no) }}</td>
                </tr>
                <tr>
                  <th>等保级别</th><td>{{ dash(report.mlps_level) }}</td>
                  <th>等保备案号</th><td>{{ dash(report.mlps_record_no) }}</td>
                </tr>
                <tr>
                  <th>隐患描述</th>
                  <td colspan="3" class="hazard-desc">
                    <template v-if="report.description_sections?.has_sections">
                      <div
                        v-if="report.description_sections.cause"
                        class="desc-section"
                      >
                        <div class="desc-section__title">一、事件成因</div>
                        <pre>{{ report.description_sections.cause }}</pre>
                      </div>
                      <div
                        v-if="report.description_sections.evidence"
                        class="desc-section"
                      >
                        <div class="desc-section__title">二、证据详情</div>
                        <pre>{{ report.description_sections.evidence }}</pre>
                      </div>
                      <div
                        v-if="report.description_sections.detail"
                        class="desc-section"
                      >
                        <div class="desc-section__title">三、详细证据</div>
                        <template v-if="detailGroups">
                          <div
                            v-for="(group, gi) in detailGroups"
                            :key="gi"
                            class="evidence-group"
                          >
                            <div class="evidence-group__title">{{ group.title }}</div>
                            <table class="evidence-kv-table">
                              <tbody>
                                <tr
                                  v-for="(item, ii) in group.items"
                                  :key="ii"
                                >
                                  <td v-if="item.key" class="evidence-kv-key">{{ item.key }}</td>
                                  <td :colspan="item.key ? 1 : 2" class="evidence-kv-val">
                                    <pre v-if="item.value.includes('\n')" class="evidence-json">{{ item.value }}</pre>
                                    <span v-else>{{ item.value }}</span>
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                          </div>
                        </template>
                        <pre v-else>{{ report.description_sections.detail }}</pre>
                      </div>
                      <div
                        v-if="report.description_sections.trace"
                        class="desc-section"
                      >
                        <div class="desc-section__title">四、溯源信息</div>
                        <pre>{{ report.description_sections.trace }}</pre>
                      </div>
                    </template>
                    <pre v-else>{{ dash(report.description) }}</pre>
                    <div
                      v-if="report.evidence_images?.length"
                      class="evidence-gallery"
                    >
                      <div
                        v-for="(img, idx) in report.evidence_images"
                        :key="idx"
                        class="evidence-gallery__item"
                      >
                        <img
                          :src="`data:${img.mime_type};base64,${img.base64}`"
                          :alt="img.caption"
                        />
                        <div class="evidence-gallery__caption">{{ img.caption }}</div>
                      </div>
                    </div>
                  </td>
                </tr>
                <tr v-if="report.remediation_plan || report.remediation_advice">
                  <th>整改建议</th>
                  <td colspan="3" class="hazard-desc">
                    <pre v-if="report.remediation_plan">{{ report.remediation_plan }}</pre>
                    <pre v-if="report.remediation_advice">{{ report.remediation_advice }}</pre>
                  </td>
                </tr>
                <tr v-if="report.attachment">
                  <th>证据附件</th>
                  <td colspan="3" class="hazard-attach">{{ dash(report.attachment) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
      </NSpin>
    </NDrawerContent>
  </NDrawer>
</template>

<style scoped>
.hazard-doc {
  padding: 8px 4px 24px;
}
.hazard-doc__title {
  text-align: center;
  font-size: 20px;
  font-weight: 700;
  letter-spacing: 2px;
  margin: 0 0 16px;
}
.hazard-table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
  font-size: 13px;
}
.hazard-table th,
.hazard-table td {
  border: 1px solid #333;
  padding: 8px 10px;
  vertical-align: top;
}
.hazard-table th {
  width: 14%;
  text-align: center;
  font-weight: 500;
  background: #fafafa;
}
.hazard-desc {
  line-height: 1.5;
}
.hazard-desc pre {
  margin: 0 0 8px;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: inherit;
  font-size: 13px;
}
.desc-section {
  margin-bottom: 12px;
}
.desc-section__title {
  font-weight: 600;
  margin-bottom: 4px;
}
.evidence-gallery {
  margin-top: 12px;
}
.evidence-gallery__item {
  margin-bottom: 16px;
  text-align: center;
}
.evidence-gallery__item img {
  max-width: 100%;
  border: 1px solid #ddd;
}
.evidence-gallery__caption {
  font-size: 12px;
  color: #666;
  margin-top: 4px;
}
.hazard-attach {
  color: #2080f0;
}
.break-all {
  word-break: break-all;
}
.evidence-group {
  margin-bottom: 12px;
}
.evidence-group__title {
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 4px;
  padding: 4px 8px;
  background: #f0f5ff;
  border-left: 3px solid #2080f0;
}
.evidence-kv-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  margin-bottom: 8px;
}
.evidence-kv-table td {
  padding: 4px 8px;
  border-bottom: 1px solid #f0f0f0;
  vertical-align: top;
}
.evidence-kv-key {
  width: 30%;
  color: #666;
  font-weight: 500;
  word-break: break-all;
}
.evidence-kv-val {
  color: #333;
  word-break: break-all;
}
.evidence-json {
  margin: 0;
  padding: 6px 8px;
  background: #f9f9f9;
  border: 1px solid #eee;
  border-radius: 4px;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 200px;
  overflow-y: auto;
}
</style>
