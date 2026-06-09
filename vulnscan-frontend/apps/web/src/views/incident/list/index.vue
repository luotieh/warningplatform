<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';
import type { DataTableRowKey } from 'naive-ui';

import {
  NButton, NCard, NDataTable, NDropdown, NInput, NSelect, NSpace, NTag, NPopconfirm,
  NModal, NForm, NFormItem, NDatePicker, NInputNumber, NTabs, NTabPane,
  useMessage,
} from 'naive-ui';
import { useRouter } from 'vue-router';
import {
  getIncidentList, deleteIncident, aiPreAudit, createIncident,
  transferToCircular,
  type SecurityIncident, type CreateIncidentReq,
} from '#/api/incident';
import {
  downloadBatchIncidentExport,
  downloadOneIncidentExport,
  type IncidentExportFormat,
} from '../incident-export';
import IncidentPreviewDrawer from '../components/IncidentPreviewDrawer.vue';
import { useRoutePerm } from '#/composables/use-route-perm';

defineOptions({ name: 'IncidentList' });

const { perm } = useRoutePerm('/incident/list');

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const data = ref<SecurityIncident[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const statusFilter = ref<number | null>(null);
const levelFilter = ref<number | null>(null);
const showCreate = ref(false);
const checkedRowKeys = ref<DataTableRowKey[]>([]);
const exporting = ref(false);
const showPreview = ref(false);
const previewId = ref<string | null>(null);

function openPreview(row: SecurityIncident) {
  previewId.value = row.id;
  showPreview.value = true;
}

const defaultForm = (): CreateIncidentReq => ({
  name: '',
  level: 3,
  source: 1,
  report_time: undefined,
  asset: {},
  metadata: {},
});
const createForm = ref<CreateIncidentReq>(defaultForm());

const statusLabels: Record<number, string> = { 1: '待人工复核', 2: '复核通过', 3: '复核失败', 4: '待整改', 5: '整改中', 6: '待验证', 7: '已关闭' };
const statusTypes: Record<number, string> = { 1: 'default', 2: 'success', 3: 'error', 4: 'warning', 5: 'info', 6: 'warning', 7: 'default' };
const levelLabels: Record<number, string> = { 1: '低', 2: '中', 3: '高', 4: '紧急' };
const levelColors: Record<number, string> = { 1: '#18a058', 2: '#2080f0', 3: '#f0a020', 4: '#d03050' };
const statusOptions = Object.entries(statusLabels).map(([k, v]) => ({ label: v, value: Number(k) }));
const levelOptions = Object.entries(levelLabels).map(([k, v]) => ({ label: v, value: Number(k) }));
const sourceOptions = [
  { label: '站点监测', value: 1 },
  { label: '漏洞扫描', value: 2 },
  { label: '流量分析', value: 3 },
  { label: '风险探测', value: 4 },
];
const incidentTypeOptions = [
  { label: 'Web攻击', value: 'web_attack' },
  { label: '恶意代码', value: 'malware' },
  { label: '信息泄露', value: 'data_leak' },
  { label: '拒绝服务', value: 'dos' },
  { label: '非法入侵', value: 'intrusion' },
  { label: '其他', value: 'other' },
];
const unitTypeOptions = [
  { label: '政府机关', value: '政府机关' },
  { label: '事业单位', value: '事业单位' },
  { label: '国有企业', value: '国有企业' },
  { label: '私营企业', value: '私营企业' },
  { label: '其他', value: '其他' },
];
const industryOptions = [
  { label: '金融', value: '金融' },
  { label: '教育', value: '教育' },
  { label: '医疗', value: '医疗' },
  { label: '能源', value: '能源' },
  { label: '通信', value: '通信' },
  { label: '交通', value: '交通' },
  { label: '其他', value: '其他' },
];

const exportMenuOptions = [
  { label: '导出 Word (.docx)', key: 'docx' },
  { label: '导出 PDF', key: 'pdf' },
];

async function handleBatchExport(format: IncidentExportFormat) {
  const ids = checkedRowKeys.value.map(String);
  if (!ids.length) {
    message.warning('请先勾选要导出的事件');
    return;
  }
  exporting.value = true;
  try {
    await downloadBatchIncidentExport(ids, format);
    message.success('导出完成');
  } catch (e: any) {
    message.error(e?.message || '导出失败');
  } finally {
    exporting.value = false;
  }
}

async function handleRowExport(row: SecurityIncident, format: IncidentExportFormat) {
  exporting.value = true;
  try {
    await downloadOneIncidentExport(row.id, format, row.incident_no);
    message.success('导出完成');
  } catch (e: any) {
    message.error(e?.message || '导出失败');
  } finally {
    exporting.value = false;
  }
}

async function handleTransferToCircular(row: SecurityIncident) {
  try {
    const res = await transferToCircular({
      incident_id: row.id,
      incident_no: row.incident_no,
      name: row.name,
      level: row.level,
      source_system: 'incident',
    });
    message.success(`已转通报，通报编号: ${res.circular_code}`);
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '转通报失败');
  }
}

async function handleBatchTransfer() {
  const ids = checkedRowKeys.value.map(String);
  if (!ids.length) {
    message.warning('请先勾选要转通报的事件');
    return;
  }
  const rows = data.value.filter(r => ids.includes(r.id));
  let successCount = 0;
  for (const row of rows) {
    try {
      await transferToCircular({
        incident_id: row.id,
        incident_no: row.incident_no,
        name: row.name,
        level: row.level,
        source_system: 'incident',
      });
      successCount++;
    } catch { /* ignore individual failures */ }
  }
  message.success(`已转通报 ${successCount} 条`);
  await fetchData();
}

const columns = computed(() => [
  { type: 'selection' as const },
  { title: '事件编号', key: 'incident_no', width: 160, ellipsis: { tooltip: true } },
  { title: '事件名称', key: 'name', minWidth: 200, render: (row: SecurityIncident) => h('a', { style: 'color:#2080f0;cursor:pointer', onClick: () => router.push(`/incident/list/${row.id}`) }, row.name) },
  { title: '级别', key: 'level', width: 80, align: 'center' as const, render: (row: SecurityIncident) => h('span', { style: `padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;color:#fff;background:${levelColors[row.level] ?? '#999'}` }, levelLabels[row.level] ?? '-') },
  { title: '状态', key: 'status', width: 110, render: (row: SecurityIncident) => h(NTag, { size: 'small', type: (statusTypes[row.status] || 'default') as any, bordered: false }, () => statusLabels[row.status] ?? '-') },
  { title: 'AI预审', key: 'ai_pre_status', width: 90, render: (row: SecurityIncident) => h(NTag, { size: 'small', type: row.ai_pre_status === 1 ? 'success' : 'default', bordered: false }, () => row.ai_pre_status === 1 ? '已预审' : '未预审') },
  { title: '处置截止时间', key: 'sla_deadline', width: 170, render: (row: SecurityIncident) => { if (!row.sla_deadline) return '-'; const d = new Date(row.sla_deadline); const overdue = d < new Date(); const fmt = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`; return h('span', { style: overdue ? 'color:#d03050;font-weight:600' : '' }, fmt); } },
  { title: '创建时间', key: 'created_at', width: 170, render: (row: SecurityIncident) => { if (!row.created_at) return '-'; const d = new Date(row.created_at); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`; } },
  { title: '操作', key: 'actions', width: 200, fixed: 'right' as const, render: (row: SecurityIncident) => {
    const moreOpts: any[] = [
      { label: '转通报', key: 'transfer' },
      { label: '导出 Word', key: 'docx' },
      { label: '导出 PDF', key: 'pdf' },
    ];
    if (row.status === 1 || row.status === 3) {
      moreOpts.push({ label: 'AI预审', key: 'ai-audit' });
    }
    moreOpts.push({ type: 'divider', key: 'd1' });
    moreOpts.push({ label: '删除', key: 'delete', props: { style: 'color: #d03050' } });
    function handleMoreSelect(key: string) {
      if (key === 'transfer') handleTransferToCircular(row);
      else if (key === 'docx' || key === 'pdf') handleRowExport(row, key as IncidentExportFormat);
      else if (key === 'ai-audit') handleAiAudit(row.id);
      else if (key === 'delete') handleDelete(row.id);
    }
    return h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', text: true, onClick: () => openPreview(row) }, () => '预览'),
      h(NButton, { size: 'tiny', type: 'info', text: true, onClick: () => router.push(`/incident/list/${row.id}`) }, () => '详情'),
      h(NDropdown, { trigger: 'click', options: moreOpts, onSelect: handleMoreSelect }, {
        default: () => h(NButton, { size: 'tiny', text: true, quaternary: true }, () => '更多'),
      }),
    ]);
  } },
]);

async function fetchData() {
  loading.value = true;
  try {
    const r = await getIncidentList({ index: page.value, size: pageSize.value, name: keyword.value || undefined, status: statusFilter.value ?? undefined, level: levelFilter.value ?? undefined });
    data.value = r.items; total.value = r.total;
  } finally { loading.value = false; }
}

async function handleAiAudit(id: string) {
  try { await aiPreAudit(id); message.success('AI预审已完成'); await fetchData(); } catch (e: any) { message.error(e?.message || 'AI预审失败'); }
}
async function handleDelete(id: string) {
  if (!window.confirm('确认删除该安全事件？此操作不可恢复。')) return;
  try { await deleteIncident(id); message.success('已删除'); await fetchData(); } catch (e: any) { message.error(e?.message || '删除失败'); }
}

async function handleBatchDelete() {
  const ids = checkedRowKeys.value as string[];
  if (!ids.length) return;
  let success = 0;
  let fail = 0;
  for (const id of ids) {
    try { await deleteIncident(id); success++; } catch { fail++; }
  }
  message.success(`删除完成：成功 ${success}，失败 ${fail}`);
  checkedRowKeys.value = [];
  await fetchData();
}

function openCreate() {
  createForm.value = defaultForm();
  showCreate.value = true;
}

async function handleCreate() {
  if (!createForm.value.name) { message.warning('请输入事件名称'); return; }
  try {
    await createIncident(createForm.value);
    message.success('创建成功');
    showCreate.value = false;
    await fetchData();
  } catch (e: any) { message.error(e?.message || '创建失败'); }
}

function handleReportTimeUpdate(ts: number | null) {
  createForm.value.report_time = ts ? new Date(ts).toISOString() : undefined;
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NCard title="安全事件列表" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NSelect v-model:value="statusFilter" :options="statusOptions" placeholder="状态" size="small" style="width:120px" clearable @update:value="()=>{page=1;fetchData()}" />
          <NSelect v-model:value="levelFilter" :options="levelOptions" placeholder="级别" size="small" style="width:100px" clearable @update:value="()=>{page=1;fetchData()}" />
          <NInput v-model:value="keyword" placeholder="搜索事件..." size="small" clearable style="width:200px" @keyup.enter="()=>{page=1;fetchData()}" @clear="()=>{page=1;fetchData()}" />
          <NButton size="small" type="primary" @click="()=>{page=1;fetchData()}">搜索</NButton>
          <NButton v-perm.disable="perm('transfer')" size="small" :disabled="!checkedRowKeys.length" @click="handleBatchTransfer">
            批量转通报
          </NButton>
          <NDropdown
            trigger="click"
            :options="exportMenuOptions"
            @select="(key: string) => handleBatchExport(key as IncidentExportFormat)"
          >
            <NButton v-perm.disable="perm('export')" size="small" :loading="exporting" :disabled="!checkedRowKeys.length">
              批量导出
            </NButton>
          </NDropdown>
          <NPopconfirm
            :positive-text="'确认删除'"
            :negative-text="'取消'"
            @positive-click="handleBatchDelete"
          >
            <template #trigger>
              <NButton v-perm.disable="perm('delete')" size="small" type="error" :disabled="!checkedRowKeys.length">
                批量删除
              </NButton>
            </template>
            确认删除选中的 {{ checkedRowKeys.length }} 条安全事件？此操作不可恢复。
          </NPopconfirm>
          <NButton v-perm.disable="perm('create')" size="small" type="primary" @click="openCreate">新建事件</NButton>
        </NSpace>
      </template>
      <NDataTable
        v-model:checked-row-keys="checkedRowKeys"
        :columns="columns"
        :data="data"
        :loading="loading"
        :bordered="false"
        size="small"
        striped
        :scroll-x="1280"
        :row-key="(row: SecurityIncident) => row.id"
        :pagination="{ page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20,50,100], onUpdatePage:(p:number)=>{page=p;fetchData()}, onUpdatePageSize:(s:number)=>{pageSize=s;page=1;fetchData()} }" />
    </NCard>

    <IncidentPreviewDrawer
      v-model:show="showPreview"
      :incident-id="previewId"
    />

    <NModal v-model:show="showCreate" preset="card" title="新建安全事件" style="width:720px;max-width:90vw" :segmented="{ content: true }">
      <NTabs type="line" size="small">
        <NTabPane name="basic" tab="基本信息">
          <NForm label-placement="left" label-width="90" style="padding-top:12px">
            <NFormItem label="事件名称" required>
              <NInput v-model:value="createForm.name" placeholder="请输入事件名称" />
            </NFormItem>
            <NFormItem label="事件级别" required>
              <NSelect v-model:value="createForm.level" :options="levelOptions" />
            </NFormItem>
            <NFormItem label="事件来源" required>
              <NSelect v-model:value="createForm.source" :options="sourceOptions" />
            </NFormItem>
            <NFormItem label="上报时间">
              <NDatePicker type="datetime" clearable style="width:100%" @update:value="handleReportTimeUpdate" />
            </NFormItem>
            <NFormItem label="事件类型">
              <NSelect v-model:value="createForm.metadata!.incident_type" :options="incidentTypeOptions" clearable placeholder="选择事件类型" />
            </NFormItem>
            <NFormItem label="事件描述">
              <NInput v-model:value="createForm.metadata!.incident_description" type="textarea" :rows="3" placeholder="描述事件详情" />
            </NFormItem>
            <NFormItem label="事件URL">
              <NInput v-model:value="createForm.metadata!.incident_url" placeholder="相关URL地址" />
            </NFormItem>
          </NForm>
        </NTabPane>

        <NTabPane name="asset" tab="涉事资产">
          <NForm label-placement="left" label-width="90" style="padding-top:12px">
            <NFormItem label="资产名称">
              <NInput v-model:value="createForm.asset!.asset_name" placeholder="资产名称" />
            </NFormItem>
            <NFormItem label="系统名称">
              <NInput v-model:value="createForm.asset!.system_name" placeholder="信息系统名称" />
            </NFormItem>
            <NFormItem label="域名/IP">
              <NInput v-model:value="createForm.asset!.domain_ip" placeholder="域名或IP地址" />
            </NFormItem>
            <NFormItem label="站点IP">
              <NInput v-model:value="createForm.asset!.site_ip" placeholder="站点IP地址" />
            </NFormItem>
            <NFormItem label="责任单位">
              <NInput v-model:value="createForm.asset!.unit" placeholder="责任单位名称" />
            </NFormItem>
            <NFormItem label="单位类型">
              <NSelect v-model:value="createForm.asset!.unit_type" :options="unitTypeOptions" clearable placeholder="选择单位类型" />
            </NFormItem>
            <NFormItem label="行业">
              <NSelect v-model:value="createForm.asset!.industry" :options="industryOptions" clearable placeholder="选择行业" />
            </NFormItem>
            <NFormItem label="所属地区">
              <NInput v-model:value="createForm.asset!.region" placeholder="所属地区" />
            </NFormItem>
            <NFormItem label="等保备案号">
              <NInput v-model:value="createForm.asset!.mlps_record_no" placeholder="等保备案编号" />
            </NFormItem>
            <NFormItem label="等保级别">
              <NInput v-model:value="createForm.asset!.mlps_level" placeholder="如：三级" />
            </NFormItem>
            <NFormItem label="ICP备案号">
              <NInput v-model:value="createForm.asset!.miit_record_no" placeholder="工信部备案号" />
            </NFormItem>
          </NForm>
        </NTabPane>

        <NTabPane name="vuln" tab="漏洞信息">
          <NForm label-placement="left" label-width="100" style="padding-top:12px">
            <NFormItem label="数据编号">
              <NInput v-model:value="createForm.metadata!.data_no" placeholder="数据编号" />
            </NFormItem>
            <NFormItem label="CVE编号">
              <NInput v-model:value="createForm.metadata!.cve_id" placeholder="如 CVE-2024-1234" />
            </NFormItem>
            <NFormItem label="CVSS评分">
              <NInputNumber v-model:value="createForm.metadata!.cvss_score" :min="0" :max="10" :step="0.1" placeholder="0-10" style="width:100%" />
            </NFormItem>
            <NFormItem label="OWASP分类">
              <NInput v-model:value="createForm.metadata!.owasp_category" placeholder="如 A01:2021-Broken Access Control" />
            </NFormItem>
            <NFormItem label="利用难度">
              <NSelect v-model:value="createForm.metadata!.exploit_difficulty" clearable placeholder="选择利用难度" :options="[{label:'低',value:'低'},{label:'中',value:'中'},{label:'高',value:'高'}]" />
            </NFormItem>
            <NFormItem label="影响范围">
              <NInput v-model:value="createForm.metadata!.affect_scope" placeholder="影响范围描述" />
            </NFormItem>
            <NFormItem label="受影响数量">
              <NInput v-model:value="createForm.metadata!.affected_count" placeholder="受影响资产/用户数" />
            </NFormItem>
            <NFormItem label="受影响类型">
              <NInput v-model:value="createForm.metadata!.affected_type" placeholder="如：用户数据、服务器" />
            </NFormItem>
            <NFormItem label="通报厂商">
              <NInput v-model:value="createForm.metadata!.vendor_name" placeholder="安全厂商名称" />
            </NFormItem>
            <NFormItem label="厂商所属区域">
              <NInput v-model:value="createForm.metadata!.vendor_region" placeholder="厂商区域" />
            </NFormItem>
          </NForm>
        </NTabPane>
      </NTabs>

      <template #footer>
        <NSpace justify="end">
          <NButton @click="showCreate=false">取消</NButton>
          <NButton type="primary" @click="handleCreate">创建事件</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>
