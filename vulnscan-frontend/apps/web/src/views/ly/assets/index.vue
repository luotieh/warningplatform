<script lang="ts" setup>
import { computed, h, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import { marked } from 'marked';
import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPagination,
  NSelect,
  NSpace,
  NTag,
  NUpload,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  lyAssetCreate,
  lyAssetDelete,
  lyAssetImport,
  lyAssetList,
  lyAssetTemplateUrl,
  lyAssetUpdate,
  type LyAsset,
} from '#/api/ly/assets';
import {
  lyGetAssetMonthlyJob,
  lyGetAssetMonthlySummary,
  lyRunAssetMonthlySummary,
  type AssetReportJob,
  type AssetReportSummary,
} from '#/api/ly';
import { useLyStore } from '#/store/ly';
import { countAssetEvents } from '#/utils/ly-asset';
import { paginate } from '#/utils/ly';

defineOptions({ name: 'LyAssets' });

const router = useRouter();
const lyStore = useLyStore();

const assets = ref<LyAsset[]>([]);
const loading = ref(false);
const state = reactive({ keyword: '', type: '', status: '', page: 1, pageSize: 10 });

const typeOptions = [
  { label: 'IP资产', value: 'ip' },
  { label: '域名网站', value: 'domain_site' },
  { label: '网段资产', value: 'ip_segment' },
];
const typeMeta: Record<string, { label: string; tag: 'info' | 'success' | 'warning' }> = {
  domain_site: { label: '域名网站', tag: 'warning' },
  ip: { label: 'IP资产', tag: 'info' },
  ip_segment: { label: '网段资产', tag: 'success' },
};
const statusOptions = [
  { label: '启用', value: '1' },
  { label: '停用', value: '0' },
];

const filtered = computed(() =>
  assets.value.filter((a) => {
    if (state.type && a.asset_type !== state.type) return false;
    if (state.status !== '' && String(a.status ?? 1) !== state.status) return false;
    if (state.keyword) {
      const k = state.keyword.toLowerCase();
      if (!String(a.name).toLowerCase().includes(k) && !String(a.address).toLowerCase().includes(k)) return false;
    }
    return true;
  }),
);
const paged = computed(() => paginate(filtered.value, state.page, state.pageSize));
const monthlyRunning = ref(false);
const monthlyJob = ref<AssetReportJob | null>(null);
const downloadingSummary = ref(false);
const summaryModalVisible = ref(false);
const summaryContent = ref<AssetReportSummary | null>(null);
const summaryHtml = computed(() => {
  const narrative = summaryContent.value?.narrative || '（暂无内容）';
  return marked.parse(narrative, { async: false }) as string;
});

async function load() {
  loading.value = true;
  try {
    assets.value = (await lyAssetList()) || [];
    if (!lyStore.events.length) await lyStore.loadEvents();
  } catch (error) {
    message.error(error instanceof Error ? error.message : '加载失败');
  } finally {
    loading.value = false;
  }
}

// 新增/编辑
const editVisible = ref(false);
const editing = ref(false);
const form = reactive<LyAsset>({ name: '', asset_type: 'ip', address: '', unit: '', owner: '', remark: '', status: 1 });
let editId = '';

function openCreate() {
  editing.value = false;
  editId = '';
  Object.assign(form, { name: '', asset_type: 'ip', address: '', unit: '', owner: '', remark: '', status: 1 });
  editVisible.value = true;
}
function openEdit(row: LyAsset) {
  editing.value = true;
  editId = String(row.id);
  Object.assign(form, { ...row });
  editVisible.value = true;
}
async function submit() {
  if (!form.name.trim() || !form.address.trim()) {
    message.error('资产名称与地址必填');
    return;
  }
  try {
    if (editing.value) {
      await lyAssetUpdate(editId, { ...form });
      message.success('已更新');
    } else {
      await lyAssetCreate({ ...form });
      message.success('已创建');
    }
    editVisible.value = false;
    await load();
  } catch (error) {
    message.error(error instanceof Error ? error.message : '保存失败');
  }
}
function remove(row: LyAsset) {
  dialog.warning({
    title: '删除资产',
    content: `确认删除资产「${row.name}（${row.address}）」？`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await lyAssetDelete(String(row.id));
        message.success('已删除');
        await load();
      } catch (error) {
        message.error(error instanceof Error ? error.message : '删除失败');
      }
    },
  });
}

// 导入
const importVisible = ref(false);
const importResult = ref<{ imported: number; errors: Array<{ row: number; message: string }> } | null>(null);
async function onUpload({ file }: { file: { file?: File | null } }) {
  if (!file.file) return;
  try {
    importResult.value = await lyAssetImport(file.file);
    message.success(`导入成功 ${importResult.value.imported} 条`);
    await load();
  } catch (error) {
    message.error(error instanceof Error ? error.message : '导入失败');
  }
}

function jumpToEvents(row: LyAsset) {
  router.push({ path: '/ly/event/list', query: { asset: row.address } });
}

async function runMonthlySummary() {
  if (monthlyRunning.value) return;
  monthlyRunning.value = true;
  try {
    const job = await lyRunAssetMonthlySummary();
    monthlyJob.value = job;
    message.info(`月度总结任务已创建（job: ${job.id}，共 ${job.total_assets} 个资产）`);
    const timer = window.setInterval(async () => {
      try {
        const current = await lyGetAssetMonthlyJob(job.id);
        monthlyJob.value = current;
        if (current.status === 'completed') {
          window.clearInterval(timer);
          monthlyRunning.value = false;
          message.success(
            `月度总结已完成（${current.completed_assets}/${current.total_assets}）`,
          );
        } else if (current.status === 'failed') {
          window.clearInterval(timer);
          monthlyRunning.value = false;
          message.error(current.error || '月度总结任务失败');
        }
      } catch (error) {
        window.clearInterval(timer);
        monthlyRunning.value = false;
        message.error(error instanceof Error ? error.message : '查询任务进度失败');
      }
    }, 2000);
  } catch (error) {
    monthlyRunning.value = false;
    message.error(error instanceof Error ? error.message : '创建月度总结任务失败');
  }
}

async function viewMonthlySummary(row: LyAsset) {
  try {
    const res = await lyGetAssetMonthlySummary(String(row.id));
    const list = Array.isArray(res) ? res : res ? [res] : [];
    if (!list.length) {
      message.warning('该资产暂无月度总结，请先执行「生成月度总结」');
      return;
    }
    summaryContent.value = list[0] as AssetReportSummary;
    summaryModalVisible.value = true;
  } catch (error) {
    message.error(error instanceof Error ? error.message : '获取月度总结失败');
  }
}

// 生成月度总结 Word 文档（与“查看报告”下载一致：Markdown → HTML → .doc，含 BOM）
function buildMonthlyMarkdown(d: AssetReportSummary): string {
  const s = d.stats || {};
  const lines: string[] = [];
  lines.push(`# 资产月度安全总结报告（${d.period || ''}）`, '');
  lines.push(`- **资产IP**：${d.asset_ip || ''}`);
  lines.push(`- **统计窗口**：${d.window_from || ''} ~ ${d.window_to || ''}`);
  lines.push(`- **落档报告数**：${d.event_count ?? 0}（已闭环 ${s.closed_count ?? 0}）`, '');
  lines.push('## 量化统计', '', '| 指标 | 值 |', '| --- | --- |');
  lines.push(`| 总命中次数 | ${s.total_occurrences ?? 0} |`);
  lines.push(`| 总体量（wire_bytes） | ${s.total_wire_bytes ?? 0} |`);
  lines.push(`| 严重级别分布 | ${JSON.stringify(s.by_severity ?? {})} |`);
  lines.push(`| 事件类型分布 | ${JSON.stringify(s.by_event_type ?? {})} |`);
  lines.push(`| 处置状态分布 | ${JSON.stringify(s.by_status ?? {})} |`);
  for (const [title, key] of [['攻击源 Top', 'top_sources'], ['IOC Top', 'top_iocs'], ['规则 Top', 'top_rules']] as const) {
    lines.push('', `### ${title}`, '');
    const items = s[key] || [];
    if (!items.length) lines.push('- 无');
    for (const item of items) lines.push(`- ${item.value}：${item.count} 次`);
  }
  lines.push('', '## LLM 月度总结', '', d.narrative || '（无）');
  return lines.join('\n');
}

async function downloadMonthlySummary() {
  const d = summaryContent.value;
  if (!d || downloadingSummary.value) return;
  downloadingSummary.value = true;
  try {
    const fullMd = buildMonthlyMarkdown(d);
    const bodyHtml = marked.parse(fullMd, { async: false }) as string;
    const safeName = `月度总结_${String(d.asset_ip || 'asset')}_${String(d.period || '')}`
      .replace(/[\n\r\t\\/:*?"<>|]/g, '_');
    const docHtml =
      '<!DOCTYPE html>' +
      '<html xmlns:o="urn:schemas-microsoft-com:office:office" ' +
      'xmlns:w="urn:schemas-microsoft-com:office:word" ' +
      'xmlns="http://www.w3.org/TR/REC-html40">' +
      '<head><meta charset="utf-8">' +
      `<title>${safeName}</title>` +
      '<style>' +
      'body{font-family:"Microsoft YaHei","PingFang SC",-apple-system,sans-serif;font-size:14px;line-height:1.7;color:#1a1a1a;}' +
      'h1{font-size:22px;font-weight:700;margin:0 0 16px;}' +
      'h2{font-size:18px;font-weight:700;margin:20px 0 10px;}' +
      'h3{font-size:15px;font-weight:600;margin:16px 0 8px;}' +
      'p,li{margin:6px 0;}' +
      'hr{border:0;border-top:1px solid #d9d9d9;margin:18px 0;}' +
      'pre,code{background:#f5f5f5;font-family:Consolas,monospace;}' +
      'pre{padding:12px;}' +
      'table{border-collapse:collapse;width:100%;}' +
      'th,td{border:1px solid #d9d9d9;padding:6px 10px;}' +
      '</style></head>' +
      `<body>${bodyHtml}</body></html>`;
    const blob = new Blob(['﻿', docHtml], { type: 'application/msword' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${safeName}.doc`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    console.error('[monthly] 生成 Word 文档失败', error);
    message.error('生成月度总结 Word 文档失败');
  } finally {
    downloadingSummary.value = false;
  }
}

const columns = [
  { title: '名称', key: 'name', minWidth: 140 },
  {
    title: '类型',
    key: 'asset_type',
    width: 110,
    render: (row: LyAsset) => {
      const meta = typeMeta[row.asset_type ?? ''] ?? { label: row.asset_type || '-', tag: 'info' as const };
      return h(NTag, { size: 'small', type: meta.tag }, { default: () => meta.label });
    },
  },
  { title: '地址', key: 'address', minWidth: 160 },
  { title: '所属单位', key: 'unit', minWidth: 120 },
  { title: '责任人', key: 'owner', width: 100 },
  {
    title: '状态',
    key: 'status',
    width: 90,
    render: (row: LyAsset) =>
      h(NTag, { size: 'small', type: (row.status ?? 1) === 1 ? 'success' : 'default' }, { default: () => ((row.status ?? 1) === 1 ? '启用' : '停用') }),
  },
  {
    title: '关联事件数',
    key: 'related',
    width: 110,
    render: (row: LyAsset) => {
      const n = countAssetEvents(row, lyStore.events || []);
      return h(NButton, { text: true, type: 'primary', disabled: n === 0, onClick: () => jumpToEvents(row) }, { default: () => String(n) });
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 200,
    render: (row: LyAsset) =>
      h(NSpace, { size: 4 }, {
        default: () => [
          h(NButton, { text: true, type: 'info', onClick: () => viewMonthlySummary(row) }, { default: () => '月度总结' }),
          h(NButton, { text: true, type: 'primary', onClick: () => openEdit(row) }, { default: () => '编辑' }),
          h(NButton, { text: true, type: 'error', onClick: () => remove(row) }, { default: () => '删除' }),
        ],
      }),
  },
];

onMounted(load);
</script>

<template>
  <div class="ly-page">
    <NSpace vertical :size="12">
      <NCard size="small">
        <NSpace>
          <NInput v-model:value="state.keyword" clearable placeholder="名称或地址" style="width: 200px" />
          <NSelect v-model:value="state.type" clearable placeholder="类型" :options="typeOptions" style="width: 140px" />
          <NSelect v-model:value="state.status" clearable placeholder="状态" :options="statusOptions" style="width: 120px" />
          <NButton type="primary" @click="openCreate">新增资产</NButton>
          <NButton @click="importVisible = true">导入</NButton>
          <NButton :loading="monthlyRunning" @click="runMonthlySummary">生成月度总结</NButton>
          <NButton @click="load">刷新</NButton>
        </NSpace>
      </NCard>

      <NCard size="small">
        <NDataTable :columns="columns" :data="paged" :loading="loading" size="small" :bordered="false" />
        <div class="pager-wrap">
          <NPagination v-model:page="state.page" v-model:page-size="state.pageSize" :item-count="filtered.length" show-size-picker :page-sizes="[10, 20, 50]" />
        </div>
      </NCard>
    </NSpace>

    <NModal v-model:show="editVisible" preset="card" :title="editing ? '编辑资产' : '新增资产'" style="width: 520px">
      <NForm label-placement="left" label-width="90">
        <NFormItem label="资产名称" required>
          <NInput v-model:value="form.name" placeholder="资产名称" />
        </NFormItem>
        <NFormItem label="类型" required>
          <NSelect v-model:value="form.asset_type" :options="typeOptions" />
        </NFormItem>
        <NFormItem label="地址" required>
          <NInput
            v-model:value="form.address"
            :placeholder="form.asset_type === 'ip_segment' ? '网段 CIDR，如 192.168.1.0/24' : 'IP 或 域名'"
          />
        </NFormItem>
        <NFormItem label="所属单位">
          <NInput v-model:value="form.unit" />
        </NFormItem>
        <NFormItem label="责任人">
          <NInput v-model:value="form.owner" />
        </NFormItem>
        <NFormItem label="状态">
          <NSelect v-model:value="form.status" :options="[{ label: '启用', value: 1 }, { label: '停用', value: 0 }]" />
        </NFormItem>
        <NFormItem label="备注">
          <NInput v-model:value="form.remark" type="textarea" :rows="2" />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="editVisible = false">取消</NButton>
          <NButton type="primary" @click="submit">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <NModal v-model:show="importVisible" preset="card" title="导入资产" style="width: 520px">
      <NSpace vertical>
        <a :href="lyAssetTemplateUrl()" download>下载导入模板（CSV）</a>
        <NUpload :show-file-list="false" accept=".csv,.xlsx" :custom-request="() => {}" @change="onUpload">
          <NButton>选择文件并导入（.csv/.xlsx）</NButton>
        </NUpload>
        <div v-if="importResult">
          成功导入 {{ importResult.imported }} 条<span v-if="importResult.errors?.length">，失败 {{ importResult.errors.length }} 条：</span>
          <ul v-if="importResult.errors?.length">
            <li v-for="e in importResult.errors" :key="e.row">第 {{ e.row }} 行：{{ e.message }}</li>
          </ul>
        </div>
      </NSpace>
    </NModal>

    <NModal
      v-model:show="summaryModalVisible"
      preset="card"
      :title="`月度总结（${summaryContent?.period || ''}）`"
      style="width: 680px"
    >
      <div v-if="summaryContent" class="summary-preview">
        <div class="summary-meta">
          资产 {{ summaryContent.asset_ip }} · 落档报告 {{ summaryContent.event_count }} 份 ·
          窗口 {{ summaryContent.window_from }} ~ {{ summaryContent.window_to }}
        </div>
        <div class="summary-narrative markdown-body" v-html="summaryHtml"></div>
      </div>
      <template #footer>
        <NSpace justify="end">
          <NButton :loading="downloadingSummary" @click="downloadMonthlySummary">
            下载Word
          </NButton>
          <NButton @click="summaryModalVisible = false">关闭</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.ly-page { padding: 12px; }
.pager-wrap { display: flex; justify-content: flex-end; margin-top: 12px; }
.summary-meta { margin-bottom: 10px; font-size: 13px; color: #64748b; }
.summary-narrative { max-height: 60vh; margin: 0; overflow: auto; font-family: inherit; font-size: 13px; line-height: 1.7; word-break: break-word; }
.summary-narrative :deep(h1), .summary-narrative :deep(h2), .summary-narrative :deep(h3) { margin: 12px 0 6px; font-size: 15px; }
.summary-narrative :deep(p) { margin: 6px 0; }
.summary-narrative :deep(ul), .summary-narrative :deep(ol) { margin: 6px 0; padding-left: 20px; }
.summary-narrative :deep(strong) { color: #d03050; }
</style>
