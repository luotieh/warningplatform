<script lang="ts" setup>
import { computed, h, onMounted, onUnmounted, ref } from 'vue';

import {
  NButton,
  NCard,
  NDataTable,
  NInput,
  NModal,
  NForm,
  NFormItem,
  NSelect,
  NSpace,
  NTag,
  NProgress,
  NPopconfirm,
  useMessage,
  type DataTableRowKey,
} from 'naive-ui';
import { useRouter } from 'vue-router';

import { getTaskList, createTask, cancelTask, deleteTask, type ScanTask } from '#/api/task';
import { getTemplateList, type ScanTemplate } from '#/api/template';
import ModuleConfigPanel from '../components/module-config-panel.vue';

defineOptions({ name: 'ScanTaskList' });

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const data = ref<ScanTask[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const checkedRowKeys = ref<DataTableRowKey[]>([]);
let refreshTimer: ReturnType<typeof setInterval> | null = null;

const showCreate = ref(false);
const creating = ref(false);
const showAdvanced = ref(false);
const showModuleConfig = ref(false);
const moduleConfigs = ref<Record<string, Record<string, any>>>({});
const templates = ref<ScanTemplate[]>([]);
const selectedTemplateId = ref('');
const form = ref<{
  name: string;
  targets: string;
  profile: string;
  priority: number;
  modules: string[];
  template_id: string;
  verification_level: string;
}>({ name: '', targets: '', profile: 'full', priority: 5, modules: [], template_id: '', verification_level: 'both' });

const profileOptions = [
  { label: '全面扫描 — 信息收集+漏洞检测完整流程', value: 'full' },
  { label: '快速扫描 — 存活检测+端口扫描+服务识别', value: 'quick' },
  { label: '信息收集 — 子域名/DNS/指纹/WAF/技术栈', value: 'recon' },
  { label: '漏洞扫描 — 常规漏洞检测模块', value: 'vuln' },
  { label: '深度漏洞扫描 — 包含所有漏洞检测+API安全', value: 'vuln-full' },
];

const verificationOptions = [
  { label: '全部 — 原理验证+实际利用', value: 'both' },
  { label: '原理验证 — 仅检测漏洞模式，不实际利用', value: 'principle' },
  { label: '实际利用 — 确认漏洞可被利用', value: 'exploit' },
];

const moduleOptions = [
  { label: 'ICMP 存活探测', value: 'icmp_ping' },
  { label: '端口扫描', value: 'port_scan' },
  { label: 'SYN 半开扫描', value: 'syn_scan' },
  { label: 'UDP 端口扫描', value: 'udp_scan' },
  { label: '服务探测', value: 'service_probe' },
  { label: '子域名爆破', value: 'subdomain_brute' },
  { label: 'DNS 全量枚举', value: 'dns_all' },
  { label: 'Web 爬虫', value: 'web_crawl' },
  { label: 'JS 分析', value: 'js_analyze' },
  { label: 'WAF 检测', value: 'waf_detect' },
  { label: '技术栈检测', value: 'tech_detect' },
  { label: 'Favicon Hash', value: 'favicon' },
  { label: 'TLS/SSL 证书检测', value: 'cert_check' },
  { label: 'API 接口发现', value: 'api_disc' },
  { label: '目录扫描', value: 'dir_scan' },
  { label: '真实IP发现', value: 'real_ip' },
  { label: 'SQL 注入检测', value: 'sqli' },
  { label: 'XSS 检测', value: 'xss' },
  { label: 'SSRF 检测', value: 'ssrf' },
  { label: '弱口令检测', value: 'weak_pass' },
  { label: '信息泄露检测', value: 'info_leak' },
  { label: 'SSTI 模板注入检测', value: 'ssti' },
  { label: 'XXE 外部实体注入', value: 'xxe' },
  { label: 'NoSQL 注入检测', value: 'nosqli' },
  { label: 'JWT 安全检测', value: 'jwt_sec' },
  { label: '命令注入检测', value: 'cmdi' },
  { label: '本地文件包含', value: 'lfi' },
  { label: '暴力破解', value: 'bruteforce' },
  { label: 'API 安全检测', value: 'apisec' },
  { label: 'Nuclei PoC', value: 'nuclei' },
];

const priorityOptions = [
  { label: '最高 (1)', value: 1 },
  { label: '高 (3)', value: 3 },
  { label: '普通 (5)', value: 5 },
  { label: '低 (7)', value: 7 },
  { label: '最低 (10)', value: 10 },
];

const statusConfig: Record<string, { type: string; label: string }> = {
  pending: { type: 'default', label: '等待中' },
  queued: { type: 'info', label: '排队中' },
  running: { type: 'warning', label: '扫描中' },
  completed: { type: 'success', label: '完成' },
  failed: { type: 'error', label: '失败' },
  cancelled: { type: 'default', label: '已取消' },
};

function formatTime(raw?: string) {
  if (!raw) return '-';
  const d = new Date(raw);
  if (isNaN(d.getTime())) return raw;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const columns = [
  { type: 'selection' as const, width: 40 },
  {
    title: '任务名称',
    key: 'name',
    minWidth: 140,
    ellipsis: { tooltip: true },
    render: (row: ScanTask) =>
      h('a', {
        style: 'color: var(--primary-color); cursor: pointer; font-weight: 500',
        onClick: () => router.push(`/scan/task/${row.id}`),
      }, row.name),
  },
  {
    title: '目标数',
    key: 'total_targets',
    width: 70,
    align: 'center' as const,
  },
  {
    title: '存活/端口',
    key: 'alive_hosts',
    width: 90,
    align: 'center' as const,
    render: (row: ScanTask) => {
      const alive = row.alive_hosts ?? 0;
      const ports = row.open_ports ?? 0;
      return h('span', { style: 'font-size: 12px' }, `${alive} / ${ports}`);
    },
  },
  {
    title: '任务进度',
    key: 'progress',
    width: 160,
    render: (row: ScanTask) => {
      const pct = Math.round(row.progress ?? 0);
      const color = row.status === 'failed' ? '#e88080' : row.status === 'completed' ? '#48bb78' : undefined;
      return h(NProgress, {
        type: 'line',
        percentage: pct,
        indicatorPlacement: 'inside',
        height: 18,
        color,
        railColor: row.status === 'failed' ? '#fce4e4' : undefined,
      });
    },
  },
  {
    title: '状态',
    key: 'status',
    width: 80,
    render: (row: ScanTask) => {
      const s = statusConfig[row.status] || { type: 'default', label: row.status };
      return h(NTag, { type: s.type as any, size: 'small' }, () => s.label);
    },
  },
  {
    title: '创建时间',
    key: 'created_at',
    width: 170,
    render: (row: ScanTask) => h('span', { style: 'font-size: 13px; white-space: nowrap' }, formatTime(row.created_at)),
  },
  {
    title: '结束时间',
    key: 'finished_at',
    width: 170,
    render: (row: ScanTask) => h('span', { style: 'font-size: 13px; white-space: nowrap' }, formatTime(row.finished_at)),
  },
  {
    title: '操作',
    key: 'actions',
    width: 200,
    fixed: 'right' as const,
    render: (row: ScanTask) => {
      const btns: any[] = [];

      btns.push(h(NButton, {
        size: 'tiny',
        type: 'primary',
        text: true,
        onClick: () => router.push(`/scan/task/${row.id}`),
      }, () => row.status === 'completed' || row.status === 'failed' ? '结果' : '查看'));

      if (row.status === 'running' || row.status === 'queued') {
        btns.push(h(NPopconfirm, { onPositiveClick: () => handleCancel(row.id) }, {
          trigger: () => h(NButton, { size: 'tiny', type: 'warning', text: true }, () => '取消'),
          default: () => '确定取消此任务？',
        }));
      }

      if (row.status !== 'running' && row.status !== 'queued') {
        btns.push(h(NPopconfirm, { onPositiveClick: () => handleDeleteRow(row.id) }, {
          trigger: () => h(NButton, { size: 'tiny', type: 'error', text: true }, () => '删除'),
          default: () => '确定删除此任务？',
        }));
      }

      return h(NSpace, { size: 8 }, () => btns);
    },
  },
];

async function fetchData() {
  loading.value = true;
  try {
    const result = await getTaskList({
      page: page.value,
      page_size: pageSize.value,
      keyword: keyword.value || undefined,
    });
    data.value = result.items ?? [];
    total.value = result.total ?? 0;
  } finally {
    loading.value = false;
  }
}

async function handleCreate() {
  if (!form.value.targets.trim()) {
    message.warning('请输入扫描目标');
    return;
  }
  creating.value = true;
  try {
    const targets = form.value.targets.split(/[\n,;]+/).map((t) => t.trim()).filter(Boolean);
    const payload: Record<string, any> = {
      name: form.value.name || `扫描-${new Date().toLocaleString()}`,
      targets,
      profile: form.value.profile,
      priority: form.value.priority,
      modules: form.value.modules.length > 0 ? form.value.modules : undefined,
    };
    const params: Record<string, any> = {};
    if (Object.keys(moduleConfigs.value).length > 0) {
      params.module_configs = moduleConfigs.value;
    }
    if (form.value.verification_level !== 'both') {
      params.verification_level = form.value.verification_level;
    }
    if (Object.keys(params).length > 0) {
      payload.parameters = params;
    }
    if (form.value.template_id) {
      payload.template_id = form.value.template_id;
    }
    await createTask(payload);
    message.success('任务创建成功');
    showCreate.value = false;
    showAdvanced.value = false;
    selectedTemplateId.value = '';
    form.value = { name: '', targets: '', profile: 'full', priority: 5, modules: [], template_id: '', verification_level: 'both' };
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '创建失败');
  } finally {
    creating.value = false;
  }
}

async function handleCancel(id: string) {
  try {
    await cancelTask(id);
    message.success('任务已取消');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '取消失败');
  }
}

async function handleDeleteRow(id: string) {
  try {
    await deleteTask(id);
    message.success('删除成功');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}

async function handleBatchDelete() {
  if (checkedRowKeys.value.length === 0) {
    message.warning('请先选择任务');
    return;
  }
  for (const id of checkedRowKeys.value) {
    try {
      await deleteTask(id as string);
    } catch { /* continue */ }
  }
  checkedRowKeys.value = [];
  message.success('批量删除完成');
  await fetchData();
}

async function loadTemplates() {
  try {
    const res = await getTemplateList({ page: 1, page_size: 100 });
    templates.value = res.items.filter(t => t.enabled);
  } catch {}
}

const templateOptions = computed(() => [
  { label: '不使用模板 (手动配置)', value: '' },
  ...templates.value.map(t => ({ label: `${t.name} ${t.builtin ? '(内置)' : ''}`, value: t.id })),
]);

function handleTemplateSelect(id: string) {
  selectedTemplateId.value = id;
  form.value.template_id = id;
  if (!id) return;
  const tmpl = templates.value.find(t => t.id === id);
  if (!tmpl) return;
  form.value.name = tmpl.name + ' - ' + new Date().toLocaleDateString('zh-CN');
}

onMounted(() => {
  fetchData();
  loadTemplates();
  refreshTimer = setInterval(() => {
    if (data.value.some((t) => t.status === 'running' || t.status === 'queued')) {
      fetchData();
    }
  }, 5000);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
});
</script>

<template>
  <div class="task-list-page">
    <NCard size="small">
      <!-- Toolbar -->
      <div class="toolbar">
        <div class="toolbar-left">
          <NButton type="primary" @click="showCreate = true">
            <template #icon><span style="font-size: 16px; line-height: 1">+</span></template>
            新建任务
          </NButton>
          <NPopconfirm @positive-click="handleBatchDelete">
            <template #trigger>
              <NButton :disabled="checkedRowKeys.length === 0">
                删除{{ checkedRowKeys.length > 0 ? ` (${checkedRowKeys.length})` : '' }}
              </NButton>
            </template>
            确定删除选中的 {{ checkedRowKeys.length }} 个任务？
          </NPopconfirm>
          <NButton quaternary @click="fetchData">
            <template #icon><span style="font-size: 14px">&#8635;</span></template>
          </NButton>
        </div>
        <div class="toolbar-right">
          <NInput
            v-model:value="keyword"
            placeholder="搜索任务名称..."
            style="width: 260px"
            clearable
            @keyup.enter="fetchData"
            @clear="fetchData"
          />
        </div>
      </div>

      <NDataTable
        :columns="columns"
        :data="data"
        :loading="loading"
        :bordered="false"
        size="small"
        striped
        :scroll-x="1120"
        :row-key="(row: ScanTask) => row.id"
        v-model:checked-row-keys="checkedRowKeys"
        :pagination="{
          page: page,
          pageSize: pageSize,
          itemCount: total,
          showSizePicker: true,
          pageSizes: [20, 50, 100],
          prefix: ({ itemCount }: { itemCount: number }) => `共 ${itemCount} 条`,
          onUpdatePage: (p: number) => { page = p; fetchData(); },
          onUpdatePageSize: (s: number) => { pageSize = s; page = 1; fetchData(); },
        }"
      />
    </NCard>

    <!-- Create Task Modal -->
    <NModal v-model:show="showCreate" preset="card" style="width: 680px; border-radius: 12px" :mask-closable="false">
      <template #header>
        <div class="modal-header">
          <span class="modal-title">创建扫描任务</span>
          <span class="modal-subtitle">配置目标和扫描策略</span>
        </div>
      </template>

      <NForm label-placement="left" label-width="80" style="margin-top: 4px">
        <!-- Template -->
        <NFormItem label="扫描模板">
          <NSelect v-model:value="selectedTemplateId" :options="templateOptions" placeholder="选择模板快速配置（可选）" @update:value="handleTemplateSelect" />
        </NFormItem>

        <!-- Task Name -->
        <NFormItem label="任务名称">
          <NInput v-model:value="form.name" placeholder="留空将自动生成名称" />
        </NFormItem>

        <!-- Targets -->
        <NFormItem label="扫描目标">
          <NInput
            v-model:value="form.targets"
            type="textarea"
            placeholder="每行一个目标，支持 IP / 域名 / CIDR / URL&#10;示例: 192.168.1.0/24&#10;      example.com&#10;      https://api.example.com"
            :rows="5"
            style="font-family: 'SF Mono', Consolas, monospace; font-size: 13px"
          />
        </NFormItem>

        <!-- Profile & Verification in a row -->
        <div style="display: flex; gap: 16px">
          <NFormItem label="扫描模式" style="flex: 1">
            <NSelect v-model:value="form.profile" :options="profileOptions" />
          </NFormItem>
          <NFormItem label="验证级别" style="flex: 1">
            <NSelect v-model:value="form.verification_level" :options="verificationOptions" />
          </NFormItem>
        </div>

        <!-- Advanced Toggle -->
        <div class="advanced-toggle" @click="showAdvanced = !showAdvanced">
          <span class="advanced-arrow" :class="{ expanded: showAdvanced }">&#9654;</span>
          <span>高级选项</span>
        </div>

        <template v-if="showAdvanced">
          <div style="display: flex; gap: 16px; margin-top: 12px">
            <NFormItem label="优先级" style="flex: 1">
              <NSelect v-model:value="form.priority" :options="priorityOptions" />
            </NFormItem>
            <div style="flex: 1" />
          </div>
          <NFormItem label="扫描模块">
            <NSelect
              v-model:value="form.modules"
              :options="moduleOptions"
              multiple
              clearable
              placeholder="留空使用扫描模式默认模块"
              max-tag-count="responsive"
            />
          </NFormItem>
          <div class="form-hint">选择后将覆盖扫描模式的默认模块列表</div>
        </template>

        <!-- Module Config -->
        <div class="module-config-link">
          <NButton text type="primary" size="small" @click="showModuleConfig = true">
            模块参数微调
          </NButton>
          <NTag v-if="Object.keys(moduleConfigs).length > 0" size="small" type="success" round :bordered="false">
            {{ Object.keys(moduleConfigs).length }} 个模块已配置
          </NTag>
        </div>
      </NForm>

      <template #action>
        <NSpace justify="end" :size="12">
          <NButton @click="showCreate = false">取消</NButton>
          <NButton type="primary" :loading="creating" @click="handleCreate">
            开始扫描
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <ModuleConfigPanel
      v-model:show="showModuleConfig"
      :module-configs="moduleConfigs"
      @save="(configs: Record<string, Record<string, any>>) => moduleConfigs = configs"
    />
  </div>
</template>

<style scoped>
.task-list-page {
  padding: 20px 24px;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 12px;
}

.toolbar-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.toolbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.modal-header {
  display: flex;
  flex-direction: column;
}

.modal-title {
  font-size: 17px;
  font-weight: 600;
}

.modal-subtitle {
  font-size: 12px;
  color: #999;
  margin-top: 2px;
  font-weight: 400;
}

.advanced-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  font-size: 13px;
  color: #666;
  user-select: none;
  padding: 6px 0;
  transition: color 0.15s;
}
.advanced-toggle:hover {
  color: #1890ff;
}

.advanced-arrow {
  display: inline-block;
  font-size: 10px;
  transition: transform 0.2s;
}
.advanced-arrow.expanded {
  transform: rotate(90deg);
}

.form-hint {
  font-size: 12px;
  color: #999;
  margin-top: -8px;
  margin-bottom: 12px;
  padding-left: 80px;
}

.module-config-link {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 8px;
  padding-top: 12px;
  border-top: 1px dashed #f0f0f0;
}
</style>
