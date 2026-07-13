<script lang="ts" setup>
import { computed, h, onMounted, reactive } from 'vue';

import {
  NButton,
  NCard,
  NDataTable,
  NDrawer,
  NDrawerContent,
  NInput,
  NModal,
  NPagination,
  NSelect,
  NSpace,
  NTag,
  NText,
  useMessage,
} from 'naive-ui';

import { IconifyIcon } from '@vben/icons';

import { lyRuleConfigGet, lyRuleConfigSave, lyRuleList } from '#/api/ly';
import { formatTimestamp } from '#/utils/ly';

defineOptions({ name: 'LyConfigRules' });

const message = useMessage();

const state = reactive({
  loading: false,
  rows: [] as Record<string, any>[],
  total: 0,
  page: 1,
  pageSize: 20,
  type: '',
  severity: '',
  keyword: '',
  typeCounts: {} as Record<string, number>,
  sourceFile: '',
  loadedAt: '',
});

const config = reactive({
  show: false,
  loading: false,
  saving: false,
  path: '',
  info: null as null | Record<string, any>,
});

const modeText: Record<string, string> = {
  auto: '默认探测',
  file: '单文件',
  folder: '文件夹',
};

async function openConfig() {
  config.show = true;
  config.loading = true;
  try {
    const data = (await lyRuleConfigGet()) as Record<string, any>;
    config.info = data;
    config.path = String(data?.path ?? '');
  } catch (error) {
    message.error(error instanceof Error ? error.message : '获取规则路径配置失败');
  } finally {
    config.loading = false;
  }
}

async function saveConfig() {
  config.saving = true;
  try {
    const data = (await lyRuleConfigSave(config.path.trim())) as Record<string, any>;
    config.info = data;
    if (data?.error) {
      message.warning(`已保存，但解析有误：${data.error}`);
    } else {
      message.success(
        `已生效：${data?.file_count ?? 0} 个文件 / ${data?.rule_count ?? 0} 条规则`,
      );
    }
    state.page = 1;
    await load();
  } catch (error) {
    message.error(error instanceof Error ? error.message : '保存规则路径失败');
  } finally {
    config.saving = false;
  }
}

const typeLabels: Record<string, string> = {
  domain: '域名',
  hash: '文件哈希',
  ip: 'IP',
  url: 'URL',
};

const allCount = computed(() =>
  Object.values(state.typeCounts).reduce((sum, n) => sum + Number(n || 0), 0),
);

const typeOptions = computed(() => [
  { label: `全部${allCount.value ? ` (${allCount.value})` : ''}`, value: '' },
  ...Object.entries(state.typeCounts).map(([key, count]) => ({
    label: `${typeLabels[key] ?? key} (${count})`,
    value: key,
  })),
]);

const severityOptions = [
  { label: '全部等级', value: '' },
  { label: '高', value: 'high' },
  { label: '中', value: 'medium' },
  { label: '低', value: 'low' },
];

function severityTag(value: string) {
  const map: Record<string, { text: string; type: 'default' | 'error' | 'info' | 'warning' }> = {
    high: { text: '高', type: 'error' },
    low: { text: '低', type: 'info' },
    medium: { text: '中', type: 'warning' },
  };
  return map[String(value).toLowerCase()] ?? { text: value || '-', type: 'default' };
}

// 行左侧严重度色条（与事件列表的视觉语言一致）
function rowClassName(row: Record<string, any>): string {
  const sev = String(row.severity ?? '').toLowerCase();
  return ['high', 'medium', 'low'].includes(sev) ? `sev-${sev}` : 'sev-none';
}

// recommended_action → 展示元数据
function actionMeta(value?: string): {
  icon: string;
  text: string;
  type: 'default' | 'error' | 'info' | 'warning';
} {
  const map: Record<string, { icon: string; text: string; type: 'error' | 'info' | 'warning' }> = {
    alert: { icon: 'lucide:bell-ring', text: '告警', type: 'warning' },
    block: { icon: 'lucide:ban', text: '阻断', type: 'error' },
    block_and_report: { icon: 'lucide:shield-ban', text: '阻断并上报', type: 'error' },
    monitor: { icon: 'lucide:eye', text: '监控', type: 'info' },
    report: { icon: 'lucide:flag', text: '上报', type: 'warning' },
  };
  const key = String(value ?? '').toLowerCase();
  return map[key] ?? { icon: 'lucide:circle-help', text: value || '-', type: 'default' };
}

function tlpTagType(value?: string): 'default' | 'error' | 'success' | 'warning' {
  const map: Record<string, 'error' | 'success' | 'warning'> = {
    amber: 'warning',
    green: 'success',
    red: 'error',
  };
  return map[String(value ?? '').toLowerCase()] ?? 'default';
}

function threatLabels(row: Record<string, any>): string[] {
  const labels = row?.evidence?.threat_labels;
  return Array.isArray(labels) ? labels.filter(Boolean).map(String) : [];
}

const detail = reactive({
  show: false,
  row: null as null | Record<string, any>,
});

function openDetail(row: Record<string, any>) {
  detail.row = row;
  detail.show = true;
}

const detailEvidencePairs = computed(() => {
  const ev = detail.row?.evidence ?? {};
  return [
    { label: '关联活动', value: ev.activity },
    { label: '情报源', value: ev.source },
    { label: '交叉验证', value: ev.cross_check },
    { label: '置信度', value: ev.confidence },
    { label: 'MISP 事件', value: ev.misp_event_id },
  ].filter((item) => item.value);
});

const columns = [
  {
    title: '类型',
    key: 'type',
    width: 96,
    render: (row: Record<string, any>) =>
      h(
        NTag,
        { size: 'small', type: 'info', bordered: false },
        { default: () => typeLabels[row.type] ?? row.type ?? '-' },
      ),
  },
  {
    title: '值',
    key: 'value',
    minWidth: 200,
    ellipsis: { tooltip: true },
    render: (row: Record<string, any>) =>
      h(
        'span',
        { style: 'font-family:ui-monospace,SFMono-Regular,Menlo,monospace' },
        row.value ?? '-',
      ),
  },
  { title: '类别', key: 'category', width: 96 },
  {
    title: '等级',
    key: 'severity',
    width: 84,
    render: (row: Record<string, any>) => {
      const tag = severityTag(row.severity);
      return h(NTag, { size: 'small', type: tag.type }, { default: () => tag.text });
    },
  },
  {
    title: '处置建议',
    key: 'recommended_action',
    width: 128,
    render: (row: Record<string, any>) => {
      if (!row.recommended_action) return '-';
      const meta = actionMeta(row.recommended_action);
      return h(
        NTag,
        { size: 'small', round: true, type: meta.type },
        {
          default: () =>
            h('span', { style: 'display:inline-flex;align-items:center;gap:3px' }, [
              h(IconifyIcon, { icon: meta.icon }),
              meta.text,
            ]),
        },
      );
    },
  },
  {
    title: '威胁标签',
    key: 'threat_labels',
    minWidth: 190,
    render: (row: Record<string, any>) => {
      const labels = threatLabels(row);
      if (labels.length === 0) return '-';
      const shown = labels.slice(0, 2);
      const rest = labels.length - shown.length;
      const children = shown.map((label) =>
        h(
          NTag,
          { size: 'small', bordered: false, style: 'max-width:120px' },
          { default: () => h('span', { class: 'label-ellipsis', title: label }, label) },
        ),
      );
      if (rest > 0) {
        children.push(
          h(
            NTag,
            { size: 'small', bordered: false, type: 'info' },
            { default: () => `+${rest}` },
          ),
        );
      }
      return h('div', { style: 'display:flex;flex-wrap:wrap;gap:4px' }, children);
    },
  },
  { title: '来源', key: 'source', width: 130, ellipsis: { tooltip: true } },
  {
    title: '描述',
    key: 'description',
    minWidth: 240,
    ellipsis: { tooltip: true },
  },
  {
    title: '操作',
    key: 'actions',
    width: 64,
    render: (row: Record<string, any>) =>
      h(
        NButton,
        { text: true, size: 'small', type: 'primary', onClick: () => openDetail(row) },
        { default: () => '详情' },
      ),
  },
];

async function load() {
  state.loading = true;
  try {
    const data = (await lyRuleList({
      keyword: state.keyword || undefined,
      page: state.page,
      page_size: state.pageSize,
      severity: state.severity || undefined,
      type: state.type || undefined,
    })) as Record<string, any>;
    state.rows = Array.isArray(data?.items) ? data.items : [];
    state.total = Number(data?.total ?? 0);
    if (data?.type_counts) state.typeCounts = data.type_counts;
    state.sourceFile = String(data?.source_file ?? '');
    state.loadedAt = String(data?.loaded_at ?? '');
  } catch (error) {
    message.error(error instanceof Error ? error.message : '获取规则失败');
    state.rows = [];
    state.total = 0;
  } finally {
    state.loading = false;
  }
}

function onSearch() {
  state.page = 1;
  load();
}

function onReset() {
  state.type = '';
  state.severity = '';
  state.keyword = '';
  state.page = 1;
  load();
}

function onPageChange(page: number) {
  state.page = page;
  load();
}

function onSizeChange(size: number) {
  state.pageSize = size;
  state.page = 1;
  load();
}

onMounted(load);
</script>

<template>
  <div class="ly-page">
    <NCard class="content-card" size="small">
      <div class="toolbar">
        <NSpace align="center" :wrap="true">
          <NSelect
            v-model:value="state.type"
            :options="typeOptions"
            class="filter-type"
            @update:value="onSearch"
          />
          <NSelect
            v-model:value="state.severity"
            :options="severityOptions"
            class="filter-severity"
            @update:value="onSearch"
          />
          <NInput
            v-model:value="state.keyword"
            class="filter-keyword"
            placeholder="按值 / 描述 / 标签 / 证据 / 处置建议搜索"
            clearable
            @keyup.enter="onSearch"
          />
          <NButton type="primary" :loading="state.loading" @click="onSearch">
            搜索
          </NButton>
          <NButton @click="onReset">重置</NButton>
          <NButton secondary type="primary" @click="openConfig">
            规则路径配置
          </NButton>
        </NSpace>
        <NText depth="3" class="meta">
          共 {{ state.total }} 条 · 只读，规则来自 ta_node
          <template v-if="state.sourceFile"> · {{ state.sourceFile }}</template>
        </NText>
      </div>

      <NDataTable
        :columns="columns"
        :data="state.rows"
        :loading="state.loading"
        :bordered="true"
        size="small"
        :row-key="(row) => row.id"
        :row-class-name="rowClassName"
        :scroll-x="1180"
      />
      <div class="pager-wrap">
        <NPagination
          :page="state.page"
          :page-size="state.pageSize"
          :item-count="state.total"
          show-size-picker
          show-quick-jumper
          :page-sizes="[20, 50, 100, 200]"
          @update:page="onPageChange"
          @update:page-size="onSizeChange"
        />
      </div>
    </NCard>

    <NModal
      v-model:show="config.show"
      preset="card"
      title="规则读取路径配置"
      class="config-modal"
      ::bordered="false"
      :style="{ width: 'min(520px, 92vw)' }"
    >
      <NSpace vertical :size="14">
        <div class="config-hint">
          填写<strong>单个 yaml 文件</strong>路径，或<strong>包含 yaml 的文件夹</strong>路径（文件夹会读取其下所有
          .yaml/.yml）。留空则恢复默认探测（环境变量 / 内置目录）。
        </div>
        <NInput
          v-model:value="config.path"
          type="text"
          clearable
          placeholder="例如 /app/configs/intel.ip.yaml 或 /app/configs"
        />
        <div v-if="config.info" class="config-info">
          <div>
            当前模式：<NTag size="small" type="info">{{
              modeText[config.info.mode] ?? config.info.mode
            }}</NTag>
          </div>
          <div>生效路径：{{ config.info.path || '（默认探测）' }}</div>
          <div>
            解析到 {{ config.info.file_count ?? 0 }} 个文件 ·
            {{ config.info.rule_count ?? 0 }} 条规则
          </div>
          <div v-if="config.info.error" class="config-error">
            解析错误：{{ config.info.error }}
          </div>
          <ul
            v-if="config.info.resolved_files && config.info.resolved_files.length"
            class="config-files"
          >
            <li v-for="f in config.info.resolved_files" :key="f">{{ f }}</li>
          </ul>
        </div>
        <NText depth="3" class="config-note">
          说明：当前为进程内存生效，服务重启后回退默认探测。
        </NText>
      </NSpace>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="config.show = false">关闭</NButton>
          <NButton type="primary" :loading="config.saving" @click="saveConfig">
            保存并重新加载
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <NDrawer v-model:show="detail.show" placement="right" :width="640">
      <NDrawerContent title="规则详情" closable>
        <div v-if="detail.row" class="detail-body">
          <div class="detail-value">
            <IconifyIcon
              icon="lucide:crosshair"
              class="detail-value-icon"
              :style="{ color: severityTag(detail.row.severity).type === 'error' ? '#d03050' : '#909399' }"
            />
            <span class="detail-value-text">{{ detail.row.value || '-' }}</span>
          </div>
          <NSpace :size="6" align="center" :wrap="true" class="detail-tags-row">
            <NTag size="small" type="info" :bordered="false">
              {{ typeLabels[detail.row.type] ?? detail.row.type ?? '-' }}
            </NTag>
            <NTag size="small" :type="severityTag(detail.row.severity).type">
              {{ severityTag(detail.row.severity).text }}等级
            </NTag>
            <NTag v-if="detail.row.category" size="small" :bordered="false">
              {{ detail.row.category }}
            </NTag>
            <NTag
              v-if="detail.row.recommended_action"
              size="small"
              round
              :type="actionMeta(detail.row.recommended_action).type"
            >
              <span class="pill-inline">
                <IconifyIcon :icon="actionMeta(detail.row.recommended_action).icon" />
                {{ actionMeta(detail.row.recommended_action).text }}
              </span>
            </NTag>
            <NTag size="small" :type="detail.row.enabled ? 'success' : 'default'">
              {{ detail.row.enabled ? '启用' : '停用' }}
            </NTag>
            <NTag
              v-if="detail.row.evidence?.tlp"
              size="small"
              :type="tlpTagType(detail.row.evidence.tlp)"
            >
              TLP:{{ String(detail.row.evidence.tlp).toUpperCase() }}
            </NTag>
          </NSpace>

          <div v-if="detail.row.evidence?.narrative" class="detail-section">
            <div class="detail-section-title">
              <IconifyIcon icon="lucide:sparkles" /> 情报研判
            </div>
            <div class="detail-narrative">{{ detail.row.evidence.narrative }}</div>
          </div>

          <div v-if="detail.row.description" class="detail-section">
            <div class="detail-section-title">
              <IconifyIcon icon="lucide:text" /> 描述
            </div>
            <div class="detail-desc">{{ detail.row.description }}</div>
          </div>

          <div v-if="detailEvidencePairs.length" class="detail-section">
            <div class="detail-section-title">
              <IconifyIcon icon="lucide:file-search" /> 证据信息
            </div>
            <div class="detail-kv">
              <template v-for="item in detailEvidencePairs" :key="item.label">
                <div class="detail-kv-label">{{ item.label }}</div>
                <div class="detail-kv-value">{{ item.value }}</div>
              </template>
            </div>
          </div>

          <div v-if="threatLabels(detail.row).length" class="detail-section">
            <div class="detail-section-title">
              <IconifyIcon icon="lucide:tags" /> 威胁标签
            </div>
            <NSpace :size="6" :wrap="true">
              <NTag
                v-for="label in threatLabels(detail.row)"
                :key="label"
                size="small"
                :bordered="false"
              >
                {{ label }}
              </NTag>
            </NSpace>
          </div>

          <div v-if="detail.row.tags?.length" class="detail-section">
            <div class="detail-section-title">
              <IconifyIcon icon="lucide:bookmark" /> 原始标签
            </div>
            <NSpace :size="6" :wrap="true">
              <NTag
                v-for="tag in detail.row.tags"
                :key="tag"
                size="small"
                :bordered="false"
                class="detail-raw-tag"
              >
                {{ tag }}
              </NTag>
            </NSpace>
          </div>

          <div class="detail-section">
            <div class="detail-section-title">
              <IconifyIcon icon="lucide:info" /> 元信息
            </div>
            <div class="detail-kv">
              <div class="detail-kv-label">规则 ID</div>
              <div class="detail-kv-value detail-mono">{{ detail.row.id || '-' }}</div>
              <div class="detail-kv-label">来源</div>
              <div class="detail-kv-value">{{ detail.row.source || '-' }}</div>
              <div class="detail-kv-label">创建时间</div>
              <div class="detail-kv-value">{{ formatTimestamp(detail.row.created_at) }}</div>
              <div class="detail-kv-label">更新时间</div>
              <div class="detail-kv-value">{{ formatTimestamp(detail.row.updated_at) }}</div>
            </div>
          </div>
        </div>
        <template #footer>
          <NButton @click="detail.show = false">关闭</NButton>
        </template>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>

<style scoped>
.ly-page {
  min-height: 100%;
  padding: 16px;
}

.content-card :deep(.n-card__content) {
  padding: 18px;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}

.filter-type {
  width: 160px;
}

.filter-severity {
  width: 130px;
}

.filter-keyword {
  width: 280px;
}

.meta {
  font-size: 12px;
  white-space: nowrap;
}

.pager-wrap {
  display: flex;
  justify-content: flex-end;
  padding-top: 12px;
}

.config-modal {
  width: min(520px, 92vw);
}

.config-modal :deep(.n-card__content) {
  padding: 16px 20px;
}

.config-hint {
  font-size: 13px;
  line-height: 1.6;
  color: hsl(var(--muted-foreground));
}

.config-info {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 10px 12px;
  font-size: 13px;
  background: hsl(var(--muted) / 40%);
  border-radius: 8px;
}

.config-error {
  color: hsl(var(--destructive, 0 84% 60%));
}

.config-files {
  max-height: 160px;
  margin: 4px 0 0;
  padding-left: 18px;
  overflow: auto;
  font-size: 12px;
  color: hsl(var(--muted-foreground));
}

.config-note {
  font-size: 12px;
}

/* 行左侧严重度色条（与事件列表一致的视觉语言） */
:deep(.n-data-table-tr.sev-high .n-data-table-td:first-child) {
  box-shadow: inset 3px 0 0 #d03050;
}

:deep(.n-data-table-tr.sev-medium .n-data-table-td:first-child) {
  box-shadow: inset 3px 0 0 #f0a020;
}

:deep(.n-data-table-tr.sev-low .n-data-table-td:first-child) {
  box-shadow: inset 3px 0 0 #2080f0;
}

:deep(.label-ellipsis) {
  display: inline-block;
  max-width: 112px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
}

.pill-inline {
  display: inline-flex;
  gap: 3px;
  align-items: center;
}

.detail-body {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.detail-value {
  display: flex;
  gap: 8px;
  align-items: center;
}

.detail-value-icon {
  flex: none;
  font-size: 20px;
}

.detail-value-text {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 17px;
  font-weight: 600;
  word-break: break-all;
}

.detail-tags-row {
  margin-top: -6px;
}

.detail-section {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.detail-section-title {
  display: flex;
  gap: 6px;
  align-items: center;
  font-size: 13px;
  font-weight: 600;
  color: hsl(var(--muted-foreground));
}

.detail-narrative {
  padding: 10px 12px;
  font-size: 13px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-word;
  background: hsl(var(--muted) / 40%);
  border-radius: 8px;
}

.detail-desc {
  font-size: 13px;
  line-height: 1.6;
  word-break: break-word;
  color: var(--n-text-color-2, inherit);
}

.detail-kv {
  display: grid;
  grid-template-columns: 84px 1fr;
  row-gap: 6px;
  column-gap: 12px;
  font-size: 13px;
}

.detail-kv-label {
  color: hsl(var(--muted-foreground));
  white-space: nowrap;
}

.detail-kv-value {
  word-break: break-word;
}

.detail-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
}

.detail-raw-tag {
  font-size: 11px;
}

@media (max-width: 640px) {
  .ly-page {
    padding: 12px;
  }

  .filter-keyword {
    width: 100%;
  }
}
</style>
