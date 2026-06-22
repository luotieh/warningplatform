<script lang="ts" setup>
import { computed, h, onMounted, reactive } from 'vue';

import {
  NButton,
  NCard,
  NDataTable,
  NInput,
  NModal,
  NPagination,
  NSelect,
  NSpace,
  NTag,
  NText,
  useMessage,
} from 'naive-ui';

import { lyRuleConfigGet, lyRuleConfigSave, lyRuleList } from '#/api/ly';

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
  { title: '值', key: 'value', minWidth: 220, ellipsis: { tooltip: true } },
  { title: '类别', key: 'category', width: 140 },
  {
    title: '等级',
    key: 'severity',
    width: 84,
    render: (row: Record<string, any>) => {
      const tag = severityTag(row.severity);
      return h(NTag, { size: 'small', type: tag.type }, { default: () => tag.text });
    },
  },
  { title: '来源', key: 'source', width: 130, ellipsis: { tooltip: true } },
  {
    title: '描述',
    key: 'description',
    minWidth: 280,
    ellipsis: { tooltip: true },
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
            placeholder="按值 / 描述 / 类别 / 来源搜索"
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
      :bordered="false"
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

@media (max-width: 640px) {
  .ly-page {
    padding: 12px;
  }

  .filter-keyword {
    width: 100%;
  }
}
</style>
