<script lang="ts" setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute } from 'vue-router';

import {
  NButton,
  NCard,
  NCheckbox,
  NDatePicker,
  NInput,
  NPagination,
  NSelect,
  NSpace,
  NTag,
} from 'naive-ui';

import { lyAssetList, type LyAsset } from '#/api/ly/assets';
import {
  assetMatchesEvent,
  assetOptionFilter,
  eventMatchesAnyAsset,
} from '#/utils/ly-asset';

import { useLyStore } from '#/store/ly';
import { countByKey, matchesEventKeyword } from '#/utils/ly';
import { eventAssetNames } from '#/utils/ly-asset';

import LyEventTable from '../components/LyEventTable.vue';

defineOptions({ name: 'LyEventList' });

const route = useRoute();
const lyStore = useLyStore();

const state = reactive({
  level: '',
  starttime: null as null | number,
  endtime: null as null | number,
  keyword: '',
  scope: 'today' as 'today' | 'archive',
  archiveDate: null as null | number,
  page: 1,
  pageSize: 20,
  total: 0,
  rankKey: '' as '' | 'attackDevice' | 'victimDevice' | 'typeText',
  rankValue: '',
  // 排序：time=时间倒序（默认）/ payload=总载荷大小 / frequency=命中频次
  sort: 'time' as 'time' | 'payload' | 'frequency',
  order: 'desc' as 'desc' | 'asc',
});

const sortOptions = [
  { label: '时间', value: 'time' },
  { label: '总载荷大小', value: 'payload' },
  { label: '命中频次', value: 'frequency' },
];
const orderOptions = [
  { label: '降序', value: 'desc' },
  { label: '升序', value: 'asc' },
];

const levelOptions = [
  { label: '高危', value: 'high' },
  { label: '中危', value: 'medium' },
  { label: '低危', value: 'low' },
];

const assets = ref<LyAsset[]>([]);
const selectedAsset = ref<string>((route.query.asset as string) || '');
const onlyAssetRelated = ref(false);

const assetOptions = computed(() =>
  assets.value.map((a) => ({ label: `${a.name}（${a.address}）`, value: a.address })),
);

async function loadAssets() {
  try {
    assets.value = (await lyAssetList()) || [];
  } catch {
    assets.value = [];
  }
}

function formatDay(ts: number | null | undefined) {
  if (!ts) return '';
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

async function loadEvents() {
  const params: Record<string, any> = {
    scope: state.scope,
    page: state.page,
    page_size: state.pageSize,
  };
  if (state.level) params.level = state.level;
  if (state.keyword.trim()) params.keyword = state.keyword.trim();
  if (selectedAsset.value) params.asset = selectedAsset.value;
  if (state.starttime) params.starttime = Math.floor(state.starttime / 1000);
  if (state.endtime) params.endtime = Math.floor(state.endtime / 1000);
  if (state.scope === 'archive') params.date = formatDay(state.archiveDate) || formatDay(Date.now());
  // 服务端排序（分页前生效），默认 time/desc 与现状一致
  if (state.sort !== 'time' || state.order !== 'desc') {
    params.sort = state.sort;
    params.order = state.order;
  }
  await lyStore.loadEvents(params);
  state.total = lyStore.eventTotal;
  const maxPage = Math.max(1, Math.ceil(state.total / state.pageSize));
  if (state.page > maxPage) {
    state.page = maxPage;
    await lyStore.loadEvents({ ...params, page: state.page });
  }
}

function onScopeChange() {
  state.page = 1;
  void loadEvents();
}

function onPageChange(page: number) {
  state.page = page;
  void loadEvents();
}

// 排序变更：回到第 1 页并按新排序重新加载（服务端分页前排序）。
function onSortChange() {
  state.page = 1;
  void loadEvents();
}

// 基础筛选（处理状态/活跃/资产）——排行标签基于此计算，
// 保证选中某排行值后其它标签依然可见、可再切换。
const baseRows = computed(() => {
  const rows = (lyStore.events || []).filter((item) => {
    if (state.level && item.level !== state.level) return false;
    if (state.starttime || state.endtime) {
      const t = Number(item.starttime ?? 0) * 1000;
      if (state.starttime && (!t || t < state.starttime)) return false;
      if (state.endtime && (!t || t > state.endtime)) return false;
    }
    if (state.keyword.trim() && !matchesEventKeyword(item, state.keyword)) return false;
    if (selectedAsset.value) {
      if (!assetMatchesEvent({ address: selectedAsset.value }, item)) return false;
    } else if (onlyAssetRelated.value) {
      if (!eventMatchesAnyAsset(item, assets.value)) return false;
    }
    return true;
  });
  // 资产归属：来源/目标命中启用资产显示资产名，否则「未登记」（新增行字段供表格展示）
  return rows.map(
    (item): Record<string, any> => ({
      ...item,
      assetText: eventAssetNames(item, assets.value).join('、') || '未登记',
    }),
  );
});
// 叠加"事件排行筛选"后的最终列表（表格与分页用）。
const filteredRows = computed(() => {
  if (!state.rankKey || !state.rankValue) return baseRows.value;
  return baseRows.value.filter(
    (item) => String(item[state.rankKey] ?? '') === state.rankValue,
  );
});
const attackRank = computed(() => countByKey(baseRows.value, 'attackDevice').slice(0, 8));
const victimRank = computed(() => countByKey(baseRows.value, 'victimDevice').slice(0, 8));
const typeRank = computed(() => countByKey(baseRows.value, 'typeText').slice(0, 8));

const RANK_LABELS: Record<string, string> = {
  attackDevice: '威胁来源',
  victimDevice: '受害目标',
  typeText: '事件类型',
};

type RankKey = 'attackDevice' | 'victimDevice' | 'typeText';

function isRankActive(key: RankKey, value: string) {
  return state.rankKey === key && state.rankValue === value;
}

// 点击排行标签：在当前列表内筛选（不跳转）；再次点同一标签则取消。
function rankFilter(key: RankKey, value: string) {
  if (isRankActive(key, value)) {
    clearRankFilter();
    return;
  }
  state.rankKey = key;
  state.rankValue = value;
}

function clearRankFilter() {
  state.rankKey = '';
  state.rankValue = '';
}

onMounted(async () => {
  await loadEvents();
  void loadAssets();
});
</script>

<template>
  <div class="ly-page">
    <NSpace vertical :size="12">
      <NCard title="事件排行筛选" size="small">
        <div class="rank-grid">
          <div>
            <div class="rank-title">威胁来源</div>
            <NSpace>
              <NTag v-for="item in attackRank" :key="item.name" size="small" class="rank-tag" :class="{ 'rank-tag--active': isRankActive('attackDevice', item.name) }" @click="rankFilter('attackDevice', item.name)">
                {{ item.name }} ({{ item.value }})
              </NTag>
            </NSpace>
          </div>
          <div>
            <div class="rank-title">受害目标</div>
            <NSpace>
              <NTag v-for="item in victimRank" :key="item.name" size="small" type="success" class="rank-tag" :class="{ 'rank-tag--active': isRankActive('victimDevice', item.name) }" @click="rankFilter('victimDevice', item.name)">
                {{ item.name }} ({{ item.value }})
              </NTag>
            </NSpace>
          </div>
          <div>
            <div class="rank-title">事件类型</div>
            <NSpace>
              <NTag v-for="item in typeRank" :key="item.name" size="small" type="warning" class="rank-tag" :class="{ 'rank-tag--active': isRankActive('typeText', item.name) }" @click="rankFilter('typeText', item.name)">
                {{ item.name }} ({{ item.value }})
              </NTag>
            </NSpace>
          </div>
        </div>
      </NCard>

      <NCard size="small">
        <NSpace>
          <NSelect
            v-model:value="state.scope"
            :options="[
              { label: '今日视图', value: 'today' },
              { label: '历史归档', value: 'archive' },
            ]"
            style="width: 130px"
            @update:value="onScopeChange"
          />
          <NDatePicker
            v-if="state.scope === 'archive'"
            v-model:value="state.archiveDate"
            type="date"
            clearable
            placeholder="归档日期"
            style="width: 150px"
            @update:value="onScopeChange"
          />
          <NSelect v-model:value="state.level" clearable placeholder="严重级别" :options="levelOptions" style="width: 140px" />
          <NDatePicker v-model:value="state.starttime" type="date" clearable placeholder="开始日期" style="width: 150px" />
          <NDatePicker v-model:value="state.endtime" type="date" clearable placeholder="结束日期" style="width: 150px" />
          <NInput
            v-model:value="state.keyword"
            clearable
            placeholder="关键字/IP（空格分词，如 c2 185.230）"
            style="width: 260px"
          />
          <NSelect
            v-model:value="selectedAsset"
            clearable
            filterable
            :filter="assetOptionFilter"
            placeholder="按资产筛选"
            :options="assetOptions"
            style="width: 240px"
          />
          <NCheckbox v-model:checked="onlyAssetRelated" :disabled="!!selectedAsset">
            仅看已登记资产相关事件
          </NCheckbox>
          <NSelect
            v-model:value="state.sort"
            :options="sortOptions"
            style="width: 140px"
            @update:value="onSortChange"
          />
          <NSelect
            v-model:value="state.order"
            :options="orderOptions"
            style="width: 100px"
            @update:value="onSortChange"
          />
          <NButton type="primary" @click="loadEvents">刷新</NButton>
          <NTag v-if="state.rankKey" size="small" type="info" closable @close="clearRankFilter">
            {{ RANK_LABELS[state.rankKey] }}：{{ state.rankValue }}
          </NTag>
        </NSpace>
      </NCard>

      <NCard size="small">
        <LyEventTable
          :rows="filteredRows"
          :auto-analyze="true"
          :loading="lyStore.loading"
          :show-asset="true"
        />
        <div class="pager-wrap">
          <NPagination
            v-model:page="state.page"
            :item-count="state.total"
            :page-size="state.pageSize"
            show-size-picker
            :page-sizes="[20, 50, 100]"
            @update:page="onPageChange"
            @update:page-size="(size: number) => { state.pageSize = size; state.page = 1; void loadEvents(); }"
          />
        </div>
      </NCard>
    </NSpace>
  </div>
</template>

<style scoped>
.ly-page { padding: 12px; }
.pager-wrap { display: flex; justify-content: flex-end; padding-top: 12px; }
.rank-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
.rank-title { margin-bottom: 8px; font-weight: 600; }
.rank-tag { cursor: pointer; }
.rank-tag--active { outline: 2px solid var(--n-color-target, #2080f0); outline-offset: 1px; font-weight: 600; }
</style>
