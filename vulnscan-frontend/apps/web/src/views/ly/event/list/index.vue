<script lang="ts" setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue';
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
import deepflowSocket from '#/utils/deepflow-socket';
import { assetOptionFilter } from '#/utils/ly-asset';

import { useLyStore } from '#/store/ly';
import { eventAssetNames } from '#/utils/ly-asset';
import { deepflowGetEventRank, type EventRankResult } from '#/api/ly/deepflow';

import LyEventTable from '../components/LyEventTable.vue';
import { type ArchivePeriod } from './archive-filter';

defineOptions({ name: 'LyEventList' });

const route = useRoute();
const lyStore = useLyStore();

// 事件排行统计（服务端按基础过滤条件在全量结果上计数，与列表筛选同口径）。
const ranks = ref<EventRankResult>({ attackDevice: [], victimDevice: [], typeText: [] });

const state = reactive({
  level: '',
  starttime: null as null | number,
  endtime: null as null | number,
  keyword: '',
  scope: 'all' as 'all' | 'today' | '3' | '7',
  archivePeriod: 'all' as ArchivePeriod,
  archiveRange: null as [string, string] | null,
  page: 1,
  pageSize: 20,
  total: 0,
  rankKey: '' as '' | 'attackDevice' | 'victimDevice' | 'typeText',
  rankValue: '',
  // 排序：time=时间倒序（默认）/ payload=总载荷大小 / frequency=命中频次
  // 排序：time=时间倒序（默认）/ payload=总载荷大小 / frequency=命中频次 / probability=研判概率
  sort: 'time' as 'time' | 'payload' | 'frequency' | 'probability',
  order: 'desc' as 'desc' | 'asc',
});

const sortOptions = [
  { label: '创建时间', value: 'time' },
  { label: '总载荷大小', value: 'payload' },
  { label: '命中频次', value: 'frequency' },
  { label: '研判概率', value: 'probability' },
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

let listRequestId = 0;

async function loadEvents() {
  const requestId = ++listRequestId;
  const params: Record<string, any> = {
    scope: state.scope,
    page: state.page,
    page_size: state.pageSize,
  };
  if (state.level) params.level = state.level;
  if (state.keyword.trim()) params.keyword = state.keyword.trim();
  if (selectedAsset.value) params.asset = selectedAsset.value;
  else if (onlyAssetRelated.value) params.only_asset_related = true;
  if (state.starttime || state.endtime) {
    // 自定义日期按事件开始时间过滤（可只选一端）：
    // 只选开始=列出该日及以后开始的事件，只选结束=列出该日及之前开始的事件
    // （结束日期按整日包含：date 选择器返回当天 00:00，后端区间为上界开，需 +1 天）。
    // 与快捷范围互斥，由 onCustomDateChange 保证 scope 已复位为默认值。
    if (state.starttime) params.starttime = Math.floor(state.starttime / 1000);
    if (state.endtime) params.endtime = Math.floor((state.endtime + 86400000) / 1000);
  } else if (state.scope === 'today' || state.scope === '3' || state.scope === '7') {
    const days = state.scope === 'today' ? 1 : Number(state.scope);
    const end = new Date();
    const start = new Date(end);
    start.setDate(start.getDate() - (days - 1));
    start.setHours(0, 0, 0, 0);
    params.starttime = Math.floor(start.getTime() / 1000);
    params.endtime = Math.floor(end.getTime() / 1000);
  }
  // 服务端排序（分页前生效），默认 time/desc 与现状一致
  if (state.sort !== 'time' || state.order !== 'desc') {
    params.sort = state.sort;
    params.order = state.order;
  }
  // 排行维度筛选随查询下发，由服务端按展示口径过滤分页。
  if (state.rankKey && state.rankValue) {
    params.rank_key = state.rankKey;
    params.rank_value = state.rankValue;
  }
  // 排行统计与列表共用基础过滤条件（不含分页/排序/排行筛选本身），
  // 服务端在全量结果上计数，标签数字与点击后的列表总数一致。
  const rankParams: Record<string, any> = { ...params };
  for (const key of ['page', 'page_size', 'sort', 'order', 'rank_key', 'rank_value']) {
    delete rankParams[key];
  }
  const [, rankResult] = await Promise.all([
    lyStore.loadEvents(params),
    deepflowGetEventRank(rankParams).catch(() => null),
  ]);
  if (requestId !== listRequestId) return;
  if (rankResult) {
    ranks.value = {
      attackDevice: rankResult.attackDevice || [],
      victimDevice: rankResult.victimDevice || [],
      typeText: rankResult.typeText || [],
    };
  }
  state.total = lyStore.eventTotal;
  const maxPage = Math.max(1, Math.ceil(state.total / state.pageSize));
  if (state.page > maxPage) {
    state.page = maxPage;
    await lyStore.loadEvents({ ...params, page: state.page });
    if (requestId !== listRequestId) return;
    state.total = lyStore.eventTotal;
  }
}

// 基础筛选变化时重置页码和排行条件，列表与总数使用同一次服务端筛选。
watch([() => state.keyword.trim(), () => state.level, selectedAsset, onlyAssetRelated], () => {
  state.page = 1;
  clearRankFilter();
  void loadEvents();
});

async function refreshEvents() {
  state.page = 1;
  await loadEvents();
}

function onScopeChange() {
  // 快捷范围与自定义日期互斥：选快捷范围时清空自定义日期。
  state.starttime = null;
  state.endtime = null;
  state.archivePeriod = 'all';
  state.archiveRange = null;
  state.sort = 'time';
  state.order = 'desc';
  clearRankFilter();
  onArchiveFilterChange();
}

// 自定义日期（按事件开始时间过滤）与快捷范围互斥：
// 选了日期就把快捷范围复位为默认（全部时间），清空（clear）则保持现状。
function onCustomDateChange() {
  if (state.starttime || state.endtime) {
    state.scope = 'all';
  }
  onArchiveFilterChange();
}

function onArchiveFilterChange() {
  state.page = 1;
  clearRankFilter();
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

// 基础筛选由服务端完成；这里只补充资产名称供表格展示。
const baseRows = computed(() => {
  // 所有查询筛选在服务端分页前完成，当前页不再删行，以免总数与展示不一致。
  const rows = lyStore.events || [];
  // 资产归属：来源/目标命中启用资产显示资产名，否则「未登记」（新增行字段供表格展示）
  return rows.map(
    (item): Record<string, any> => ({
      ...item,
      assetText: eventAssetNames(item, assets.value).join('、') || '未登记',
    }),
  );
});
// 排行筛选已由服务端完成（rank_key/rank_value 随查询下发），前端不再二次过滤。
const filteredRows = computed(() => baseRows.value);
// 排行统计来自服务端全量计数（与列表筛选同口径），不再按当前页估算。
const attackRank = computed(() => ranks.value.attackDevice);
const victimRank = computed(() => ranks.value.victimDevice);
const typeRank = computed(() => ranks.value.typeText);

const RANK_LABELS: Record<string, string> = {
  attackDevice: '威胁来源',
  victimDevice: '受害目标',
  typeText: '事件类型',
};

type RankKey = 'attackDevice' | 'victimDevice' | 'typeText';

function isRankActive(key: RankKey, value: string) {
  return state.rankKey === key && state.rankValue === value;
}

// 点击排行标签：按服务端筛选并回到第 1 页（不跳转）；再次点同一标签则取消。
function rankFilter(key: RankKey, value: string) {
  if (isRankActive(key, value)) {
    clearRankFilter();
  } else {
    state.rankKey = key;
    state.rankValue = value;
  }
  state.page = 1;
  void loadEvents();
}

function clearRankFilter() {
  state.rankKey = '';
  state.rankValue = '';
}

function onRankTagClose() {
  clearRankFilter();
  state.page = 1;
  void loadEvents();
}

// 订阅事件列表广播：分析完成/失败等行级状态变化时防抖刷新当前页，
// 研判概率、分析状态等列无需手动刷新即可看到最新值。
let listUpdateTimer: ReturnType<typeof setTimeout> | undefined;
const handleEventListUpdate = () => {
  clearTimeout(listUpdateTimer);
  listUpdateTimer = setTimeout(() => void loadEvents(), 800);
};

onMounted(async () => {
  deepflowSocket.connect();
  deepflowSocket.join('events');
  deepflowSocket.on('event_list_update', handleEventListUpdate);
  await loadEvents();
  void loadAssets();
});

onUnmounted(() => {
  clearTimeout(listUpdateTimer);
  deepflowSocket.off('event_list_update', handleEventListUpdate);
  deepflowSocket.leave('events');
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
              { label: '全部时间', value: 'all' },
              { label: '仅看今日', value: 'today' },
              { label: '近三天', value: '3' },
              { label: '近七天', value: '7' },
            ]"
            style="width: 130px"
            @update:value="onScopeChange"
          />
          <NSelect
            v-if="false"
            v-model:value="state.archivePeriod"
            :options="[
              { label: '全部归档', value: 'all' },
              { label: '过去三天', value: '3' },
              { label: '过去七天', value: '7' },
              { label: '自定义时间段', value: 'custom' },
            ]"
            style="width: 160px"
            @update:value="onArchiveFilterChange"
          />
          <NDatePicker
            v-if="false && state.archivePeriod === 'custom'"
            v-model:formatted-value="state.archiveRange"
            type="daterange"
            value-format="yyyy-MM-dd"
            clearable
            start-placeholder="归档开始日期"
            end-placeholder="归档结束日期"
            style="width: 280px"
            @update:formatted-value="onArchiveFilterChange"
          />
          <NSelect v-model:value="state.level" clearable placeholder="严重级别" :options="levelOptions" style="width: 140px" />
          <NDatePicker v-model:value="state.starttime" type="date" clearable placeholder="开始日期" style="width: 150px" @update:value="onCustomDateChange" />
          <NDatePicker v-model:value="state.endtime" type="date" clearable placeholder="结束日期" style="width: 150px" @update:value="onCustomDateChange" />
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
          <NButton type="primary" :loading="lyStore.loading" @click="refreshEvents">刷新</NButton>
          <NTag v-if="state.rankKey" size="small" type="info" closable @close="onRankTagClose">
            {{ RANK_LABELS[state.rankKey] }}：{{ state.rankValue }}
          </NTag>
        </NSpace>
        <div v-if="false" class="mt-2 text-xs text-muted-foreground">
          按归档日期筛选，范围包含起止日期；过去三天、七天包含今天（北京时间）。不选日期时显示全部归档。
        </div>
      </NCard>

      <NCard size="small">
        <LyEventTable
          :rows="filteredRows"
          :auto-analyze="true"
          :loading="lyStore.loading"
          :show-asset="true"
          :assets="assets"
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
