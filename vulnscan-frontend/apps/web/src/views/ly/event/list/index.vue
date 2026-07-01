<script lang="ts" setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute } from 'vue-router';

import {
  NButton,
  NCard,
  NCheckbox,
  NSelect,
  NSpace,
  NTag,
} from 'naive-ui';

import { lyAssetList, type LyAsset } from '#/api/ly/assets';
import { assetMatchesEvent, eventMatchesAnyAsset } from '#/utils/ly-asset';

import { useLyStore } from '#/store/ly';
import { countByKey } from '#/utils/ly';

import LyEventTable from '../components/LyEventTable.vue';

defineOptions({ name: 'LyEventList' });

const route = useRoute();
const lyStore = useLyStore();

const state = reactive({
  proc_status: '',
  is_alive: '' as '' | 'false' | 'true',
  rankKey: '' as '' | 'attackDevice' | 'victimDevice' | 'typeText',
  rankValue: '',
});

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

// 基础筛选（处理状态/活跃/资产）——排行标签基于此计算，
// 保证选中某排行值后其它标签依然可见、可再切换。
const baseRows = computed(() => {
  return (lyStore.events || []).filter((item) => {
    if (state.proc_status && item.proc_status !== state.proc_status) return false;
    if (state.is_alive) {
      const alive = String(item.is_alive) === state.is_alive;
      if (!alive) return false;
    }
    if (selectedAsset.value) {
      if (!assetMatchesEvent({ address: selectedAsset.value }, item)) return false;
    } else if (onlyAssetRelated.value) {
      if (!eventMatchesAnyAsset(item, assets.value)) return false;
    }
    return true;
  });
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
  if (!lyStore.events.length) {
    await lyStore.loadEvents();
  }
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
          <NSelect v-model:value="state.proc_status" clearable placeholder="处理状态" :options="[{ label: '未处理', value: 'unprocessed' }, { label: '已处理', value: 'processed' }, { label: '已确认', value: 'assigned' }]" style="width: 160px" />
          <NSelect v-model:value="state.is_alive" clearable placeholder="活跃状态" :options="[{ label: '活跃', value: 'true' }, { label: '不活跃', value: 'false' }]" style="width: 160px" />
          <NSelect
            v-model:value="selectedAsset"
            clearable
            filterable
            placeholder="按资产筛选"
            :options="assetOptions"
            style="width: 240px"
          />
          <NCheckbox v-model:checked="onlyAssetRelated" :disabled="!!selectedAsset">
            仅看已登记资产相关事件
          </NCheckbox>
          <NButton type="primary" @click="lyStore.loadEvents()">刷新</NButton>
          <NTag v-if="state.rankKey" size="small" type="info" closable @close="clearRankFilter">
            {{ RANK_LABELS[state.rankKey] }}：{{ state.rankValue }}
          </NTag>
        </NSpace>
      </NCard>

      <NCard size="small">
        <LyEventTable :rows="filteredRows" :auto-analyze="true" :loading="lyStore.loading" />
      </NCard>
    </NSpace>
  </div>
</template>

<style scoped>
.ly-page { padding: 12px; }
.rank-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
.rank-title { margin-bottom: 8px; font-weight: 600; }
.rank-tag { cursor: pointer; }
.rank-tag--active { outline: 2px solid var(--n-color-target, #2080f0); outline-offset: 1px; font-weight: 600; }
</style>
