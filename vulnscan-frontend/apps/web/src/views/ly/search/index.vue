<script lang="ts" setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute } from 'vue-router';

import {
  NPagination,
  NButton,
  NCard,
  NDatePicker,
  NForm,
  NFormItem,
  NInput,
  NSelect,
  NSpace,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import { lyEventSearch } from '#/api/ly';
import { lyAssetList, type LyAsset } from '#/api/ly/assets';
import { normalizeLyEvents } from '#/utils/ly';
import { epochToPickerTime, pickerTimeToEpoch } from '#/utils/ly-query-time';
import LyEventTable from '../event/components/LyEventTable.vue';

defineOptions({ name: 'LySearch' });

const route = useRoute();

const form = reactive({
  asset: '',
  keyword: '',
  starttime: null as null | number,
  endtime: null as null | number,
});

const assets = ref<LyAsset[]>([]);
const assetOptions = computed(() =>
  assets.value.map((a) => ({ label: `${a.name}（${a.address}）`, value: a.address })),
);

const state = reactive({
  loading: false,
  searched: false,
  page: 1,
  pageSize: 20,
  total: 0,
  rows: [] as Record<string, any>[],
});

async function loadAssets() {
  try {
    assets.value = (await lyAssetList()) || [];
  } catch {
    assets.value = [];
  }
}

let searchRequestId = 0;
let submittedQuery: Record<string, any> = {};

async function runSearch() {
  const requestId = ++searchRequestId;
  state.loading = true;
  state.searched = true;
  try {
    const res = await lyEventSearch({ ...submittedQuery, scope: 'all', page: state.page, page_size: state.pageSize });
    if (requestId !== searchRequestId) return;
    state.rows = normalizeLyEvents(Array.isArray(res?.items) ? res.items : []);
    state.total = Number(res?.total || 0);
    const maxPage = Math.max(1, Math.ceil(state.total / state.pageSize));
    if (state.page > maxPage) { state.page = maxPage; await runSearch(); }
  } catch (error) {
    if (requestId !== searchRequestId) return;
    message.error(error instanceof Error ? error.message : '搜索失败，请检查后端服务');
    state.rows = [];
    state.total = 0;
  } finally {
    if (requestId === searchRequestId) state.loading = false;
  }
}

function startSearch() {
  const query: Record<string, any> = {};
  if (form.keyword.trim()) query.keyword = form.keyword.trim();
  if (form.asset) query.asset = form.asset;
  if (form.starttime !== null) query.starttime = Math.floor(pickerTimeToEpoch(form.starttime) / 1000);
  if (form.endtime !== null) query.endtime = Math.floor(pickerTimeToEpoch(form.endtime) / 1000);
  if (query.starttime !== undefined && query.endtime !== undefined && query.starttime >= query.endtime) {
    message.error('开始时间必须早于结束时间');
    return;
  }
  submittedQuery = query;
  state.page = 1;
  void runSearch();
}

function onPageChange(page: number) { state.page = page; void runSearch(); }
function onPageSizeChange(size: number) { state.pageSize = size; state.page = 1; void runSearch(); }

function resetSearch() {
  searchRequestId++;
  form.asset = '';
  form.keyword = '';
  form.starttime = null;
  form.endtime = null;
  submittedQuery = {};
  state.rows = [];
  state.page = 1;
  state.total = 0;
  state.loading = false;
  state.searched = false;
}

onMounted(() => {
  void loadAssets();
  const q = route.query as Record<string, any>;
  form.asset = String(q.asset ?? '');
  form.keyword = String(q.keyword ?? '');
  const startSec = Number(q.starttime);
  const endSec = Number(q.endtime);
  form.starttime = q.starttime && !Number.isNaN(startSec) ? epochToPickerTime(startSec * 1000) : null;
  form.endtime = q.endtime && !Number.isNaN(endSec) ? epochToPickerTime(endSec * 1000) : null;
  if (q.asset || q.keyword || q.starttime || q.endtime) {
    startSearch();
  }
});
</script>

<template>
  <div class="ly-page">
    <NCard title="全局搜索引擎" size="small" class="search-card">
      <NForm label-placement="left" label-width="90">
        <div class="form-grid">
          <NFormItem label="资产">
            <NSelect
              v-model:value="form.asset"
              clearable
              filterable
              placeholder="选择已登记资产"
              :options="assetOptions"
              class="full-input"
            />
          </NFormItem>
          <NFormItem label="关键字">
            <NInput v-model:value="form.keyword" placeholder="可选" />
          </NFormItem>
          <NFormItem label="开始（北京）">
            <NDatePicker v-model:value="form.starttime" type="datetime" clearable placeholder="选择开始时间" class="full-input" />
          </NFormItem>
          <NFormItem label="结束（北京）">
            <NDatePicker v-model:value="form.endtime" type="datetime" clearable placeholder="选择结束时间" class="full-input" />
          </NFormItem>
        </div>
      </NForm>
      <NSpace justify="center">
        <NButton type="primary" :loading="state.loading" @click="startSearch">搜索</NButton>
        <NButton @click="resetSearch">重置</NButton>
      </NSpace>
    </NCard>

    <NCard v-if="state.searched" class="result-card" title="搜索结果" size="small">
      <LyEventTable :rows="state.rows" :show-desc="true" :auto-analyze="false" :loading="state.loading" />
      <NPagination :page="state.page" :page-size="state.pageSize" :item-count="state.total"
        show-size-picker :page-sizes="[20, 50, 100]" :disabled="state.loading"
        @update:page="onPageChange" @update:page-size="onPageSizeChange" />
    </NCard>
  </div>
</template>

<style scoped>
.ly-page { min-height: 100%; padding: 16px; }
.search-card { margin-bottom: 16px; }
.form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 16px; }
.full-input { width: 100%; }
.result-card :deep(.n-card__content) { padding: 18px; }
@media (max-width: 640px) {
  .ly-page { padding: 12px; }
  .form-grid { grid-template-columns: 1fr; }
}
</style>
