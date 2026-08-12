<script lang="ts" setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute } from 'vue-router';

import {
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
import { assetMatchesEvent } from '#/utils/ly-asset';
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
  rows: [] as Record<string, any>[],
});

async function loadAssets() {
  try {
    assets.value = (await lyAssetList()) || [];
  } catch {
    assets.value = [];
  }
}

async function runSearch() {
  state.loading = true;
  state.searched = true;
  try {
    const query: Record<string, any> = { keyword: form.keyword || undefined };
    if (form.starttime) query.starttime = Math.floor(form.starttime / 1000);
    if (form.endtime) query.endtime = Math.floor(form.endtime / 1000);
    const res = await lyEventSearch(query);
    const rows = Array.isArray(res) ? res : [];
    const keyword = String(form.keyword || '').trim().toLowerCase();
    const asset = form.asset;
    state.rows = normalizeLyEvents(rows).filter((item) => {
      if (keyword && !JSON.stringify(item).toLowerCase().includes(keyword)) return false;
      if (asset && !assetMatchesEvent({ address: asset }, item as Record<string, any>)) return false;
      const t = Number(item.time ?? item.starttime ?? 0);
      if (form.starttime && (!t || t < form.starttime / 1000)) return false;
      if (form.endtime && (!t || t > form.endtime / 1000)) return false;
      return true;
    });
  } catch (error) {
    console.error('[ly] 搜索失败', error);
    message.error('搜索失败，请检查后端服务');
    state.rows = [];
  } finally {
    state.loading = false;
  }
}

function startSearch() {
  runSearch();
}

function resetSearch() {
  form.asset = '';
  form.keyword = '';
  form.starttime = null;
  form.endtime = null;
}

onMounted(() => {
  void loadAssets();
  const q = route.query as Record<string, any>;
  form.asset = String(q.asset ?? '');
  form.keyword = String(q.keyword ?? '');
  const startSec = Number(q.starttime);
  const endSec = Number(q.endtime);
  form.starttime = q.starttime && !Number.isNaN(startSec) ? startSec * 1000 : null;
  form.endtime = q.endtime && !Number.isNaN(endSec) ? endSec * 1000 : null;
  if (q.asset || q.keyword || q.starttime || q.endtime) {
    runSearch();
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
          <NFormItem label="开始时间">
            <NDatePicker v-model:value="form.starttime" type="datetime" clearable placeholder="选择开始时间" class="full-input" />
          </NFormItem>
          <NFormItem label="结束时间">
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
