<script lang="ts" setup>
import { computed, onUnmounted, reactive, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { NAlert, NButton, NCard, NInput, NPagination, NSelect, NSpace, NTag } from 'naive-ui';
import { lyAssetList, type LyAsset } from '#/api/ly/assets';
import { deepflowGetEventsPage } from '#/api/ly/deepflow';
import { normalizeLyEvents } from '#/utils/ly';
import { eventAssetNames } from '#/utils/ly-asset';
import LyEventTable from '../components/LyEventTable.vue';

defineOptions({ name: 'LyEventHistory' });
const route = useRoute();
const form = reactive({ ioc: '', type: '', victim: '', mode: 'same' });
const query = ref<Record<string, any> | null>(null);
const rows = ref<Record<string, any>[]>([]);
const assets = ref<LyAsset[]>([]);
const page = ref(1);
const pageSize = ref(20);
const total = ref(0);
const loading = ref(false);
const error = ref('');
let requestId = 0;
const displayRows = computed(() => rows.value.map((row) => ({
  ...row, assetText: eventAssetNames(row, assets.value).join('、') || '未登记',
})));

async function loadHistory() {
  if (!query.value) return;
  const id = ++requestId;
  loading.value = true;
  error.value = '';
  try {
    const params = { ...query.value, scope: 'all', page: page.value, page_size: pageSize.value };
    let result = await deepflowGetEventsPage(params);
    if (id !== requestId) return;
    const maxPage = Math.max(1, Math.ceil(result.total / pageSize.value));
    if (page.value > maxPage) {
      page.value = maxPage;
      result = await deepflowGetEventsPage({ ...params, page: maxPage });
      if (id !== requestId) return;
    }
    rows.value = normalizeLyEvents(result.items);
    total.value = result.total;
  } catch (cause) {
    if (id !== requestId) return;
    rows.value = [];
    total.value = 0;
    error.value = cause instanceof Error ? cause.message : '历史事件查询失败';
  } finally {
    if (id === requestId) loading.value = false;
  }
}

function search() {
  // 默认范围必须同时指定 IOC 和被攻击方，缺少目标时不静默放宽范围。
  if (!form.ioc.trim() || (form.mode === 'same' && !form.victim.trim())) return;
  query.value = {
    ioc_value: form.ioc.trim(),
    ioc_type: form.type.trim(),
    ...(form.mode === 'same' ? { victim: form.victim.trim() } : {}),
  };
  page.value = 1;
  void loadHistory();
}

watch(() => [route.query.ioc_value, route.query.ioc_type, route.query.victim], () => {
  ++requestId;
  loading.value = false;
  query.value = null;
  rows.value = [];
  total.value = 0;
  error.value = '';
  form.ioc = typeof route.query.ioc_value === 'string' ? route.query.ioc_value : '';
  form.type = typeof route.query.ioc_type === 'string' ? route.query.ioc_type : '';
  form.victim = typeof route.query.victim === 'string' ? route.query.victim : '';
  form.mode = 'same';
  search();
}, { immediate: true });

function changeMode() { search(); }
function changePage(value: number) { page.value = value; void loadHistory(); }
function changePageSize(value: number) { pageSize.value = value; page.value = 1; void loadHistory(); }

void lyAssetList().then((result) => { assets.value = result || []; }).catch(() => {});
onUnmounted(() => { ++requestId; });
</script>

<template>
  <div class="history-page">
    <NSpace vertical :size="12">
      <NCard title="IOC 历史事件查询" size="small">
        <NSpace>
          <NInput v-model:value="form.ioc" clearable placeholder="IOC 命中值（精确匹配）" style="width: 280px" @keyup.enter="search" />
          <NInput v-model:value="form.type" clearable placeholder="IOC 类型（可选）" style="width: 160px" @keyup.enter="search" />
          <NSelect
            v-model:value="form.mode"
            :options="[{ label: '同 IOC、同被攻击方', value: 'same' }, { label: '该 IOC 所有事件', value: 'all' }]"
            style="width: 220px"
            @update:value="changeMode"
          />
          <NInput v-model:value="form.victim" :disabled="form.mode === 'all'" clearable placeholder="被攻击方 IP / 域名" style="width: 240px" @keyup.enter="search" />
          <NButton type="primary" :loading="loading" :disabled="!form.ioc.trim() || (form.mode === 'same' && !form.victim.trim())" @click="search">查询</NButton>
        </NSpace>
        <p class="history-hint">查询全部时间，包含已归档事件及当前事件。默认仅查看同 IOC、同被攻击方；可切换查看该 IOC 所有事件。</p>
        <NSpace v-if="query">
          <NTag type="info">IOC：{{ query.ioc_value }}</NTag>
          <NTag v-if="query.ioc_type">类型：{{ query.ioc_type }}</NTag>
          <NTag>{{ query.victim ? `被攻击方：${query.victim}` : '全部被攻击方' }}</NTag>
        </NSpace>
      </NCard>
      <NAlert v-if="error" type="error">{{ error }}</NAlert>
      <NAlert v-else-if="!query" type="info">请输入 IOC 和被攻击方，或选择“该 IOC 所有事件”后查询。</NAlert>
      <NCard v-if="query" :title="`历史事件（${total}）`" size="small">
        <LyEventTable :rows="displayRows" :loading="loading" :show-asset="true" :assets="assets" />
        <div class="history-pager">
          <NPagination :page="page" :page-size="pageSize" :item-count="total" show-size-picker :page-sizes="[20, 50, 100]" @update:page="changePage" @update:page-size="changePageSize" />
        </div>
      </NCard>
    </NSpace>
  </div>
</template>

<style scoped>
.history-page { padding: 12px; }
.history-hint { color: #808080; font-size: 13px; margin: 12px 0; }
.history-pager { display: flex; justify-content: flex-end; padding-top: 12px; }
</style>
