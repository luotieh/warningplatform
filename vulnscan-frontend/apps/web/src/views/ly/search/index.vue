<script lang="ts" setup>
import { computed, h, onMounted, reactive, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import {
  NButton,
  NCard,
  NDataTable,
  NDatePicker,
  NForm,
  NFormItem,
  NInput,
  NPagination,
  NSpace,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import { lyEventSearch } from '#/api/ly';
import { normalizeLyEvents, paginate } from '#/utils/ly';

defineOptions({ name: 'LySearch' });

const route = useRoute();
const router = useRouter();

const form = reactive({
  devid: '',
  keyword: '',
  // 时间选择器返回毫秒时间戳；提交时转换为秒
  starttime: null as null | number,
  endtime: null as null | number,
});

const state = reactive({
  loading: false,
  searched: false,
  rows: [] as Record<string, any>[],
  page: 1,
  pageSize: 10,
});

const pagedRows = computed(() =>
  paginate(state.rows, state.page, state.pageSize),
);

watch(
  () => state.rows.length,
  () => {
    const max = Math.max(1, Math.ceil(state.rows.length / state.pageSize));
    if (state.page > max) state.page = max;
  },
);

const columns = [
  { title: 'ID', key: 'id', width: 90 },
  { title: '事件类型', key: 'typeText', width: 120 },
  { title: '描述', key: 'desc', ellipsis: { tooltip: true } },
  { title: '等级', key: 'levelText', width: 100 },
  { title: '处理状态', key: 'procStatusText', width: 120 },
  {
    title: '操作',
    key: 'actions',
    width: 100,
    render: (row: Record<string, any>) =>
      h(
        NButton,
        {
          size: 'small',
          text: true,
          type: 'primary',
          onClick: () => router.push('/ly/event/list'),
        },
        { default: () => `查看 ${row.id}` },
      ),
  },
];

async function runSearch() {
  state.loading = true;
  state.searched = true;
  try {
    const query: Record<string, any> = {
      devid: form.devid || undefined,
      keyword: form.keyword || undefined,
    };
    if (form.starttime) query.starttime = Math.floor(form.starttime / 1000);
    if (form.endtime) query.endtime = Math.floor(form.endtime / 1000);
    const res = await lyEventSearch(query);
    const rows = Array.isArray(res) ? res : [];
    const keyword = String(form.keyword || '').trim().toLowerCase();
    state.rows = normalizeLyEvents(rows).filter((item) => {
      if (!keyword) return true;
      return JSON.stringify(item).toLowerCase().includes(keyword);
    });
    state.page = 1;
  } catch (error) {
    console.error('[ly] 搜索失败', error);
    message.error('搜索失败，请检查后端服务');
    state.rows = [];
  } finally {
    state.loading = false;
  }
}

function startSearch() {
  // 仅刷新搜索结果，不再改动路由（避免触发整页过渡导致搜索表单一起刷新）
  state.page = 1;
  runSearch();
}

function resetSearch() {
  form.devid = '';
  form.keyword = '';
  form.starttime = null;
  form.endtime = null;
}

onMounted(() => {
  // 支持从事件列表/总览等页面携带查询条件跳转过来时自动检索（URL 中的时间戳为秒）
  const q = route.query as Record<string, any>;
  form.devid = String(q.devid ?? '');
  form.keyword = String(q.keyword ?? '');
  const startSec = Number(q.starttime);
  const endSec = Number(q.endtime);
  form.starttime = q.starttime && !Number.isNaN(startSec) ? startSec * 1000 : null;
  form.endtime = q.endtime && !Number.isNaN(endSec) ? endSec * 1000 : null;
  if (q.devid || q.keyword || q.starttime || q.endtime) {
    runSearch();
  }
});
</script>

<template>
  <div class="ly-page">
    <NCard title="全局搜索引擎" size="small" class="search-card">
      <NForm label-placement="left" label-width="90">
        <div class="form-grid">
          <NFormItem label="设备ID">
            <NInput v-model:value="form.devid" placeholder="可选" />
          </NFormItem>
          <NFormItem label="关键字">
            <NInput v-model:value="form.keyword" placeholder="可选" />
          </NFormItem>
          <NFormItem label="开始时间">
            <NDatePicker
              v-model:value="form.starttime"
              type="datetime"
              clearable
              placeholder="选择开始时间"
              class="full-input"
            />
          </NFormItem>
          <NFormItem label="结束时间">
            <NDatePicker
              v-model:value="form.endtime"
              type="datetime"
              clearable
              placeholder="选择结束时间"
              class="full-input"
            />
          </NFormItem>
        </div>
      </NForm>
      <NSpace justify="center">
        <NButton type="primary" :loading="state.loading" @click="startSearch">
          搜索
        </NButton>
        <NButton @click="resetSearch">重置</NButton>
      </NSpace>
    </NCard>

    <NCard
      v-if="state.searched"
      class="result-card"
      title="搜索结果"
      size="small"
    >
      <NDataTable
        :columns="columns"
        :data="pagedRows"
        :loading="state.loading"
        :bordered="true"
        size="small"
      />
      <div class="pager-wrap">
        <NPagination
          v-model:page="state.page"
          v-model:page-size="state.pageSize"
          :item-count="state.rows.length"
          show-size-picker
          show-quick-jumper
          :page-sizes="[10, 20, 50, 100]"
        />
      </div>
    </NCard>
  </div>
</template>

<style scoped>
.ly-page {
  min-height: 100%;
  padding: 16px;
}

.search-card {
  margin-bottom: 16px;
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 16px;
}

.full-input {
  width: 100%;
}

.result-card :deep(.n-card__content) {
  padding: 18px;
}

.pager-wrap {
  display: flex;
  justify-content: flex-end;
  padding-top: 12px;
}

@media (max-width: 640px) {
  .ly-page {
    padding: 12px;
  }

  .form-grid {
    grid-template-columns: 1fr;
  }
}
</style>
