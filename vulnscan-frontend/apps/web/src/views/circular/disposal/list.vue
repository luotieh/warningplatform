<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';
import dayjs from 'dayjs';
import { NButton, NCard, NDataTable, NSpace, NTag, NInput, NModal, NForm, NFormItem, NDatePicker, useMessage } from 'naive-ui';
import OrganizeTreeSelect from '#/components/organize/OrganizeTreeSelect.vue';
import { useRouter } from 'vue-router';
import {
  getDisposalList,
  redistributeCircular,
  getInputDetail,
  type CircularItem,
  CircularStatusLabels,
  CircularStatusTypes,
} from '#/api/circular';
import { useCircularOrganizeMaps } from '../composables/use-circular-organize';
import { extractCircularUnitHint, formatCircularTime } from '../utils';

defineOptions({ name: 'CircularDisposalList' });

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const data = ref<CircularItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const showRedist = ref(false);
const redistForm = ref({ circular_id: '', target_organize: null as string | null, processing_deadline: null as number | null });
const { ensureLoaded, resolveOrganizeId } = useCircularOrganizeMaps();

const columns = computed(() => [
  { title: '通报编号', key: 'code', width: 160, ellipsis: { tooltip: true } },
  { title: '标题', key: 'title', minWidth: 200 },
  { title: '状态', key: 'status', width: 100, render: (row: CircularItem) => h(NTag, { size: 'small', type: (CircularStatusTypes[row.status]||'default') as any, bordered: false }, () => CircularStatusLabels[row.status] ?? row.status) },
  { title: '所属组织', key: 'organize', width: 140, ellipsis: { tooltip: true } },
  {
    title: '处置期限',
    key: 'processing_deadline',
    width: 172,
    render: (row: CircularItem) => {
      const text = formatCircularTime(row.processing_deadline);
      if (!text || text === '-') return '-';
      const overdue = row.processing_deadline ? new Date(row.processing_deadline) < new Date() : false;
      return h('span', { style: overdue ? 'color:#d03050;font-weight:600;white-space:nowrap;font-size:13px' : 'white-space:nowrap;font-size:13px' }, [
        text,
        overdue ? h(NTag, { size: 'tiny', type: 'error', bordered: false, style: 'margin-left:4px' }, () => '超期') : null,
      ]);
    },
  },
  {
    title: '创建时间',
    key: 'created_at',
    width: 172,
    render: (row: CircularItem) => h('span', { style: 'white-space:nowrap;font-size:13px' }, formatCircularTime(row.created_at)),
  },
  { title: '操作', key: 'actions', width: 150, fixed: 'right' as const, render: (row: CircularItem) => h(NSpace, { size: 4 }, () => [
    h(NButton, { size: 'tiny', type: 'primary', onClick: () => router.push(`/circular/disposal/${row.id}`) }, () => '处置'),
    h(NButton, { size: 'tiny', onClick: () => openRedistModal(row) }, () => '转派'),
  ]) },
]);

async function openRedistModal(row: CircularItem) {
  redistForm.value = { circular_id: row.id, target_organize: null, processing_deadline: null };
  await ensureLoaded();
  let source: Pick<CircularItem, 'circular_data' | 'disposal_organize'> = row;
  if (!row.circular_data?.length) {
    try {
      source = await getInputDetail(row.id);
    } catch { /* ignore */ }
  }
  const resolved = resolveOrganizeId(extractCircularUnitHint(source));
  if (resolved) {
    redistForm.value.target_organize = resolved;
  }
  showRedist.value = true;
}

async function fetchData() {
  loading.value = true;
  try {
    const r = await getDisposalList({ index: page.value, size: pageSize.value, keyword: keyword.value || undefined });
    data.value = r.items;
    total.value = r.total;
  } finally {
    loading.value = false;
  }
}

async function handleRedistribute() {
  if (!redistForm.value.target_organize) { message.warning('请选择目标单位'); return; }
  try {
    const processing_deadline = redistForm.value.processing_deadline
      ? dayjs(redistForm.value.processing_deadline).format('YYYY-MM-DD HH:mm:ss')
      : undefined;
    await redistributeCircular({
      circular_id: redistForm.value.circular_id,
      distribution_id: '',
      target_organize: redistForm.value.target_organize,
      processing_deadline,
    });
    message.success('转派成功');
    showRedist.value = false;
    redistForm.value = { circular_id: '', target_organize: null, processing_deadline: null };
    await fetchData();
  }
  catch (e: any) { message.error(e?.message || '转派失败'); }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NCard title="通报处置" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NInput
            v-model:value="keyword"
            placeholder="搜索编号/标题..."
            size="small"
            clearable
            style="width:200px"
            @keyup.enter="() => { page = 1; fetchData(); }"
          />
          <NButton size="small" type="primary" @click="() => { page = 1; fetchData(); }">搜索</NButton>
        </NSpace>
      </template>
      <NDataTable :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped
        :pagination="{ page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20,50,100], onUpdatePage:(p:number)=>{page=p;fetchData()}, onUpdatePageSize:(s:number)=>{pageSize=s;page=1;fetchData()} }" />
    </NCard>
    <NModal v-model:show="showRedist" preset="dialog" title="转派通报" positive-text="确认" negative-text="取消" @positive-click="handleRedistribute">
      <NForm label-placement="left" label-width="88">
        <NFormItem label="目标单位" required>
          <OrganizeTreeSelect v-model="redistForm.target_organize" />
        </NFormItem>
        <NFormItem label="处置期限">
          <NDatePicker
            v-model:value="redistForm.processing_deadline"
            type="datetime"
            clearable
            style="width: 100%"
            placeholder="请选择处置期限"
          />
        </NFormItem>
      </NForm>
    </NModal>
  </div>
</template>
