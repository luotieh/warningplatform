<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';
import {
  NButton, NCard, NDataTable, NInput, NSpace, NTag,
  NModal, NRadioGroup, NRadio, NFormItem, NForm, useMessage,
} from 'naive-ui';
import {
  getVerifyList, verifyCircular,
  getDistributeList, distributeCircular,
  getReviewList, reviewCircular,
  type CircularItem, CircularStatusLabels, CircularStatusTypes,
} from '#/api/circular';

const props = defineProps<{
  mode: 'verify' | 'distribute' | 'review';
}>();

const titles: Record<string, string> = {
  verify: '通报核验',
  distribute: '通报派发',
  review: '处置审核',
};
const actionLabels: Record<string, string> = {
  verify: '核验',
  distribute: '派发',
  review: '审核',
};

defineOptions({ name: 'CircularFlowBoard' });

const message = useMessage();
const loading = ref(false);
const data = ref<CircularItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const showModal = ref(false);
const currentId = ref('');
const selectedIds = ref<string[]>([]);

const verifyResult = ref('pass');
const distForm = ref({ target_organize: '', processing_deadline: '', requirements: '' });
const reviewForm = ref({ review: 'approve' as string, instructions: '' });

const columns = computed(() => [
  { title: '通报编号', key: 'code', width: 160, ellipsis: { tooltip: true } },
  { title: '标题', key: 'title', minWidth: 200 },
  {
    title: '状态', key: 'status', width: 100,
    render: (row: CircularItem) => h(NTag, { size: 'small', type: (CircularStatusTypes[row.status] || 'default') as any, bordered: false }, () => CircularStatusLabels[row.status] ?? row.status),
  },
  { title: '所属组织', key: 'organize', width: 140, ellipsis: { tooltip: true } },
  { title: '创建时间', key: 'created_at', width: 170 },
  {
    title: '操作', key: 'actions', width: 100, fixed: 'right' as const,
    render: (row: CircularItem) => h(NButton, { size: 'tiny', type: 'primary', onClick: () => { currentId.value = row.id; selectedIds.value = [row.id]; showModal.value = true; } }, () => actionLabels[props.mode]),
  },
]);

function fetchData() {
  loading.value = true;
  const params: Record<string, any> = { index: page.value, size: pageSize.value };
  if (props.mode === 'verify') params.keyword = keyword.value || undefined;

  let fetcher: Promise<any>;
  if (props.mode === 'verify') fetcher = getVerifyList(params);
  else if (props.mode === 'distribute') fetcher = getDistributeList(params);
  else fetcher = getReviewList(params);

  fetcher
    .then(r => { data.value = r.items; total.value = r.total; })
    .finally(() => { loading.value = false; });
}

async function handleAction() {
  try {
    if (props.mode === 'verify') {
      await verifyCircular({ circular_ids: selectedIds.value, result: verifyResult.value });
      message.success('核验完成');
    } else if (props.mode === 'distribute') {
      if (!distForm.value.target_organize) { message.warning('请输入目标组织'); return; }
      await distributeCircular({ circular_id: currentId.value, ...distForm.value });
      message.success('派发成功');
      distForm.value = { target_organize: '', processing_deadline: '', requirements: '' };
    } else {
      await reviewCircular(currentId.value, reviewForm.value);
      message.success('审核完成');
      reviewForm.value = { review: 'approve', instructions: '' };
    }
    showModal.value = false;
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding:16px">
    <NCard :title="titles[mode]" size="small">
      <template v-if="mode === 'verify'" #header-extra>
        <NSpace :size="8">
          <NInput v-model:value="keyword" placeholder="搜索..." size="small" clearable style="width:200px" @keyup.enter="() => { page = 1; fetchData(); }" />
          <NButton size="small" type="primary" @click="() => { page = 1; fetchData(); }">搜索</NButton>
        </NSpace>
      </template>
      <NDataTable
        :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped
        :pagination="{
          page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20, 50, 100],
          onUpdatePage: (p: number) => { page = p; fetchData(); },
          onUpdatePageSize: (s: number) => { pageSize = s; page = 1; fetchData(); },
        }"
      />
    </NCard>

    <!-- 核验弹窗 -->
    <NModal v-if="mode === 'verify'" v-model:show="showModal" preset="dialog" :title="titles[mode]" positive-text="确认" negative-text="取消" @positive-click="handleAction">
      <NFormItem label="核验结果">
        <NRadioGroup v-model:value="verifyResult">
          <NRadio value="pass">通过</NRadio>
          <NRadio value="reject">驳回</NRadio>
        </NRadioGroup>
      </NFormItem>
    </NModal>

    <!-- 派发弹窗 -->
    <NModal v-if="mode === 'distribute'" v-model:show="showModal" preset="dialog" :title="titles[mode]" positive-text="确认派发" negative-text="取消" @positive-click="handleAction">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="目标组织" required><NInput v-model:value="distForm.target_organize" placeholder="请输入目标组织" /></NFormItem>
        <NFormItem label="处置期限"><NInput v-model:value="distForm.processing_deadline" placeholder="YYYY-MM-DD" /></NFormItem>
        <NFormItem label="处置要求"><NInput v-model:value="distForm.requirements" type="textarea" placeholder="请输入处置要求" :rows="3" /></NFormItem>
      </NForm>
    </NModal>

    <!-- 审核弹窗 -->
    <NModal v-if="mode === 'review'" v-model:show="showModal" preset="dialog" :title="titles[mode]" positive-text="确认" negative-text="取消" @positive-click="handleAction">
      <NFormItem label="审核结果">
        <NRadioGroup v-model:value="reviewForm.review">
          <NRadio value="approve">通过</NRadio>
          <NRadio value="reject">驳回</NRadio>
        </NRadioGroup>
      </NFormItem>
      <NFormItem label="审核意见"><NInput v-model:value="reviewForm.instructions" type="textarea" placeholder="请输入审核意见" :rows="3" /></NFormItem>
    </NModal>
  </div>
</template>
