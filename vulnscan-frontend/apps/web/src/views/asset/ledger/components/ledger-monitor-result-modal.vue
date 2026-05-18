<script lang="ts" setup>
import { computed, h } from 'vue';
import { NCard, NDataTable, NEmpty, NModal, NSpace, NTag } from 'naive-ui';

defineOptions({ name: 'LedgerMonitorResultModal' });

type MonitorResultItem = {
  asset_id: string;
  asset_name: string;
  task_id?: string;
  success: boolean;
  skipped: boolean;
  reason?: string;
  error?: string;
};

defineProps<{
  show: boolean;
  result: null | {
    total: number;
    success: number;
    results: MonitorResultItem[];
  };
}>();

const emit = defineEmits<{
  close: [];
  'update:show': [value: boolean];
}>();

const columns = computed(() => [
  { title: '资产', key: 'asset_name', ellipsis: { tooltip: true } },
  {
    title: '结果',
    key: 'success',
    width: 100,
    render: (row: MonitorResultItem) =>
      h(
        NTag,
        {
          bordered: false,
          type: row.success ? 'success' : row.skipped ? 'warning' : 'error',
        },
        {
          default: () => (row.success ? '成功' : row.skipped ? '跳过' : '失败'),
        },
      ),
  },
  { title: '说明', key: 'message', render: (row: MonitorResultItem) => row.reason || row.error || '-' },
]) as any;
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    title="发送监测结果"
    style="width: min(760px, calc(100vw - 32px))"
    @update:show="(value) => emit('update:show', value)"
  >
    <template v-if="result">
      <NSpace style="margin-bottom: 16px" :size="16">
        <NCard size="small" embedded>
          <div>总计</div>
          <strong>{{ result.total }}</strong>
        </NCard>
        <NCard size="small" embedded>
          <div>成功</div>
          <strong>{{ result.success }}</strong>
        </NCard>
        <NCard size="small" embedded>
          <div>失败 / 跳过</div>
          <strong>{{ result.total - result.success }}</strong>
        </NCard>
      </NSpace>

      <NDataTable
        v-if="result.results.length > 0"
        :bordered="false"
        :columns="columns"
        :data="result.results"
        :max-height="360"
      />
      <NEmpty v-else description="暂无返回结果" />
    </template>

    <template #footer>
      <NSpace justify="end">
        <NTag :bordered="false" type="info">后续可在监测中心继续查看任务</NTag>
      </NSpace>
    </template>
  </NModal>
</template>
