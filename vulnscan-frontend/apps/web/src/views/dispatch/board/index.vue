<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import {
  NCard, NTag, NSpace, NButton, NEmpty, NSpin, NBadge,
  NSelect, NTooltip, NIcon, NScrollbar,
  useMessage,
} from 'naive-ui';
import type { SelectOption } from 'naive-ui';
import { useRouter } from 'vue-router';
import {
  getOrderList,
  type DispatchOrder, type DispatchType,
  DispatchStatusLabels, DispatchStatusTypes,
  DispatchTypeLabels, PriorityLabels, PriorityColors,
} from '#/api/dispatch';

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const allOrders = ref<DispatchOrder[]>([]);
const filterType = ref<string | null>(null);

const boardColumns = [
  { key: 'pending', label: '待接收', color: '#faad14' },
  { key: 'in_progress', label: '处理中', color: '#1890ff' },
  { key: 'submitted', label: '待审核', color: '#52c41a' },
  { key: 'completed', label: '已完成', color: '#8c8c8c' },
] as const;

async function fetchAll() {
  loading.value = true;
  try {
    const params: Record<string, any> = { page: 1, page_size: 200 };
    if (filterType.value) params.type = filterType.value;
    const res = await getOrderList(params);
    allOrders.value = res.items;
  } catch (e: any) {
    message.error(e?.message || '加载失败');
  } finally {
    loading.value = false;
  }
}

onMounted(fetchAll);

const columnOrders = computed(() => {
  const map: Record<string, DispatchOrder[]> = {};
  for (const col of boardColumns) {
    map[col.key] = [];
  }
  for (const o of allOrders.value) {
    if (map[o.status]) {
      map[o.status]!.push(o);
    }
  }
  return map;
});

const typeOptions: SelectOption[] = [
  { value: null, label: '全部类型' },
  ...Object.entries(DispatchTypeLabels).map(([v, l]) => ({ value: v, label: l })),
];

function fmtTime(t: string | null) {
  if (!t) return '';
  const d = new Date(t);
  return `${d.getMonth() + 1}/${d.getDate()} ${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
}

function goDetail(id: string) {
  router.push(`/dispatch/orders/${id}`);
}

function isOverdue(order: DispatchOrder) {
  if (!order.deadline) return false;
  return new Date(order.deadline) < new Date() && order.status !== 'completed' && order.status !== 'cancelled';
}
</script>

<template>
  <div class="p-4">
    <NCard :bordered="false">
      <template #header>
        <NSpace align="center">
          <span style="font-size: 16px; font-weight: 600">派发工作台</span>
          <NSelect v-model:value="filterType" :options="typeOptions" size="small"
            style="width: 140px" @update:value="fetchAll" />
        </NSpace>
      </template>
      <template #header-extra>
        <NButton size="small" @click="fetchAll" :loading="loading">刷新</NButton>
      </template>

      <NSpin :show="loading">
        <div class="board-container">
          <div v-for="col in boardColumns" :key="col.key" class="board-column">
            <div class="board-column-header" :style="{ borderBottomColor: col.color }">
              <NBadge :value="columnOrders[col.key]?.length || 0" :max="99"
                :color="col.color" :offset="[10, 0]">
                <span class="board-column-title">{{ col.label }}</span>
              </NBadge>
            </div>
            <NScrollbar style="max-height: calc(100vh - 240px)">
              <div class="board-column-body">
                <div v-for="order in columnOrders[col.key]" :key="order.id"
                  class="board-card" :class="{ 'board-card--overdue': isOverdue(order) }"
                  @click="goDetail(order.id)">
                  <div class="board-card-header">
                    <NTag size="tiny" :bordered="false">{{ order.code }}</NTag>
                    <NTag size="tiny" :bordered="false"
                      :style="{ color: PriorityColors[order.priority], backgroundColor: PriorityColors[order.priority] + '18' }">
                      {{ PriorityLabels[order.priority] }}
                    </NTag>
                  </div>
                  <div class="board-card-title">{{ order.title }}</div>
                  <div class="board-card-meta">
                    <NSpace size="small">
                      <NTag size="tiny" :bordered="false">{{ DispatchTypeLabels[order.type] || order.type }}</NTag>
                      <span v-if="order.assignee_name" class="board-card-assignee">
                        {{ order.assignee_name }}
                      </span>
                    </NSpace>
                    <span v-if="order.deadline" class="board-card-deadline"
                      :class="{ 'text-red': isOverdue(order) }">
                      截止: {{ fmtTime(order.deadline) }}
                    </span>
                  </div>
                </div>
                <NEmpty v-if="!columnOrders[col.key]?.length" description="暂无数据"
                  style="padding: 40px 0" :show-icon="false" />
              </div>
            </NScrollbar>
          </div>
        </div>
      </NSpin>
    </NCard>
  </div>
</template>

<style scoped>
.board-container {
  display: flex;
  gap: 16px;
  min-height: 400px;
}

.board-column {
  flex: 1;
  min-width: 260px;
  background: #f5f5f7;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
}

:root[class*="dark"] .board-column {
  background: #1e1e1e;
}

.board-column-header {
  padding: 12px 16px;
  border-bottom: 3px solid;
  font-weight: 600;
}

.board-column-title {
  font-size: 14px;
}

.board-column-body {
  padding: 8px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.board-card {
  background: #ffffff;
  border-radius: 6px;
  padding: 12px;
  cursor: pointer;
  border: 1px solid #e8e8e8;
  transition: box-shadow 0.2s, transform 0.15s;
}

:root[class*="dark"] .board-card {
  background: #2a2a2a;
  border-color: #3a3a3a;
}

.board-card:hover {
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.12);
  transform: translateY(-2px);
  border-color: #c0c0c0;
}

.board-card--overdue {
  border-left: 3px solid #f5222d;
}

.board-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
}

.board-card-title {
  font-size: 14px;
  font-weight: 500;
  line-height: 1.5;
  margin-bottom: 8px;
  color: #333;
  overflow: hidden;
  text-overflow: ellipsis;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
}

:root[class*="dark"] .board-card-title {
  color: #e0e0e0;
}

.board-card-meta {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 12px;
  color: #999;
}

.board-card-assignee {
  color: #666;
}

.board-card-deadline {
  font-size: 11px;
}

.text-red {
  color: #f5222d !important;
  font-weight: 500;
}
</style>
