<script lang="ts" setup>
import { computed } from 'vue';

import {
  NButton,
  NDrawer,
  NDrawerContent,
  NEmpty,
  NSpace,
  NTag,
} from 'naive-ui';

import {
  formatDeepflowDate,
  mapSeverityToDisplay,
  mapSeverityToTagType,
} from '#/utils/deepflow';

const props = withDefaults(
  defineProps<{
    tableData?: Record<string, any>[];
    title?: string;
    visible?: boolean;
  }>(),
  {
    tableData: () => [],
    title: '事件列表',
    visible: false,
  },
);

const emit = defineEmits<{
  (e: 'eventClick', value: Record<string, any>): void;
  (e: 'update:visible', value: boolean): void;
}>();

const rows = computed(() => props.tableData || []);
</script>

<template>
  <NDrawer :show="visible" placement="left" :width="760" @update:show="(v) => emit('update:visible', v)">
    <NDrawerContent :title="title" closable>
      <div class="drawer-body">
        <div v-if="rows.length" class="event-list">
          <div
            v-for="event in rows"
            :key="event.event_id || event.id"
            class="event-item"
            @click="emit('eventClick', event)"
          >
            <div class="event-header">
              <h3>{{ event.event_name || '未命名事件' }}</h3>
              <span class="event-time">{{ formatDeepflowDate(event.created_at) || '-' }}</span>
            </div>
            <div class="event-description">{{ event.message || '-' }}</div>
            <div class="event-meta">
              <NSpace>
                <NTag :type="mapSeverityToTagType(event.severity)" size="small">
                  {{ mapSeverityToDisplay(event.severity) }}
                </NTag>
                <NTag type="info" size="small">待处理</NTag>
              </NSpace>
              <span class="event-source">来源: {{ event.source || '-' }}</span>
            </div>
          </div>
        </div>
        <NEmpty v-else description="暂无数据" />
      </div>
      <template #footer>
        <NButton @click="emit('update:visible', false)">关闭</NButton>
      </template>
    </NDrawerContent>
  </NDrawer>
</template>

<style scoped>
.drawer-body {
  min-height: 360px;
}
.event-item {
  border-bottom: 1px solid var(--n-border-color);
  cursor: pointer;
  padding: 16px 0;
  transition: all 0.2s ease;
}
.event-item:hover {
  transform: translateX(4px);
}
.event-header {
  align-items: flex-start;
  display: flex;
  justify-content: space-between;
  margin-bottom: 8px;
}
.event-header h3 {
  color: var(--n-color-primary);
  font-size: 16px;
  font-weight: 600;
  margin: 0;
}
.event-time,
.event-source {
  color: var(--n-text-color-3);
  font-size: 12px;
}
.event-description {
  color: var(--n-text-color-2);
  line-height: 1.4;
  margin-bottom: 12px;
}
.event-meta {
  align-items: center;
  display: flex;
  justify-content: space-between;
}
</style>
