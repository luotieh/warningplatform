<script lang="ts" setup>
/**
 * 通用列表页容器
 *
 * 把 "筛选区 + 操作区 + 选择栏 + 表格容器" 的公共结构打包，
 * 业务页面只需要：
 *   1. 通过 #filter slot 放 AdvancedFilter 或自己的筛选器（与 actions 同一行）
 *   2. 通过 #actions slot 放右侧操作按钮（新增/导入/导出等）
 *   3. 通过 #selection-extra slot 在选中条数 pill 旁追加自定义批量按钮
 *   4. 通过默认 slot 放 <Grid /> 表格
 *
 * Props：
 *   - title           可选标题
 *   - subtitle        可选副标题（描述）
 *   - card            是否用 NCard 包一层主体（默认 true）
 *   - lastQueryAt     最近刷新时间（仅 DEBUG 用，不再展示统计）
 *   - selectedCount   已选数（>0 才显示选择 pill）
 *
 * 设计原则：
 *   - 不依赖业务字段
 *   - 与 useCrudPage 解耦但可无缝搭配
 *   - filter 与 actions 同一行展示；选择栏选中时单独一行
 */
import { computed } from 'vue';

import { Page } from '@vben/common-ui';

import { NButton, NCard } from 'naive-ui';

interface Props {
  title?: string;
  subtitle?: string;
  /** 是否用 NCard 包一层主体（默认 true） */
  card?: boolean;
  /** 卡片标题（不传则用 title） */
  cardTitle?: string;
  /** 卡片大小 */
  cardSize?: 'huge' | 'large' | 'medium' | 'small';
  /**
   * 兼容历史 API：保留 totalCount/lastQueryAt props，但 UI 不再展示
   * 业务页传入不会报错，统计逻辑后续可由其他位置展示
   */
  totalCount?: number;
  totalLabel?: string;
  lastQueryAt?: string;
  selectedCount?: number;
  /** 内容容器额外 class */
  contentClass?: string;
  /** 是否撑满高度（适合表格页） */
  fillHeight?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  title: '',
  subtitle: '',
  card: true,
  cardTitle: '',
  cardSize: 'small',
  totalCount: undefined,
  totalLabel: '共有数据',
  lastQueryAt: '',
  selectedCount: 0,
  contentClass: '',
  fillHeight: true,
});

const emit = defineEmits<{
  (e: 'clearSelection'): void;
}>();

const showSelectionBar = computed(() => props.selectedCount > 0);
</script>

<template>
  <Page :auto-content-height="fillHeight">
    <div v-if="title && !card" class="iam-page-title mb-3 flex items-center gap-2">
      <span class="text-base font-medium">{{ title }}</span>
      <span v-if="subtitle" class="text-xs text-gray-500">{{ subtitle }}</span>
    </div>

    <component
      :is="card ? NCard : 'div'"
      :class="['iam-page-shell h-full', card ? '' : 'iam-page-shell-bare']"
      :title="card ? (cardTitle || title) : undefined"
      :size="card ? cardSize : undefined"
      :bordered="card ? false : undefined"
      :content-style="card ? 'display:flex;flex-direction:column;height:100%;padding:12px 16px;' : ''"
      :header-style="card ? 'padding:12px 16px 8px;' : ''"
    >
      <template v-if="card && (title || subtitle)" #header>
        <div class="flex items-center gap-2">
          <span class="text-base font-medium">{{ title || cardTitle }}</span>
          <span v-if="subtitle" class="text-xs text-gray-500 font-normal">
            {{ subtitle }}
          </span>
        </div>
      </template>

      <template v-if="card && $slots['header-extra']" #header-extra>
        <slot name="header-extra" />
      </template>

      <!-- 顶部工具栏：筛选 + 操作按钮 同一行 -->
      <div
        v-if="$slots.filter || $slots.actions"
        class="iam-page-toolbar mb-2 flex flex-wrap items-center gap-2"
      >
        <div v-if="$slots.filter" class="iam-page-toolbar__filter flex-1 min-w-0">
          <slot name="filter" />
        </div>
        <div
          v-if="$slots.actions"
          class="iam-page-toolbar__actions flex items-center gap-2 ml-auto"
        >
          <slot name="actions" />
        </div>
      </div>

      <!-- 选择栏：仅在勾选时显示，单独一行 -->
      <div
        v-if="showSelectionBar"
        class="iam-page-selection mb-2 flex items-center gap-3"
      >
        <div class="iam-selection-pill flex items-center gap-2 px-3 py-1 rounded-full">
          <span class="text-sm font-medium">已选 {{ selectedCount }}</span>
          <slot name="selection-extra" />
          <NButton
            size="tiny"
            text
            type="info"
            @click="emit('clearSelection')"
          >
            清除
          </NButton>
        </div>
      </div>

      <div :class="['iam-page-content flex-1 min-h-0', contentClass]">
        <slot />
      </div>
    </component>

    <slot name="extra" />
  </Page>
</template>

<style scoped>
.iam-page-shell {
  display: flex;
  flex-direction: column;
}

.iam-page-shell-bare {
  flex: 1;
  min-height: 0;
}

.iam-page-toolbar__filter {
  /* 让 AdvancedFilter 等水平布局正常折行 */
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.iam-selection-pill {
  background-color: rgba(91, 140, 255, 0.08);
  border: 1px dashed rgba(91, 140, 255, 0.5);
  color: var(--n-text-color, #333);
}

:deep(.dark) .iam-selection-pill {
  background-color: rgba(91, 140, 255, 0.16);
}

:deep(.iam-page-shell.n-card) > .n-card__content {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
}
</style>
