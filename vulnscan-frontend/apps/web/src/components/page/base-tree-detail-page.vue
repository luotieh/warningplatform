<script lang="ts" setup>
/**
 * 通用 "左侧树 + 右侧详情/CRUD" 页面容器
 *
 * 适用场景：组织结构、部门、菜单、权限、风险规则等
 *
 * 用法（参考 organize/index.vue）：
 *   <BaseTreeDetailPage
 *     title="组织结构"
 *     :tree-data="treeData"
 *     :loading="loading"
 *     :selected="selected"
 *     :delete-confirm="(node) => `确定删除「${node.name}」吗？`"
 *     @select="onSelect"
 *     @create="onCreate"
 *     @create-child="onCreateChild"
 *     @edit="onEdit"
 *     @delete="onDelete"
 *     @reload="loadTree"
 *   >
 *     <template #detail="{ node }">
 *       <NDescriptions ...>...
 *     </template>
 *   </BaseTreeDetailPage>
 */
import { computed, ref, watch } from 'vue';

import { Page } from '@vben/common-ui';

import {
  NButton,
  NCard,
  NEmpty,
  NInput,
  NPopconfirm,
  NSpace,
  NSpin,
  NTree,
  type TreeOption,
} from 'naive-ui';

import { usePerm, type PermInput } from '#/composables/usePerm';

interface Props {
  /** 顶部标题（兼具 NCard 标题） */
  title?: string;
  /** 树面板宽度 */
  treeWidth?: number | string;
  /** 树数据（NTree 格式：{ key, label, children, ...raw }） */
  treeData: TreeOption[];
  /** 当前选中节点（业务侧持有，原始数据） */
  selected?: any;
  /** 是否加载中（拉取树期间的 loading） */
  loading?: boolean;
  /** 默认展开全部 */
  defaultExpandAll?: boolean;
  /** 树空时的提示 */
  emptyTreeText?: string;
  /** 详情区空时的提示 */
  emptyDetailText?: string;
  /** 顶部 “新增” 按钮显示控制 */
  showCreate?: boolean;
  /** 详情区 "新增子" 显示控制 */
  showCreateChild?: boolean;
  /** 详情区 "编辑" 显示控制 */
  showEdit?: boolean;
  /** 详情区 "删除" 显示控制 */
  showDelete?: boolean;
  /** 删除二次确认 */
  deleteConfirm?: ((node: any) => string) | string;
  /** 是否显示树搜索框 */
  searchable?: boolean;
  /** 是否显示刷新按钮 */
  refreshable?: boolean;
  /** "新增" 按钮文案 */
  createText?: string;
  /** "新增子" 按钮文案 */
  createChildText?: string;
  /** "编辑" 按钮文案 */
  editText?: string;
  /** "删除" 按钮文案 */
  deleteText?: string;
  /** 选中节点的 key 字段（默认 id） */
  idKey?: string;
  /** 新增按钮权限码 */
  createPerm?: PermInput;
  /** 新增子级按钮权限码 */
  createChildPerm?: PermInput;
  /** 编辑按钮权限码 */
  editPerm?: PermInput;
  /** 删除按钮权限码 */
  deletePerm?: PermInput;
  /** 树节点自定义前缀渲染 */
  renderPrefix?: (info: { option: TreeOption }) => any;
}

const props = withDefaults(defineProps<Props>(), {
  title: '',
  treeWidth: 320,
  treeData: () => [],
  selected: null,
  loading: false,
  defaultExpandAll: true,
  emptyTreeText: '暂无数据',
  emptyDetailText: '请选择左侧节点查看详情',
  showCreate: true,
  showCreateChild: true,
  showEdit: true,
  showDelete: true,
  deleteConfirm: '确定删除该节点吗？',
  searchable: true,
  refreshable: true,
  createText: '新增',
  createChildText: '新增子级',
  editText: '编辑',
  deleteText: '删除',
  idKey: 'id',
  createPerm: undefined,
  createChildPerm: undefined,
  editPerm: undefined,
  deletePerm: undefined,
  renderPrefix: undefined,
});

const { can: canPerm } = usePerm();
const canCreate = computed(() => !props.createPerm || canPerm(props.createPerm));
const canCreateChild = computed(() => !props.createChildPerm || canPerm(props.createChildPerm));
const canEdit = computed(() => !props.editPerm || canPerm(props.editPerm));
const canDelete = computed(() => !props.deletePerm || canPerm(props.deletePerm));

const emit = defineEmits<{
  (e: 'select', node: any): void;
  (e: 'create'): void;
  (e: 'create-child', parent: any): void;
  (e: 'edit', node: any): void;
  (e: 'delete', node: any): void;
  (e: 'reload'): void;
}>();

const selectedKeys = ref<Array<number | string>>([]);
const searchKeyword = ref('');

watch(
  () => props.selected,
  (val) => {
    if (val && val[props.idKey] !== undefined) {
      selectedKeys.value = [val[props.idKey]];
    } else {
      selectedKeys.value = [];
    }
  },
  { immediate: true },
);

function getRaw(opt: any): any {
  return opt?.raw ?? opt;
}

function handleSelect(
  _keys: Array<number | string>,
  options: Array<null | TreeOption>,
) {
  const first = options.find((o) => !!o);
  if (!first) {
    emit('select', null);
    return;
  }
  emit('select', getRaw(first));
}

function handleCreate() {
  emit('create');
}

function handleCreateChild() {
  if (!props.selected) return;
  emit('create-child', props.selected);
}

function handleEdit() {
  if (!props.selected) return;
  emit('edit', props.selected);
}

function handleDelete() {
  if (!props.selected) return;
  emit('delete', props.selected);
}

const deleteConfirmText = computed(() => {
  if (!props.selected) return '';
  return typeof props.deleteConfirm === 'function'
    ? props.deleteConfirm(props.selected)
    : props.deleteConfirm;
});

function filterTree(nodes: TreeOption[], keyword: string): TreeOption[] {
  if (!keyword) return nodes;
  const kw = keyword.toLowerCase();
  const result: TreeOption[] = [];
  for (const node of nodes) {
    const children = node.children
      ? filterTree(node.children as TreeOption[], keyword)
      : undefined;
    const matched =
      String(node.label || '').toLowerCase().includes(kw) ||
      (children && children.length > 0);
    if (matched) {
      result.push({ ...node, children });
    }
  }
  return result;
}

const filteredTree = computed(() =>
  filterTree(props.treeData, searchKeyword.value.trim()),
);

const treeWidthStyle = computed(() =>
  typeof props.treeWidth === 'number' ? `${props.treeWidth}px` : props.treeWidth,
);
</script>

<template>
  <Page auto-content-height>
    <div class="flex h-full gap-4">
      <NCard
        class="iam-tree-pane shrink-0 h-full flex flex-col"
        :style="{ width: treeWidthStyle }"
        size="small"
        :bordered="false"
      >
        <template #header>
          <span class="text-sm font-medium">{{ title || '树结构' }}</span>
        </template>
        <template #header-extra>
          <NSpace size="small">
            <slot name="tree-actions" />
            <NButton
              v-if="refreshable"
              size="tiny"
              tertiary
              @click="emit('reload')"
            >
              刷新
            </NButton>
            <NButton
              v-if="showCreate && canCreate"
              size="small"
              type="primary"
              @click="handleCreate"
            >
              {{ createText }}
            </NButton>
          </NSpace>
        </template>

        <div v-if="searchable" class="mb-2">
          <NInput
            v-model:value="searchKeyword"
            placeholder="输入关键词过滤..."
            size="small"
            clearable
          />
        </div>

        <NSpin :show="loading" class="flex-1 overflow-auto">
          <NTree
            v-if="filteredTree.length > 0"
            :data="filteredTree"
            block-line
            selectable
            :selected-keys="selectedKeys"
            :default-expand-all="defaultExpandAll"
            :render-prefix="renderPrefix"
            @update:selected-keys="handleSelect"
          />
          <NEmpty v-else-if="!loading" :description="emptyTreeText" class="py-8" />
        </NSpin>
      </NCard>

      <NCard
        class="iam-detail-pane flex-1 h-full flex flex-col"
        size="small"
        :bordered="false"
      >
        <template #header>
          <span class="text-sm font-medium">
            <slot name="detail-title" :node="selected">
              {{ selected ? '节点详情' : '详情' }}
            </slot>
          </span>
        </template>
        <template v-if="selected" #header-extra>
          <NSpace size="small">
            <slot name="actions-extra" :node="selected" />
            <NButton
              v-if="showCreateChild && canCreateChild"
              size="small"
              type="primary"
              @click="handleCreateChild"
            >
              {{ createChildText }}
            </NButton>
            <NButton
              v-if="showEdit && canEdit"
              size="small"
              @click="handleEdit"
            >
              {{ editText }}
            </NButton>
            <NPopconfirm
              v-if="showDelete && canDelete"
              @positive-click="handleDelete"
            >
              <template #trigger>
                <NButton size="small" type="error">
                  {{ deleteText }}
                </NButton>
              </template>
              {{ deleteConfirmText }}
            </NPopconfirm>
          </NSpace>
        </template>

        <div v-if="selected" class="iam-detail-body flex-1 overflow-auto">
          <slot name="detail" :node="selected" />
          <slot :node="selected" />
        </div>
        <NEmpty
          v-else
          :description="emptyDetailText"
          class="flex-1 flex flex-col items-center justify-center"
        />
      </NCard>
    </div>

    <slot name="extra" />
  </Page>
</template>

<style scoped>
.iam-tree-pane :deep(.n-card__content),
.iam-detail-pane :deep(.n-card__content) {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
}
</style>
