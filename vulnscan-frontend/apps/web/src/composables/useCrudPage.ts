/**
 * CRUD 页面统一编排
 *
 * 把"列表 + 分页 + 筛选 + 新增/编辑/删除/批量"这套常见模板抽出来，
 * 业务页只需配置：列、API 函数、字段映射、操作按钮即可。
 *
 * 用法（最小示例，见 docs 或 identity/position/index.vue）：
 *   const crud = useCrudPage<PositionItem>({
 *     name: 'position',
 *     api: {
 *       list:   (params) => getPositionList(params),
 *       create: (payload) => createPosition(payload),
 *       update: (id, payload) => updatePosition(id, payload),
 *       remove: (id) => deletePosition(id),
 *     },
 *     idKey: 'id',
 *   });
 *
 *   crud.openCreate();           // 打开新增
 *   crud.openEdit(row);          // 打开编辑
 *   crud.handleSubmit(form);     // 弹窗内提交
 *   crud.remove(row);            // 删除单条
 *   crud.batchRemove();          // 删除已选
 *   crud.refresh();              // 刷新当前页
 *   crud.handleFilter(payload);  // 筛选变更
 *
 *   <Grid /> 来自 useVbenVxeGrid({ gridOptions: crud.gridOptions, gridEvents: crud.gridEvents })
 */
import type { VxeGridProps } from '#/adapter/vxe-table';

import { computed, reactive, ref, shallowRef } from 'vue';

import { message } from '#/adapter/naive';
import { useVbenVxeGrid } from '#/adapter/vxe-table';
import { useBatchOps } from './useBatchOps';

export interface CrudListResp<T> {
  items: T[];
  total: number;
}

export interface CrudApi<T, ID = number | string> {
  list: (params: Record<string, any>) => Promise<any>;
  create?: (payload: Partial<T>) => Promise<any>;
  update?: (id: ID, payload: Partial<T>) => Promise<any>;
  remove?: (id: ID) => Promise<any>;
  /** 批量删除（如果后端不支持，会自动按并发依次调用 remove） */
  batchRemove?: (ids: ID[]) => Promise<any>;
}

export interface UseCrudPageOptions<T, ID = number | string> {
  /** 业务名，用于日志/提示前缀 */
  name?: string;
  /** API */
  api: CrudApi<T, ID>;
  /** 主键字段名，默认 id */
  idKey?: string;
  /** 表格列 */
  columns?: any[];
  /** 默认分页大小 */
  pageSize?: number;
  /** 默认分页选项 */
  pageSizes?: number[];
  /** 是否启用 checkbox */
  selectable?: boolean;
  /** 提取展示名（用于消息提示） */
  identify?: (row: T) => string;
  /** 创建/编辑前的 payload 转换 */
  prepareSubmit?: (
    payload: Partial<T>,
    mode: 'create' | 'edit',
    row: null | T,
  ) => Partial<T>;
  /** 新增成功提示 */
  msgCreated?: string;
  /** 编辑成功提示 */
  msgUpdated?: string;
  /** 删除成功提示 */
  msgRemoved?: string;
  /** 列表请求结果转换：默认按 { items, total } 处理 */
  transformList?: (res: any) => CrudListResp<T>;
  /** 自定义提交（覆盖默认 create/update） */
  customSubmit?: (
    mode: 'create' | 'edit',
    payload: Partial<T>,
    row: null | T,
  ) => Promise<any>;
  /** 额外 vxe Grid 配置 */
  gridConfig?: Partial<VxeGridProps>;
}

export function useCrudPage<T extends Record<string, any>, ID = number | string>(
  options: UseCrudPageOptions<T, ID>,
) {
  const idKey = options.idKey ?? 'id';
  const name = options.name ?? 'crud';
  const identify = options.identify ?? ((r: T) => r?.name || r?.[idKey] || '');
  const transformList =
    options.transformList ??
    ((res: any) => ({
      items: res?.items ?? res?.list ?? res?.data ?? [],
      total: res?.total ?? res?.count ?? 0,
    }));

  // ---------- 弹窗状态 ----------
  const showModal = ref(false);
  const modalMode = ref<'create' | 'edit'>('create');
  const editingRow = ref<null | T>(null);
  const submitting = ref(false);

  function openCreate() {
    modalMode.value = 'create';
    editingRow.value = null;
    showModal.value = true;
  }

  function openEdit(row: T) {
    modalMode.value = 'edit';
    editingRow.value = { ...row };
    showModal.value = true;
  }

  function closeModal() {
    showModal.value = false;
    editingRow.value = null;
  }

  // ---------- 筛选 ----------
  const searchPayload = ref<Record<string, any>>({});

  function handleFilter(payload: Record<string, any>) {
    searchPayload.value = payload || {};
    refresh();
  }

  // ---------- 选择 ----------
  const selectedRows = shallowRef<T[]>([]);

  const selectedCount = computed(() => selectedRows.value.length);
  const selectedIds = computed(() =>
    selectedRows.value.map((r) => (r as any)[idKey] as ID),
  );

  function clearSelection() {
    const inst: any = gridApi.grid;
    if (inst && typeof inst.clearCheckboxRow === 'function') {
      inst.clearCheckboxRow();
    }
    selectedRows.value = [];
  }

  // ---------- 总数/最近刷新 ----------
  const totalCount = ref(0);
  const lastQueryAt = ref('');

  // ---------- 表格 ----------
  const baseColumns = options.selectable
    ? [{ type: 'checkbox', width: 50, align: 'center' }, ...(options.columns || [])]
    : options.columns || [];

  const gridOptions: VxeGridProps = reactive({
    stripe: false,
    border: 'inner',
    showOverflow: 'tooltip',
    showHeaderOverflow: 'tooltip',
    align: 'center',
    headerAlign: 'center',
    size: 'small',
    rowConfig: {
      keyField: idKey,
      isHover: true,
      isCurrent: true,
    },
    cellConfig: { height: 44 },
    headerRowConfig: { height: 38 },
    columnConfig: { resizable: true },
    scrollY: { enabled: true, gt: 40 },
    pagerConfig: {
      pageSize: options.pageSize ?? 20,
      pageSizes: options.pageSizes ?? [10, 20, 50, 100],
      background: true,
      size: 'small',
    },
    proxyConfig: {
      ajax: {
        query: async ({ page }: any) => {
          const params: Record<string, any> = {
            ...searchPayload.value,
            index: page.currentPage,
            size: page.pageSize,
          };
          try {
            const raw: any = await options.api.list(params);
            const res = transformList(raw);
            totalCount.value = res.total ?? 0;
            lastQueryAt.value = new Date().toLocaleTimeString();
            return res;
          } catch (error) {
            console.error(`[${name}] list failed`, error);
            return { items: [], total: 0 };
          }
        },
      },
    },
    toolbarConfig: { refresh: true },
    columns: baseColumns,
    ...(options.gridConfig || {}),
  } as VxeGridProps);

  const gridEvents = {
    checkboxChange: ({ records }: { records: T[] }) => {
      selectedRows.value = records || [];
    },
    checkboxAll: ({ records }: { records: T[] }) => {
      selectedRows.value = records || [];
    },
  };

  const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, gridEvents });

  function refresh() {
    gridApi.grid.commitProxy('query');
  }

  // ---------- 提交 ----------
  async function handleSubmit(payload: Partial<T>) {
    submitting.value = true;
    try {
      const merged = { ...(editingRow.value as any), ...payload } as Partial<T>;
      const finalPayload = options.prepareSubmit
        ? options.prepareSubmit(merged, modalMode.value, editingRow.value)
        : merged;

      if (options.customSubmit) {
        await options.customSubmit(
          modalMode.value,
          finalPayload,
          editingRow.value,
        );
      } else if (modalMode.value === 'create') {
        if (!options.api.create) {
          throw new Error('未配置 create API');
        }
        await options.api.create(finalPayload);
      } else {
        if (!options.api.update) {
          throw new Error('未配置 update API');
        }
        const id = (editingRow.value as any)?.[idKey];
        await options.api.update(id, finalPayload);
      }

      message.success(
        modalMode.value === 'create'
          ? options.msgCreated ?? '新增成功'
          : options.msgUpdated ?? '修改成功',
      );
      closeModal();
      refresh();
    } catch (error: any) {
      const msg = error?.message || `${modalMode.value === 'create' ? '新增' : '修改'}失败`;
      message.error(msg);
      console.error(`[${name}] submit failed`, error);
    } finally {
      submitting.value = false;
    }
  }

  // ---------- 删除 ----------
  async function remove(row: T) {
    if (!options.api.remove) return;
    try {
      const id = (row as any)[idKey] as ID;
      await options.api.remove(id);
      message.success(options.msgRemoved ?? '删除成功');
      refresh();
    } catch (error: any) {
      message.error(error?.message || '删除失败');
      console.error(`[${name}] remove failed`, error);
    }
  }

  // ---------- 批量 ----------
  const batch = useBatchOps<T>();

  async function batchRemove() {
    const rows = selectedRows.value.slice() as T[];
    if (rows.length === 0) {
      message.warning('请先勾选要删除的数据');
      return;
    }
    if (options.api.batchRemove) {
      try {
        await options.api.batchRemove(rows.map((r) => (r as any)[idKey]));
        message.success(`已删除 ${rows.length} 项`);
        clearSelection();
        refresh();
        return;
      } catch (error: any) {
        message.error(error?.message || '批量删除失败');
        return;
      }
    }
    if (!options.api.remove) {
      message.warning('未配置删除接口');
      return;
    }
    const result = await batch.execute(rows, {
      concurrency: 4,
      identify,
      task: async (row) => {
        const id = (row as any)[idKey] as ID;
        await options.api.remove!(id);
      },
    });
    batch.notifyResult('批量删除', result);
    clearSelection();
    refresh();
  }

  return {
    // 状态
    showModal,
    modalMode,
    editingRow,
    submitting,
    selectedRows,
    selectedCount,
    selectedIds,
    totalCount,
    lastQueryAt,
    batch,

    // 表格
    Grid,
    gridApi,
    gridOptions,
    gridEvents,

    // 操作
    openCreate,
    openEdit,
    closeModal,
    handleSubmit,
    handleFilter,
    refresh,
    remove,
    batchRemove,
    clearSelection,
  };
}
