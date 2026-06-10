import type { PaginationProps } from 'naive-ui';

import { computed, type Ref } from 'vue';

export interface UseNaiveTablePaginationOptions {
  page: Ref<number>;
  pageSize: Ref<number>;
  total: Ref<number>;
  onFetch: () => void | Promise<void>;
  pageSizes?: number[];
  prefix?: PaginationProps['prefix'];
}

/** Naive UI 表格分页：回调必须在 script 中用 .value 更新，模板内联 page = p 无效。 */
export function useNaiveTablePagination(opts: UseNaiveTablePaginationOptions) {
  const pageSizes = opts.pageSizes ?? [20, 50, 100];

  function handlePageChange(p: number) {
    opts.page.value = p;
    void opts.onFetch();
  }

  function handlePageSizeChange(s: number) {
    opts.pageSize.value = s;
    opts.page.value = 1;
    void opts.onFetch();
  }

  const pagination = computed<PaginationProps>(() => ({
    page: opts.page.value,
    pageSize: opts.pageSize.value,
    itemCount: opts.total.value,
    showSizePicker: true,
    pageSizes,
    prefix: opts.prefix,
    onUpdatePage: handlePageChange,
    onUpdatePageSize: handlePageSizeChange,
  }));

  return { pagination, handlePageChange, handlePageSizeChange };
}
