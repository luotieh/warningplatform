import { ref } from 'vue';

export interface RemoteSelectOption {
  label: string;
  value: string;
  [key: string]: any;
}

export interface FetchResult {
  items: RemoteSelectOption[];
  total: number;
}

export interface UseRemoteSelectOptions {
  fetchFn: (params: { index: number; size: number; keyword?: string }) => Promise<FetchResult>;
  pageSize?: number;
  immediate?: boolean;
}

export function useRemoteSelect(opts: UseRemoteSelectOptions) {
  const pageSize = opts.pageSize ?? 50;

  const options = ref<RemoteSelectOption[]>([]);
  const loading = ref(false);
  const page = ref(1);
  const hasMore = ref(true);
  const keyword = ref('');

  async function load(reset = false) {
    if (loading.value) return;
    if (reset) {
      page.value = 1;
      hasMore.value = true;
      options.value = [];
    }
    if (!hasMore.value) return;

    loading.value = true;
    try {
      const { items, total } = await opts.fetchFn({
        index: page.value,
        size: pageSize,
        keyword: keyword.value || undefined,
      });
      options.value = reset ? items : [...options.value, ...items];
      hasMore.value = options.value.length < total;
      page.value++;
    } catch {
      /* ignore */
    } finally {
      loading.value = false;
    }
  }

  function onSearch(query: string) {
    keyword.value = query;
    load(true);
  }

  function onScroll(e: Event) {
    const el = e.target as HTMLElement;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 10) {
      load();
    }
  }

  if (opts.immediate !== false) {
    load(true);
  }

  return {
    options,
    loading,
    hasMore,
    load,
    onSearch,
    onScroll,
  };
}
