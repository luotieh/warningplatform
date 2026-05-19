import { useRouter } from 'vue-router';

import { useTabbarStore } from '@vben/stores';

export type OpenTaskRecordsTabQuery = {
  dimension?: string;
  disposition?: string;
  hasIssue?: string;
};

/** 在应用标签栏新页打开路径任务的监测记录列表。 */
export function useOpenTaskRecordsTab() {
  const router = useRouter();
  const tabbarStore = useTabbarStore();

  function openTaskRecordsTab(
    task: { id: string; name?: string; task_name?: string },
    query?: OpenTaskRecordsTabQuery,
  ) {
    const path = `/monitor/records/${task.id}`;
    const routeQuery: Record<string, string> = {};
    if (query?.dimension) routeQuery.dimension = query.dimension;
    if (query?.hasIssue) routeQuery.hasIssue = query.hasIssue;
    if (query?.disposition) routeQuery.disposition = query.disposition;

    const titleName = task.name || task.task_name || '路径任务';

    tabbarStore.addTab({
      path,
      name: `MonitorRecords_${task.id}`,
      meta: {
        title: `${titleName} - 监测记录`,
        hideInMenu: true,
        activePath: '/monitor/targets',
      },
    });

    router.push({ path, query: routeQuery });
  }

  return { openTaskRecordsTab };
}
