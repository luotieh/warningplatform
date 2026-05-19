import { useRouter } from 'vue-router';

export const monitorDimensionLabels: Record<string, string> = {
  availability: '可用性监测',
  blacklink: '暗链监测',
  domain_hijack: '域名劫持监测',
  sensitive_file: '敏感文件监测',
  sensitive_word: '敏感词监测',
  tamper: '篡改监测',
};

export type OpenMonitorRecordDetailOptions = {
  taskId?: string;
  taskName?: string;
  from?: 'tasks';
};

/** 打开监测记录详情路由页（监测中心等场景仍走路由）。 */
export function useMonitorRecordDetail() {
  const router = useRouter();

  function openRecordDetail(
    recordId: string,
    options?: OpenMonitorRecordDetailOptions,
  ) {
    const query: Record<string, string> = {};
    if (options?.taskId) query.taskId = options.taskId;
    if (options?.taskName) query.taskName = options.taskName;
    if (options?.from) query.from = options.from;

    router.push({
      path: `/monitor/records/detail/${recordId}`,
      query,
    });
  }

  return { openRecordDetail, monitorDimensionLabels };
}
