import type { EnumMap } from '#/components/table';

export const vulnStatusLabels: Record<string, string> = {
  open: '待修复',
  fixed: '已修复',
  ignored: '已忽略',
  reopened: '已重开',
  verified: '已验证',
};

export const vulnStatusTypes: Record<string, string> = {
  open: 'error',
  fixed: 'success',
  ignored: 'default',
  reopened: 'warning',
  verified: 'error',
};

export const VULN_STATUS_MAP: EnumMap = {
  open: { label: '待修复', type: 'error' },
  fixed: { label: '已修复', type: 'success' },
  ignored: { label: '已忽略', type: 'default' },
  reopened: { label: '已重开', type: 'warning' },
  verified: { label: '已验证', type: 'error' },
};

export const taskStatusLabels: Record<string, string> = {
  pending: '等待中',
  queued: '排队中',
  running: '运行中',
  completed: '已完成',
  failed: '失败',
  cancelled: '已取消',
};

export const taskStatusTypes: Record<string, string> = {
  pending: 'default',
  queued: 'info',
  running: 'warning',
  completed: 'success',
  failed: 'error',
  cancelled: 'default',
};

export const SCAN_TASK_STATUS_MAP: EnumMap = {
  pending: { label: '等待中', type: 'default' },
  queued: { label: '排队中', type: 'info' },
  running: { label: '运行中', type: 'warning' },
  completed: { label: '已完成', type: 'success' },
  failed: { label: '失败', type: 'error' },
  cancelled: { label: '已取消', type: 'default' },
};
