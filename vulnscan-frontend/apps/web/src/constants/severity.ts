import type { EnumMap } from '#/components/table';

export const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type SeverityLevel = (typeof SEVERITY_LEVELS)[number];

export const sevLabels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

export const sevColors: Record<string, { bg: string; fg: string }> = {
  critical: { bg: '#fff1f0', fg: '#cf1322' },
  high: { bg: '#fff7e6', fg: '#d46b08' },
  medium: { bg: '#fffbe6', fg: '#d4b106' },
  low: { bg: '#f6ffed', fg: '#389e0d' },
  info: { bg: '#f0f5ff', fg: '#1890ff' },
};

export const SEVERITY_MAP: EnumMap = {
  critical: { label: '严重', type: 'error' },
  high: { label: '高危', type: 'warning' },
  medium: { label: '中危', type: 'warning' },
  low: { label: '低危', type: 'info' },
  info: { label: '信息', type: 'default' },
};
