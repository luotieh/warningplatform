export type ArchivePeriod = 'all' | '3' | '7' | 'custom';

// 与业务日界线一致，快捷范围按北京时间自然日计算，包含今天和起止日期。
export function archiveDateParams(
  period: ArchivePeriod,
  custom: [string, string] | null,
  now = new Date(),
): Record<string, string> {
  if (period === 'all') return {};
  if (period === 'custom') {
    return custom ? { archive_from: custom[0], archive_to: custom[1] } : {};
  }
  const parts = new Intl.DateTimeFormat('en', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(now);
  const part = (type: string) => parts.find((value) => value.type === type)!.value;
  const end = `${part('year')}-${part('month')}-${part('day')}`;
  const start = new Date(`${end}T00:00:00Z`);
  start.setUTCDate(start.getUTCDate() - (Number(period) - 1));
  return { archive_from: start.toISOString().slice(0, 10), archive_to: end };
}
