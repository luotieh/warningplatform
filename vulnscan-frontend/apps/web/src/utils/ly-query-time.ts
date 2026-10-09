const OFFSET = 8 * 60 * 60 * 1000;
const DAY = 24 * 60 * 60 * 1000;

// DatePicker calendar fields describe Beijing business time, independent of host timezone.
export function pickerTimeToEpoch(value: number, dateOnly = false) {
  const d = new Date(value);
  return Date.UTC(d.getFullYear(), d.getMonth(), d.getDate(),
    dateOnly ? 0 : d.getHours(), dateOnly ? 0 : d.getMinutes(),
    dateOnly ? 0 : d.getSeconds()) - OFFSET;
}

export function epochToPickerTime(value: number) {
  const d = new Date(value + OFFSET);
  return new Date(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(),
    d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()).getTime();
}

export function eventDateWindow(scope: string, start: number | null, end: number | null, now = Date.now()) {
  const params: Record<string, number> = {};
  if (start !== null || end !== null) {
    if (start !== null) params.starttime = Math.floor(pickerTimeToEpoch(start, true) / 1000);
    if (end !== null) params.endtime = Math.floor((pickerTimeToEpoch(end, true) + DAY) / 1000);
  } else if (['today', '3', '7'].includes(scope)) {
    const days = scope === 'today' ? 1 : Number(scope);
    params.starttime = Math.floor((Math.floor((now + OFFSET) / DAY) * DAY - OFFSET - (days - 1) * DAY) / 1000);
    params.endtime = Math.floor(now / 1000);
  }
  return params;
}
