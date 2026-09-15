export interface WaitEstimate {
  low: number;
  high: number;
  timeout: number;
  samples: number;
}

export function estimateWait(samples: number[], timeoutSeconds = 180): WaitEstimate {
  const timeout = Number.isFinite(timeoutSeconds) && timeoutSeconds > 0 ? Math.ceil(timeoutSeconds) : 180;
  const valid = samples.filter((n) => Number.isFinite(n) && n >= 1 && n <= 1800).slice(-20).sort((a, b) => a - b);
  const median = valid.length ? valid[Math.floor(valid.length / 2)]! : 65;
  const low = Math.max(1, Math.min(timeout, Math.floor((valid.length ? median * 0.7 : 45) / 5) * 5));
  const high = Math.max(low, Math.min(timeout, Math.ceil((valid.length ? median * 1.4 : 90) / 5) * 5));
  return { low, high, timeout, samples: valid.length };
}

export function waitText(elapsed: number, estimate: WaitEstimate) {
  const seconds = Math.max(0, Math.floor(elapsed));
  const basis = estimate.samples ? `参考近期 ${estimate.samples} 次成功请求` : '初始经验估计';
  if (seconds >= estimate.timeout) {
    return { title: '等待超时结果', text: `已等待 ${seconds} 秒，已达到模型超时设置，正在确认请求结果。`, slow: true };
  }
  if (seconds >= Math.max(estimate.high, estimate.timeout - 30)) {
    return { title: '等待时间较长', text: `已等待 ${seconds} 秒，接近 ${estimate.timeout} 秒超时上限；仍在等待模型返回，请勿重复提交。`, slow: true };
  }
  if (seconds >= estimate.high) {
    return { title: '已超出预估时间', text: `已等待 ${seconds} 秒，上游响应较慢，仍在等待模型返回；预计时间仅供参考。`, slow: true };
  }
  return { title: '正在等待模型', text: `已等待 ${seconds} 秒，预计总耗时 ${estimate.low}–${estimate.high} 秒（${basis}，仅供参考）。`, slow: false };
}

const STORAGE_PREFIX = 'traffic-ai-duration-v1:';
export function loadDurations(profile: string): number[] {
  try {
    const values = JSON.parse(localStorage.getItem(STORAGE_PREFIX + profile) || '[]');
    return Array.isArray(values) ? values.filter((v) => typeof v === 'number' && Number.isFinite(v) && v >= 1 && v <= 1800).slice(-20) : [];
  } catch { return []; }
}

export function saveDuration(profile: string, seconds: number) {
  if (!profile || !Number.isFinite(seconds) || seconds < 1 || seconds > 1800) return;
  try { localStorage.setItem(STORAGE_PREFIX + profile, JSON.stringify([...loadDurations(profile), seconds].slice(-20))); } catch { /* Storage is optional. */ }
}
