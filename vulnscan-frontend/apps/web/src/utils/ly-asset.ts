export function normalizeAddr(v?: string): string {
  return String(v ?? '').trim().toLowerCase();
}

interface EventLike {
  attackDevice?: string;
  victimDevice?: string;
}
interface AssetLike {
  address?: string;
  asset_type?: string;
  status?: number;
}

/** 解析 IPv4 为无符号 32 位整数；非法返回 null */
function ipv4ToInt(ip: string): null | number {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

/** 判断 IPv4 是否落在网段内；支持 "a.b.c.d/前缀长度" 与 "a.b.c.d/点分掩码" */
export function ipInSegment(ip: string, segment: string): boolean {
  const slash = segment.indexOf('/');
  if (slash < 0) return false;
  const base = ipv4ToInt(segment.slice(0, slash));
  const target = ipv4ToInt(ip);
  if (base === null || target === null) return false;

  const maskPart = segment.slice(slash + 1);
  let bits: number;
  if (maskPart.includes('.')) {
    const maskInt = ipv4ToInt(maskPart);
    if (maskInt === null) return false;
    // 连续掩码的反码 +1 是 2 的整数次幂，log2 取整校验连续性
    bits = 32 - Math.log2(((maskInt ^ 0xff_ff_ff_ff) >>> 0) + 1);
    if (!Number.isInteger(bits)) return false;
  } else {
    bits = Number(maskPart);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  }
  if (bits === 0) return true;
  const mask = (0xff_ff_ff_ff << (32 - bits)) >>> 0;
  return ((base & mask) >>> 0) === ((target & mask) >>> 0);
}

export function assetMatchesEvent(asset: AssetLike, event: EventLike): boolean {
  const addr = normalizeAddr(asset.address);
  if (!addr) return false;
  const attack = normalizeAddr(event.attackDevice);
  const victim = normalizeAddr(event.victimDevice);
  // 网段资产：来源/目标 IP 落入网段即命中
  if (asset.asset_type === 'ip_segment' || addr.includes('/')) {
    return ipInSegment(attack, addr) || ipInSegment(victim, addr);
  }
  return attack === addr || victim === addr;
}

export function countAssetEvents(asset: AssetLike, events: EventLike[]): number {
  return (events || []).reduce(
    (n, e) => (assetMatchesEvent(asset, e) ? n + 1 : n),
    0,
  );
}

export function eventMatchesAnyAsset(event: EventLike, assets: AssetLike[]): boolean {
  return (assets || []).some(
    (a) => a.status === 1 && assetMatchesEvent(a, event),
  );
}
