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

interface AssetNameLike extends AssetLike {
  name?: string;
}

/**
 * eventAssetNames 事件归属资产名列表：来源/目标任一命中启用（status=1）资产
 * 的 address 即视为归属，返回去重后的资产名；无命中返回空数组（调用方显示「未登记」）。
 */
export function eventAssetNames(
  event: EventLike,
  assets: AssetNameLike[],
): string[] {
  const names: string[] = [];
  for (const a of assets || []) {
    if (a.status !== 1) continue;
    if (assetMatchesEvent(a, event) && a.name && !names.includes(a.name)) {
      names.push(a.name);
    }
  }
  return names;
}

/**
 * eventVictimAssets 被攻击资产：仅目标侧（victimDevice）命中启用（status=1）资产，
 * 返回「名称（地址）」标签列表；无命中返回空数组。
 * 与 eventAssetNames 的区别：来源侧命中不计入——威胁情报卡片关心的是受害者。
 */
export function eventVictimAssets(
  event: EventLike,
  assets: AssetNameLike[],
): string[] {
  const victim = normalizeAddr(event.victimDevice);
  if (!victim) return [];
  const out: string[] = [];
  for (const a of assets || []) {
    if (a.status !== 1) continue;
    const addr = normalizeAddr(a.address);
    if (!addr) continue;
    const hit =
      a.asset_type === 'ip_segment' || addr.includes('/')
        ? ipInSegment(victim, addr)
        : victim === addr;
    if (!hit) continue;
    const label = a.name ? `${a.name}（${a.address}）` : String(a.address);
    if (!out.includes(label)) {
      out.push(label);
    }
  }
  return out;
}

// assetOptionFilter 资产下拉模糊匹配：按名称/地址包含匹配，大小写不敏感。
// 例如输入 "徐工" 可匹配 "徐工集团-58.218.196.193"。
export function assetOptionFilter(
  pattern: string,
  option: any,
): boolean {
  const keyword = String(pattern ?? '').trim().toLowerCase();
  if (!keyword) return true;
  const label = String(option?.label ?? '').toLowerCase();
  const value = String(option?.value ?? '').toLowerCase();
  return label.includes(keyword) || value.includes(keyword);
}
