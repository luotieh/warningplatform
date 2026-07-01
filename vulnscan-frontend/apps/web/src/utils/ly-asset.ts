export function normalizeAddr(v?: string): string {
  return String(v ?? '').trim().toLowerCase();
}

interface EventLike {
  attackDevice?: string;
  victimDevice?: string;
}
interface AssetLike {
  address?: string;
  status?: number;
}

export function assetMatchesEvent(asset: AssetLike, event: EventLike): boolean {
  const addr = normalizeAddr(asset.address);
  if (!addr) return false;
  return (
    normalizeAddr(event.attackDevice) === addr ||
    normalizeAddr(event.victimDevice) === addr
  );
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
