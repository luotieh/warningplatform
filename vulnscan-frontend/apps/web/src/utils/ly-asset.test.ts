import { describe, expect, it } from 'vitest';

import {
  assetMatchesEvent,
  countAssetEvents,
  eventMatchesAnyAsset,
  ipInSegment,
  normalizeAddr,
} from './ly-asset';

describe('ly-asset', () => {
  it('normalizeAddr trims and lowercases', () => {
    expect(normalizeAddr('  Example.COM ')).toBe('example.com');
    expect(normalizeAddr(undefined)).toBe('');
  });

  it('assetMatchesEvent matches attacker or victim', () => {
    const asset = { address: '10.0.0.9' };
    expect(assetMatchesEvent(asset, { attackDevice: '10.0.0.9', victimDevice: 'x' })).toBe(true);
    expect(assetMatchesEvent(asset, { attackDevice: 'x', victimDevice: '10.0.0.9' })).toBe(true);
    expect(assetMatchesEvent(asset, { attackDevice: 'a', victimDevice: 'b' })).toBe(false);
  });

  it('countAssetEvents counts matches', () => {
    const events = [
      { attackDevice: '10.0.0.9', victimDevice: 'x' },
      { attackDevice: 'y', victimDevice: '10.0.0.9' },
      { attackDevice: 'a', victimDevice: 'b' },
    ];
    expect(countAssetEvents({ address: '10.0.0.9' }, events)).toBe(2);
  });

  it('ipInSegment handles cidr and dotted mask', () => {
    expect(ipInSegment('222.187.92.7', '222.187.92.0/24')).toBe(true);
    expect(ipInSegment('222.187.93.7', '222.187.92.0/24')).toBe(false);
    expect(ipInSegment('36.154.169.30', '36.154.169.2/255.255.255.224')).toBe(true);
    expect(ipInSegment('36.154.169.33', '36.154.169.2/255.255.255.224')).toBe(false);
    expect(ipInSegment('1.2.3.4', 'not-a-segment')).toBe(false);
    expect(ipInSegment('1.2.3.4', '1.2.3.0/255.255.0.1')).toBe(false); // 非连续掩码
  });

  it('assetMatchesEvent supports ip_segment containment', () => {
    const seg = { address: '58.218.177.128/27', asset_type: 'ip_segment' };
    expect(assetMatchesEvent(seg, { attackDevice: '58.218.177.150', victimDevice: 'x' })).toBe(true);
    expect(assetMatchesEvent(seg, { attackDevice: 'x', victimDevice: '58.218.177.129' })).toBe(true);
    expect(assetMatchesEvent(seg, { attackDevice: '58.218.177.1', victimDevice: 'x' })).toBe(false);
  });

  it('eventMatchesAnyAsset only considers enabled assets', () => {
    const assets = [
      { address: '10.0.0.9', status: 0 },
      { address: '1.1.1.1', status: 1 },
    ];
    expect(eventMatchesAnyAsset({ attackDevice: '1.1.1.1' }, assets)).toBe(true);
    expect(eventMatchesAnyAsset({ attackDevice: '10.0.0.9' }, assets)).toBe(false);
  });
});
