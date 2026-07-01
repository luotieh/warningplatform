import { describe, expect, it } from 'vitest';

import {
  assetMatchesEvent,
  countAssetEvents,
  eventMatchesAnyAsset,
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

  it('eventMatchesAnyAsset only considers enabled assets', () => {
    const assets = [
      { address: '10.0.0.9', status: 0 },
      { address: '1.1.1.1', status: 1 },
    ];
    expect(eventMatchesAnyAsset({ attackDevice: '1.1.1.1' }, assets)).toBe(true);
    expect(eventMatchesAnyAsset({ attackDevice: '10.0.0.9' }, assets)).toBe(false);
  });
});
