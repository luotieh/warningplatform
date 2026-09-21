import { describe, expect, it } from 'vitest';

import {
  assetMatchesEvent,
  countAssetEvents,
  eventAssetNames,
  eventMatchesAnyAsset,
  eventVictimAssets,
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

  it('eventAssetNames returns deduped enabled asset names', () => {
    const assets = [
      { name: '徐工集团', address: '10.0.0.9', status: 1 },
      { name: '徐工出口', address: '10.0.0.9', status: 1 },
      { name: '停用资产', address: '172.16.0.1', status: 0 },
      { name: '目标资产', address: '10.0.0.20', status: 1 },
    ];
    expect(
      eventAssetNames({ attackDevice: '10.0.0.9', victimDevice: '10.0.0.20' }, assets),
    ).toEqual(['徐工集团', '徐工出口', '目标资产']);
    expect(eventAssetNames({ attackDevice: '8.8.8.8', victimDevice: '8.8.4.4' }, assets)).toEqual([]);
    // 停用资产不参与匹配
    expect(eventAssetNames({ attackDevice: '172.16.0.1' }, assets)).toEqual([]);
  });

  it('eventVictimAssets matches only the victim side', () => {
    const assets = [
      { name: '财务服务器', address: '10.0.0.8', status: 1 },
      { name: '边界设备', address: '1.2.3.4', status: 1 },
      { name: '徐工网段', address: '58.218.177.128/27', asset_type: 'ip_segment', status: 1 },
      { name: '停用资产', address: '10.0.0.8', status: 0 },
    ];
    // 目标侧命中：返回「名称（地址）」，停用资产不参与
    expect(eventVictimAssets({ attackDevice: 'x', victimDevice: '10.0.0.8' }, assets)).toEqual([
      '财务服务器（10.0.0.8）',
    ]);
    // 来源侧命中不计入——威胁情报卡片关心的是受害者
    expect(eventVictimAssets({ attackDevice: '10.0.0.8', victimDevice: 'x' }, assets)).toEqual([]);
    // 网段资产按包含匹配
    expect(eventVictimAssets({ attackDevice: 'x', victimDevice: '58.218.177.150' }, assets)).toEqual([
      '徐工网段（58.218.177.128/27）',
    ]);
    // 无名资产回退地址；空受害地址返回空
    expect(eventVictimAssets({ attackDevice: 'x', victimDevice: '1.2.3.4' }, assets)).toEqual([
      '边界设备（1.2.3.4）',
    ]);
    expect(eventVictimAssets({ attackDevice: 'x', victimDevice: '' }, assets)).toEqual([]);
  });
});
