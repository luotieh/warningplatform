import { describe, expect, it } from 'vitest';

import {
  deriveAssetNetworkFieldsFromAccessAddress,
  normalizeAssetAccessAddress,
  validateAssetAccessAddress,
} from './asset-address';

describe('normalizeAssetAccessAddress', () => {
  it('fixes spaced scheme', () => {
    expect(normalizeAssetAccessAddress('http: //oa.example.com')).toBe(
      'http://oa.example.com',
    );
  });

  it('lowercases scheme and host', () => {
    expect(normalizeAssetAccessAddress('HTTP://OA.Example.COM/path')).toBe(
      'http://oa.example.com/path',
    );
  });

  it('adds http for bare domain when asset family is domain_site', () => {
    expect(
      normalizeAssetAccessAddress('jspxxw.com', { assetFamily: 'domain_site' }),
    ).toBe('http://jspxxw.com');
  });

  it('keeps ipv4 without scheme', () => {
    expect(normalizeAssetAccessAddress('49.65.127.74:99')).toBe('49.65.127.74:99');
  });
});

describe('validateAssetAccessAddress', () => {
  it('rejects multiple comma-separated urls', () => {
    expect(
      validateAssetAccessAddress(
        'http://a.example.com, http://b.example.com',
      ),
    ).toContain('仅支持填写一个');
  });

  it('accepts single normalized url', () => {
    expect(validateAssetAccessAddress('http://oa.example.com')).toBeNull();
  });
});

describe('deriveAssetNetworkFieldsFromAccessAddress', () => {
  it('derives domain and url from http url', () => {
    const derived = deriveAssetNetworkFieldsFromAccessAddress(
      'http://peixian.cm.jstv.com/path',
      { assetFamily: 'domain_site' },
    );
    expect(derived.domain).toBe('peixian.cm.jstv.com');
    expect(derived.url).toBe('http://peixian.cm.jstv.com/path');
    expect(derived.protocol).toBe('http');
  });

  it('derives ipv4 and port from ip:port', () => {
    const derived = deriveAssetNetworkFieldsFromAccessAddress('49.65.127.74:99');
    expect(derived.ipv4).toBe('49.65.127.74');
    expect(derived.port).toBe(99);
    expect(derived.domain).toBe('');
  });

  it('derives domain from bare hostname', () => {
    const derived = deriveAssetNetworkFieldsFromAccessAddress('jspxxw.com', {
      assetFamily: 'domain_site',
    });
    expect(derived.domain).toBe('jspxxw.com');
  });
});
