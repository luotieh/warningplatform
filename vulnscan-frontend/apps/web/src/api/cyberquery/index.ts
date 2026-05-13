import { baseRequestClient, requestClient } from '#/api/request';
import { normalizePagedResponse } from '#/api/helpers';

export interface CyberAsset {
  ip: string;
  port: number;
  protocol: string;
  service: string;
  version: string;
  banner: string;
  os: string;
  hostname: string;
  domains: string[];
  country: string;
  city: string;
  asn: number;
  org: string;
  isp: string;
  title: string;
  cert?: { subject: string; issuer: string; sans: string[]; expired: boolean };
  tags: string[];
  source: string;
  last_seen: string;
}

export async function searchCyberspace(params: { q: string; provider?: string; max?: number }) {
  const res = await baseRequestClient.get<any>('/cyberquery/search', { params });
  return normalizePagedResponse<CyberAsset>(res);
}

export async function hostLookup(ip: string) {
  const res = await baseRequestClient.get<any>('/cyberquery/host', { params: { ip } });
  return normalizePagedResponse<CyberAsset>(res);
}

export interface CyberProvider {
  name: string;
  enabled: boolean;
}

export function getProviders() {
  return requestClient.get<CyberProvider[]>('/cyberquery/providers');
}
