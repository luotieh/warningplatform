import { baseRequestClient, requestClient } from '#/api/request';

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
  const res = await baseRequestClient.get<any>('/cyberspace/search', { params });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: CyberAsset[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}

export async function hostLookup(ip: string) {
  const res = await baseRequestClient.get<any>('/cyberspace/host', { params: { ip } });
  const body = (res as Record<string, unknown>).data ?? res;
  const typed = body as { data?: CyberAsset[]; count?: number };
  return { items: typed.data ?? [], total: typed.count ?? 0 };
}

export interface CyberProvider {
  name: string;
  enabled: boolean;
}

export function getProviders() {
  return requestClient.get<CyberProvider[]>('/cyberspace/providers');
}
