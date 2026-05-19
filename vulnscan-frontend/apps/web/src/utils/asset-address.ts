import { isIPv4 } from '#/utils/validators';

const URL_FIRST_FAMILIES = new Set([
  'domain_site',
  'official_account',
  'mini_program',
  'business_system',
]);

const SCHEME_FIX_RE = /^(https?)\s*:\s*\/\s*/i;
const HOST_PORT_RE = /^([^/:[\s]+):(\d{1,5})(?:\/.*)?$/;
const DOMAIN_LIKE_RE =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?(?:\/.*)?$/i;
const MINI_PROGRAM_PATH_RE = /^[a-z0-9][a-z0-9/_-]*$/i;

export type AssetAccessAddressOptions = {
  allowEmpty?: boolean;
  assetFamily?: string;
};

/** 从访问地址解析出的网络字段（用于补全空项） */
export type DerivedAssetNetworkFields = {
  domain: string;
  ipv4: string;
  ipv6: string;
  port: number | null;
  protocol: string;
  url: string;
};

export type DeriveAssetNetworkFieldsOptions = {
  assetFamily?: string;
  /** 已有值则不覆盖对应字段 */
  existing?: Partial<DerivedAssetNetworkFields>;
};

const EMPTY_DERIVED: DerivedAssetNetworkFields = {
  domain: '',
  ipv4: '',
  ipv6: '',
  port: null,
  protocol: '',
  url: '',
};

function isIPv6Host(host: string): boolean {
  const text = host.trim();
  if (!text.includes(':')) return false;
  if (text.includes('.')) return false;
  try {
    const url = new URL(`http://[${text.replace(/^\[|\]$/g, '')}]/`);
    return Boolean(url.hostname.includes(':'));
  } catch {
    return false;
  }
}

function parseNormalizedAccessAddress(normalized: string): {
  host: string;
  port: number | null;
  protocol: string;
  url: string;
  isMiniProgramPath: boolean;
} | null {
  const text = normalized.trim();
  if (!text) return null;

  if (looksLikeMiniProgramPath(text)) {
    return {
      host: '',
      port: null,
      protocol: '',
      url: text,
      isMiniProgramPath: true,
    };
  }

  if (/^https?:\/\//i.test(text)) {
    try {
      const parsed = new URL(text);
      const host = parsed.hostname.replace(/^\[|\]$/g, '');
      const port = parsed.port !== '' ? Number(parsed.port) : null;
      return {
        host,
        port: port && port >= 1 && port <= 65535 ? port : null,
        protocol: parsed.protocol.replace(':', '').toLowerCase(),
        url: text,
        isMiniProgramPath: false,
      };
    } catch {
      return null;
    }
  }

  const hostPort = text.match(HOST_PORT_RE);
  if (hostPort) {
    const host = hostPort[1]!;
    const port = Number(hostPort[2]);
    return {
      host,
      port: port >= 1 && port <= 65535 ? port : null,
      protocol: '',
      url: '',
      isMiniProgramPath: false,
    };
  }

  if (isIPv4WithOptionalPort(text)) {
    const onlyHost = text.includes(':') ? text.split(':')[0]! : text;
    const portMatch = text.match(/^([^:]+):(\d+)$/);
    return {
      host: onlyHost,
      port: portMatch ? Number(portMatch[2]) : null,
      protocol: '',
      url: '',
      isMiniProgramPath: false,
    };
  }

  if (DOMAIN_LIKE_RE.test(text)) {
    const host = text.split('/')[0]!.split(':')[0]!;
    const portMatch = text.match(/:(\d{1,5})(?:\/|$)/);
    const port = portMatch ? Number(portMatch[1]) : null;
    return {
      host,
      port: port && port >= 1 && port <= 65535 ? port : null,
      protocol: '',
      url: '',
      isMiniProgramPath: false,
    };
  }

  return null;
}

/** 根据归一化后的访问地址推导 domain / ipv4 / port / url / protocol */
export function deriveAssetNetworkFieldsFromAccessAddress(
  rawAddress: string,
  options: DeriveAssetNetworkFieldsOptions = {},
): DerivedAssetNetworkFields {
  const normalized = normalizeAssetAccessAddress(rawAddress, {
    assetFamily: options.assetFamily,
  });
  if (!normalized) return { ...EMPTY_DERIVED };

  const parsed = parseNormalizedAccessAddress(normalized);
  if (!parsed) return { ...EMPTY_DERIVED };

  const derived: DerivedAssetNetworkFields = { ...EMPTY_DERIVED };

  if (parsed.isMiniProgramPath) {
    derived.url = parsed.url;
    return derived;
  }

  const host = parsed.host.trim();
  if (isIPv4(host)) {
    derived.ipv4 = host;
  } else if (isIPv6Host(host)) {
    derived.ipv6 = host.toLowerCase();
  } else if (host) {
    derived.domain = host.toLowerCase();
  }

  if (parsed.port != null) {
    derived.port = parsed.port;
  }
  if (parsed.protocol) {
    derived.protocol = parsed.protocol;
  }
  if (parsed.url) {
    derived.url = parsed.url;
  } else if (/^https?:\/\//i.test(normalized)) {
    derived.url = normalized;
  }

  return derived;
}

/** 将推导结果合并到目标对象，默认仅填充空字段 */
export function mergeDerivedNetworkFields<T extends Partial<DerivedAssetNetworkFields>>(
  target: T,
  derived: DerivedAssetNetworkFields,
  onlyEmpty = true,
): T {
  const out = { ...target };
  const assign = (
    key: keyof DerivedAssetNetworkFields,
    value: string | number | null,
  ) => {
    if (value == null || value === '') return;
    const current = out[key];
    if (onlyEmpty) {
      if (key === 'port') {
        if (current != null && current !== 0) return;
      } else if (String(current ?? '').trim() !== '') {
        return;
      }
    }
    (out as Record<string, unknown>)[key] = value;
  };

  assign('domain', derived.domain);
  assign('ipv4', derived.ipv4);
  assign('ipv6', derived.ipv6);
  assign('port', derived.port);
  assign('protocol', derived.protocol);
  assign('url', derived.url);
  return out;
}

function splitAddressParts(raw: string): string[] {
  const normalized = raw
    .replace(/[，；;\n\r\t]/g, ',')
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
  return normalized.length > 0 ? normalized : [raw.trim()].filter(Boolean);
}

function fixSchemeSpacing(raw: string): string {
  const match = raw.match(SCHEME_FIX_RE);
  if (!match) return raw.trim();
  const rest = raw.slice(match[0].length).trim().replace(/^\/+/, '');
  return `${match[1]!.toLowerCase()}://${rest}`;
}

function isIPv4WithOptionalPort(value: string): boolean {
  const hostPort = value.match(/^([^:]+):(\d+)$/);
  if (hostPort) {
    const port = Number(hostPort[2]);
    return isIPv4(hostPort[1]!) && port >= 1 && port <= 65535;
  }
  return isIPv4(value);
}

function looksLikeMiniProgramPath(value: string): boolean {
  const text = value.trim();
  if (!text || text.includes('://') || text.includes(' ')) return false;
  if (text.includes('.') && DOMAIN_LIKE_RE.test(text)) return false;
  return MINI_PROGRAM_PATH_RE.test(text);
}

function shouldPreferHttpScheme(assetFamily?: string, value?: string): boolean {
  if (assetFamily && URL_FIRST_FAMILIES.has(assetFamily)) return true;
  const text = String(value ?? '').trim();
  if (!text || isIPv4WithOptionalPort(text)) return false;
  if (looksLikeMiniProgramPath(text)) return false;
  return DOMAIN_LIKE_RE.test(text) || HOST_PORT_RE.test(text);
}

function normalizeURL(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    url.protocol = url.protocol.toLowerCase();
    url.hostname = url.hostname.toLowerCase();
    if (url.pathname === '/') url.pathname = '';
    let result = url.toString();
    if (result.endsWith('/') && !url.pathname) {
      result = result.slice(0, -1);
    }
    return result;
  } catch {
    return null;
  }
}

function normalizeHostLike(value: string, preferScheme: boolean): string {
  const trimmed = value.trim();
  const hostPort = trimmed.match(HOST_PORT_RE);
  if (hostPort) {
    const host = hostPort[1]!.toLowerCase();
    const port = hostPort[2]!;
    const hostIsIP = isIPv4(host);
    const normalized = `${host}:${port}`;
    if (hostIsIP || !preferScheme) return normalized;
    return `http://${normalized}`;
  }

  if (isIPv4WithOptionalPort(trimmed)) {
    return trimmed;
  }

  if (looksLikeMiniProgramPath(trimmed)) {
    return trimmed;
  }

  if (DOMAIN_LIKE_RE.test(trimmed)) {
    const lower = trimmed.toLowerCase();
    return preferScheme ? `http://${lower}` : lower;
  }

  return trimmed;
}

/** 归一化访问地址：修正协议空格、统一 http(s) 大小写、域名类补全 http:// */
export function normalizeAssetAccessAddress(
  raw: string,
  options: AssetAccessAddressOptions = {},
): string {
  const text = fixSchemeSpacing(String(raw ?? '').trim());
  if (!text) return '';

  const preferScheme = shouldPreferHttpScheme(options.assetFamily, text);

  if (/^https?:\/\//i.test(text)) {
    return normalizeURL(fixSchemeSpacing(text)) ?? text;
  }

  if (text.includes('://')) {
    return text;
  }

  return normalizeHostLike(text, preferScheme);
}

/** 校验访问地址；空串在 allowEmpty 时通过 */
export function validateAssetAccessAddress(
  raw: string,
  options: AssetAccessAddressOptions = {},
): string | null {
  const text = String(raw ?? '').trim();
  if (!text) {
    return options.allowEmpty ? null : '请填写访问地址';
  }

  const parts = splitAddressParts(text);
  if (parts.length > 1) {
    return '访问地址仅支持填写一个目标；多个请分别登记资产，或使用 IPv4 字段填写多个 IP';
  }

  const candidate = fixSchemeSpacing(parts[0]!);

  if (candidate.includes('://') && !/^https?:\/\//i.test(candidate)) {
    return '仅支持 http:// 或 https:// 协议';
  }

  if (/^https?:\/\//i.test(candidate)) {
    if (!normalizeURL(candidate)) {
      return 'URL 格式不正确，请检查协议与主机名';
    }
    return null;
  }

  if (isIPv4WithOptionalPort(candidate)) {
    return null;
  }

  if (looksLikeMiniProgramPath(candidate)) {
    return null;
  }

  if (DOMAIN_LIKE_RE.test(candidate) || HOST_PORT_RE.test(candidate)) {
    return null;
  }

  return '访问地址格式不正确，请填写域名、URL、IP 或 IP:端口';
}
