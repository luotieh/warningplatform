/** 拆分多个 IPv4（逗号/分号/空格） */
export function splitIPv4List(raw: string): string[] {
  const text = raw.trim();
  if (!text) return [];
  return text
    .replace(/[，；;\n\t]/g, ',')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function isIPv4(value: string): boolean {
  const parts = value.trim().split('.');
  if (parts.length !== 4 || value.includes('/')) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255 && String(n) === String(Number(p));
  });
}

/** 空字符串通过 */
export function validateIPv4List(raw: string): string | null {
  const parts = splitIPv4List(raw);
  if (parts.length === 0) return null;
  const invalid = parts.find((p) => !isIPv4(p));
  if (invalid) return `IPv4 地址格式不正确：${invalid}`;
  return null;
}

/** port 为 null/undefined/0 时通过 */
export function validatePort(port: number | null | undefined): string | null {
  if (port == null || port === 0) return null;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return '端口须在 1–65535 之间';
  }
  return null;
}

const USCC_CHARSET = '0123456789ABCDEFGHJKLMNPQRTUWXY';
const USCC_WEIGHTS = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28];

function usccCharIndex(ch: string): number {
  return USCC_CHARSET.indexOf(ch);
}

function usccCheckIndex(body: string): number {
  let sum = 0;
  for (let i = 0; i < 17; i += 1) {
    const idx = usccCharIndex(body[i]!);
    if (idx < 0) return -1;
    sum += idx * USCC_WEIGHTS[i]!;
  }
  return (31 - (sum % 31)) % 31;
}

/** 空字符串通过 */
export function validateUSCC(raw: string): string | null {
  const code = raw.trim().toUpperCase();
  if (!code) return null;
  if (code.length !== 18) return '统一社会信用代码须为 18 位';
  const body = code.slice(0, 17);
  if ([...body].some((ch) => usccCharIndex(ch) < 0)) {
    return '统一社会信用代码含有非法字符';
  }
  const expected = USCC_CHARSET[usccCheckIndex(body)]!;
  if (code[17] !== expected) return '统一社会信用代码校验位不正确';
  return null;
}

function normalizePhoneInput(raw: string): string {
  let s = raw.trim().replace(/\s+/g, '').replace(/-/g, '');
  if (s.startsWith('+86')) s = s.slice(3);
  else if (s.startsWith('86') && s.length > 11) s = s.slice(2);
  return s;
}

const CN_MOBILE_RE = /^1[3-9]\d{9}$/;
const CN_LANDLINE_RE = /^0\d{10,11}$/;

/** 空字符串通过 */
export function validateCNPhone(raw: string, label = '电话号码'): string | null {
  const s = normalizePhoneInput(raw);
  if (!s) return null;
  if (CN_MOBILE_RE.test(s) || CN_LANDLINE_RE.test(s)) return null;
  return `${label}格式不正确，请填写 11 位手机号或带区号的固话`;
}

export type UnitProfileFields = {
  unified_social_credit_code?: string;
  department_leader_phone?: string;
  contact_phone?: string;
};

export function validateUnitProfile(extra: UnitProfileFields): string | null {
  const uscc = validateUSCC(extra.unified_social_credit_code ?? '');
  if (uscc) return uscc;
  const dept = validateCNPhone(extra.department_leader_phone ?? '', '负责人电话');
  if (dept) return dept;
  const contact = validateCNPhone(extra.contact_phone ?? '', '联系人电话');
  if (contact) return contact;
  return null;
}
