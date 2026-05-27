/**
 * 声明式路由权限系统
 *
 * 权限码由路由路径自动推导，不需要手动维护常量文件。
 *
 * 推导规则：
 *   路由 path  "/identity/user"  → namespace "identity:user"
 *   action     "create"          → 完整码    "identity:user:create"
 *
 * 使用方式：
 *   路由定义中声明 meta.perms: [{ action: 'create', title: '新增用户' }]
 *   组件中使用    v-perm="perm('create')"
 */

export interface RoutePerm {
  action: string;
  title: string;
}

export type BackendApiRef = string;

export interface RouteMetaPermOptions {
  perm_ns?: string;
  permNs?: string;
  permission_ns?: string;
  permissionNs?: string;
  resource_key?: string;
  resourceKey?: string;
  perms?: Array<RoutePerm | string>;
  /**
   * 页面只读接口（同步为 `{namespace}:access`）。
   * 仅放 GET/HEAD 类；POST/PUT/DELETE 必须写在 apisByAction 对应按钮上。
   */
  apis?: BackendApiRef[];
  /** 按钮级接口（同步为 `{namespace}:{action}` 按钮权限码，与 :access 分离） */
  apisByAction?: Record<string, BackendApiRef[]>;
}

/**
 * 将路由路径转换为权限命名空间
 * /identity/user → identity:user
 * /authorize/role → authorize:role
 * /governance/risk-case → governance:risk-case
 */
export function pathToNamespace(routePath: string): string {
  return routePath
    .replace(/^\/+/, '')
    .replace(/\/+$/, '')
    .split('/')
    .filter(Boolean)
    .map((s) => (s.startsWith(':') ? s.slice(1) : s))
    .join(':');
}

export function normalizeNamespace(input: string): string {
  return input
    .trim()
    .replace(/\./g, ':')
    .replace(/\//g, ':')
    .replace(/:+/g, ':')
    .replace(/^:+|:+$/g, '');
}

/**
 * 生成完整权限码
 */
export function buildPermCode(namespace: string, action: string): string {
  const ns = normalizeNamespace(namespace);
  const act = normalizeNamespace(action);
  return `${ns}:${act}`;
}

/**
 * 从路由 meta 中提取 perms 声明
 */
export function getRoutePerms(meta: RouteMetaPermOptions): RoutePerm[] {
  if (!Array.isArray(meta.perms)) return [];
  return meta.perms
    .map((p) => {
      if (typeof p === 'string') {
        const action = p.trim();
        if (!action) return null;
        return { action, title: action };
      }
      if (!p || typeof p !== 'object') return null;
      const action = String(p.action || '').trim();
      if (!action) return null;
      const raw = p as Record<string, unknown>;
      const title = String(raw.title || raw.label || action).trim();
      return { action, title };
    })
    .filter((p): p is RoutePerm => Boolean(p));
}

/**
 * 解析权限命名空间（支持 meta 中显式声明，避免路由路径变更导致权限码漂移）
 */
export function resolvePermNamespace(
  meta: RouteMetaPermOptions,
  routePath: string,
): string {
  const explicit =
    meta.permNs ||
    meta.perm_ns ||
    meta.permissionNs ||
    meta.permission_ns ||
    meta.resourceKey ||
    meta.resource_key;
  const raw = String(explicit || '').trim();
  if (raw) {
    return normalizeNamespace(raw);
  }
  return pathToNamespace(routePath);
}

/**
 * 创建当前路由的权限码生成器
 *
 * @example
 * const perm = createPermResolver('/identity/user');
 * perm('create')  // → 'identity:user:create'
 * perm('delete')  // → 'identity:user:delete'
 */
export function createPermResolver(routePath: string): (action: string) => string {
  const ns = pathToNamespace(routePath);
  return (action: string) => buildPermCode(ns, action);
}

function normalizeApiRef(ref: string): string | null {
  const s = String(ref || '').trim();
  if (!s) return null;
  const m = s.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)/i);
  if (!m) return null;
  let path = m[2];
  if (!path.startsWith('/')) path = `/${path}`;
  if (!path.startsWith('/api/') && path !== '/api') {
    path = `/api${path}`;
  }
  return `${m[1].toUpperCase()} ${path}`;
}

export function getRouteApis(meta: RouteMetaPermOptions): string[] {
  if (!Array.isArray(meta.apis)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of meta.apis) {
    const n = normalizeApiRef(String(raw));
    if (!n || seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

/** 页面 :access 用：meta.apis 减去已分配给按钮的接口，避免重复绑定 */
export function getRouteApisForPageAccess(meta: RouteMetaPermOptions): string[] {
  const page = getRouteApis(meta);
  const byAction = getRouteApisByAction(meta);
  const onButton = new Set<string>();
  for (const refs of Object.values(byAction)) {
    for (const r of refs) onButton.add(r);
  }
  return page.filter((r) => !onButton.has(r));
}

export interface RoutePermBindingIssue {
  action: string;
  kind: 'missing_apis' | 'mutating_in_page_apis';
  message: string;
}

/** 校验按钮是否声明了 apisByAction（开发/同步前检查） */
export function validateRoutePermBindings(
  meta: RouteMetaPermOptions,
): RoutePermBindingIssue[] {
  const issues: RoutePermBindingIssue[] = [];
  const perms = getRoutePerms(meta);
  const byAction = getRouteApisByAction(meta);
  const pageApis = getRouteApis(meta);
  const writeMethods = /^(POST|PUT|PATCH|DELETE)\s/i;

  for (const p of perms) {
    const refs = byAction[p.action];
    if (!refs?.length) {
      issues.push({
        action: p.action,
        kind: 'missing_apis',
        message: `按钮「${p.title}」(action=${p.action}) 未配置 apisByAction，无法做按钮级 API 授权`,
      });
    }
  }
  for (const ref of pageApis) {
    if (writeMethods.test(ref)) {
      issues.push({
        action: '_page',
        kind: 'mutating_in_page_apis',
        message: `页面 apis 含写操作 ${ref}，应移到 apisByAction`,
      });
    }
  }
  return issues;
}

export function getRouteApisByAction(
  meta: RouteMetaPermOptions,
): Record<string, string[]> {
  const map = (meta as Record<string, any>).apisByAction;
  if (!map || typeof map !== 'object') return {};
  const out: Record<string, string[]> = {};
  for (const [action, refs] of Object.entries(map)) {
    if (!Array.isArray(refs)) continue;
    const list: string[] = [];
    const seen = new Set<string>();
    for (const raw of refs) {
      const n = normalizeApiRef(String(raw));
      if (!n || seen.has(n)) continue;
      seen.add(n);
      list.push(n);
    }
    if (list.length) out[action] = list;
  }
  return out;
}
