# CLAUDE.md - 子系统前端开发指南

Vue 3 + TypeScript + Naive UI + Vben Admin | 应用目录：`apps/web/`

## 构建与运行

```bash
pnpm install && pnpm dev   # 开发模式，默认 http://localhost:5889
```

---

## 权限系统

权限流转：**路由 `meta.perms` 声明 -> 同步菜单到 IAM -> IAM 分配角色权限 -> 用户登录获取权限码 -> 运行时校验**

### 1. 路由模块（`apps/web/src/router/routes/modules/*.ts`）

```typescript
import type { RouteRecordRaw } from 'vue-router';
import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:box', order: 10, title: '模块名' },
    name: 'MyModule',
    path: '/my-module',
    children: [
      {
        name: 'MyModuleList',
        path: 'list',
        component: () => import('#/views/my-module/list.vue'),
        meta: {
          icon: 'lucide:list',
          title: '列表页',
          // 按钮级权限声明（同步到 IAM 后可做细粒度控制）
          perms: [
            { action: 'create', label: '新建' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
        },
      },
      {
        name: 'MyModuleDetail',
        path: 'detail/:id',
        component: () => import('#/views/my-module/detail.vue'),
        meta: {
          hideInMenu: true,
          title: '详情页',
        },
      },
    ],
  },
];
export default routes;
```

### 2. 权限命名空间解析

命名空间从路由路径自动推导：`/my-module/list` -> `my-module:list`

完整权限码 = `命名空间:动作`，例如 `my-module:list:create`

核心函数（`permissions/route-perm.ts`）：
- `pathToNamespace(routePath)` -- 路径转命名空间
- `buildPermCode(namespace, action)` -- 构建完整权限码
- `createPermResolver(routePath)` -- 创建当前路由的权限码生成器

### 3. 运行时权限校验

**组件内 -- 使用 `usePerm()`：**
```typescript
import { usePerm } from '#/composables/usePerm';

const { can, canAll, canAny, isSuper, hasRole } = usePerm();
can('my-module:list:create')         // 校验单个权限码
canAll(['a:b:c', 'x:y:z'])          // 全部满足
canAny(['a:b:c', 'x:y:z'])          // 任一满足
hasRole('admin')                     // 检查角色
```

**使用路由推导的权限码：**
```typescript
import { createPermResolver } from '#/permissions/route-perm';

const perm = createPermResolver('/my-module/list');
perm('create')  // → 'my-module:list:create'
perm('delete')  // → 'my-module:list:delete'
```

**模板中 -- 使用 `v-perm` 指令：**
```vue
<button v-perm="'my-module:list:create'">新建</button>
<button v-perm.disable="'my-module:list:delete'">删除</button>  <!-- 无权限时禁用而非隐藏 -->
<button v-perm.all="['a:b:update', 'a:b:delete']">批量操作</button>
```

### 4. 智能放行规则

权限校验按以下顺序判断，命中即放行：
1. 用户拥有 super 角色，或拥有通配权限 `*:*`
2. 用户角色包含 admin / administrator / superadmin
3. 待校验权限码的命名空间在 accessCodes 中无任何同命名空间码（系统未启用按钮权限，默认放行）
4. 否则严格校验 accessCodes 是否包含该码

---

## API 模块规范（`apps/web/src/api/<domain>/*.ts`）

API 路径遵循 RESTful 风格，资源名使用复数名词：

```typescript
import { baseRequestClient, requestClient } from '#/api/request';

export interface OrderItem {
  id: string;
  name: string;
  status: number;
  created_at: string;
}

// 列表（需要 count -> 使用 baseRequestClient）
export async function getOrderList(params?: Record<string, any>) {
  const res = await baseRequestClient.get<any>('/orders', { params });
  const body = res.data ?? res;
  return {
    items: (body.data ?? []) as OrderItem[],
    total: body.count ?? 0,
  };
}

// 详情
export function getOrderDetail(id: string) {
  return requestClient.get<OrderItem>(`/orders/${id}`);
}

// 创建
export function createOrder(data: Partial<OrderItem>) {
  return requestClient.post('/orders', data);
}

// 更新
export function updateOrder(id: string, data: Partial<OrderItem>) {
  return requestClient.put(`/orders/${id}`, data);
}

// 删除
export function deleteOrder(id: string) {
  return requestClient.delete(`/orders/${id}`);
}
```

**客户端选择：**
- `requestClient` -- 自动解包 `response.data.data`（code=2000 时），用于单条数据接口
- `baseRequestClient` -- 返回原始 Axios 响应，用于需要同时获取 `data` 和 `count` 的列表接口

---

## CRUD 页面标准模式（`composables/useCrudPage`）

```vue
<script lang="ts" setup>
import { NButton } from 'naive-ui';
import { useCrudPage } from '#/composables/useCrudPage';
import { useActionColumn } from '#/components/table/use-action-column';
import { renderEnabled, renderTimeCell } from '#/components/table/cell-renderers';
import { createPermResolver } from '#/permissions/route-perm';
import { getMyItemList, createMyItem, updateMyItem, deleteMyItem } from '#/api/my-module';
import type { MyItem } from '#/api/my-module';
import BasePageContainer from '#/components/page/base-page-container.vue';

const perm = createPermResolver('/my-module/list');

const renderActions = useActionColumn<MyItem>([
  { label: '编辑', onClick: (row) => crud.openEdit(row), perm: perm('update') },
  { label: '删除', type: 'error', confirm: '确认删除？',
    onClick: (row) => crud.remove(row), perm: perm('delete') },
]);

const crud = useCrudPage<MyItem>({
  name: 'my-item',
  api: {
    list: getMyItemList,
    create: createMyItem,
    update: (id, data) => updateMyItem(id as number, data),
    remove: (id) => deleteMyItem(id as number),
  },
  columns: [
    { field: 'name', title: '名称' },
    { field: 'status', title: '状态',
      slots: { default: ({ row }: any) => renderEnabled(row.status) } },
    { field: 'created_at', title: '创建时间', width: 180,
      slots: { default: ({ row }: any) => renderTimeCell(row.created_at) } },
    { field: 'action', title: '操作', width: 200, fixed: 'right',
      slots: { default: ({ row }: any) => renderActions(row) } },
  ],
});
</script>

<template>
  <BasePageContainer title="列表管理" :selected-count="crud.selectedCount.value">
    <template #actions>
      <NButton v-perm="perm('create')" type="primary" @click="crud.openCreate()">新建</NButton>
    </template>
    <crud.Grid />
    <template #extra>
      <!-- 弹窗组件 -->
    </template>
  </BasePageContainer>
</template>
```

### useCrudPage 配置项

| 选项 | 类型 | 说明 |
|------|------|------|
| `name` | `string` | 业务名，用于日志/提示 |
| `api` | `CrudApi<T>` | CRUD API 函数集 |
| `idKey` | `string` | 主键字段名，默认 `id` |
| `columns` | `any[]` | VxeTable 列配置 |
| `pageSize` | `number` | 默认分页大小，默认 20 |
| `selectable` | `boolean` | 是否启用多选 |
| `identify` | `(row) => string` | 提取展示名（用于消息提示） |
| `prepareSubmit` | `fn` | 提交前 payload 转换 |
| `transformList` | `fn` | 列表响应转换 |
| `customSubmit` | `fn` | 自定义提交逻辑 |

### useCrudPage 返回值

| 属性/方法 | 说明 |
|-----------|------|
| `Grid` | VxeGrid 组件 |
| `showModal` / `modalMode` / `editingRow` | 弹窗状态 |
| `selectedRows` / `selectedCount` / `selectedIds` | 选择状态 |
| `openCreate()` / `openEdit(row)` | 打开新增/编辑弹窗 |
| `handleSubmit(payload)` | 弹窗提交 |
| `remove(row)` / `batchRemove()` | 删除单条/批量删除 |
| `refresh()` | 刷新列表 |
| `handleFilter(payload)` | 筛选变更 |

---

## 共享组件

| 组件 | 用途 |
|------|------|
| `BasePageContainer` | 标准列表页外壳，包含筛选/操作/选择工具栏 |
| `BaseTreeDetailPage` | 树形 + 详情面板布局 |
| `useActionColumn` | 表格行操作按钮，集成权限控制和二次确认 |

### 单元格渲染器（`components/table/cell-renderers.tsx`）

| 渲染器 | 用途 |
|--------|------|
| `renderEnabled(value)` | 启用/停用状态 Tag |
| `renderEnum(value, enums)` | 枚举值映射 Tag |
| `renderStatus(value, options)` | 通用状态 Tag |
| `renderBoolean(value)` | 布尔值（是/否） |
| `renderText(value)` | 文本（含空值占位） |
| `renderEllipsis(value, max)` | 截断 + Tooltip |
| `renderTimeCell(value)` | 时间（主时间 + 相对时间副行） |
| `renderNumber(value)` | 数字千分位 |
| `renderCopyText(value)` | 点击复制 |
| `renderLink(options)` | 链接按钮 |
| `renderUserCell(input)` | 头像 + 主副标题 |
| `renderDot(value, enums)` | 圆点 + 文字状态 |
| `renderJSON(value)` | JSON 缩略展示 |
| `renderTwoLine(primary, secondary)` | 双行文本 |

---

## Composables

| Composable | 用途 |
|------------|------|
| `useCrudPage` | 完整的 CRUD 页面编排（列表/分页/筛选/新增/编辑/删除/批量） |
| `usePerm` | 权限校验（`can`/`canAll`/`canAny`/`hasRole`/`isSuper`） |
| `useBatchOps` | 并发批量操作（含进度跟踪） |
| `useRemoteSelect` | 分页远程选择器（含搜索） |
| `useIamNotifications` | IAM 通知轮询 |
| `usePolling` | 智能轮询（感知页面可见性） |

---

## 菜单同步

前端采用 `accessMode: 'backend'` 模式，菜单由 IAM 统一管理：

1. 前端路由模块定义菜单结构和按钮权限（`meta.perms`）
2. 管理员在「系统管理 → 系统初始化」页面点击同步 -> 推送到 IAM
3. IAM 后台为不同角色分配可见菜单和按钮权限
4. 用户登录后从 IAM 获取已分配的菜单

若 IAM 尚未同步菜单，前端自动降级为本地路由模式，确保管理员仍可访问。

---

## 新增模块清单

1. 创建 API 模块：`apps/web/src/api/my-module/index.ts`，定义接口类型 + CRUD 函数
2. 创建路由模块：`apps/web/src/router/routes/modules/my-module.ts`，配置 `meta.perms`
3. 创建视图：`apps/web/src/views/my-module/list.vue` + 弹窗组件
4. 使用 `useCrudPage` + `useActionColumn` + `BasePageContainer` + 单元格渲染器
5. 在「系统初始化」页面重新同步菜单

---

## 核心约定

- 列表 API 需要 `count` 时使用 `baseRequestClient`；单条数据 API 使用 `requestClient`
- 权限命名空间从路由路径自动推导，无需手动维护常量
- 权限声明通过 `meta.perms` 数组，格式 `{ action: string, label: string }`
- 新增路由后需重新同步菜单到 IAM
- `BasicLayout` 是所有一级路由模块的必备 `component`
