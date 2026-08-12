# 流量事件列表筛选改造设计

- 日期: 2026-08-10
- 状态: 已实施并验证（180 服务器 dev.20260810）
- 范围: 仅 `views/ly/event/list/index.vue`（事件列表页筛选区），不改后端接口

## 1. 背景

现事件列表页筛选区存在两个无效筛选（后端硬编码字段），资产筛选仅支持
Naive UI 默认匹配，缺少常用检索能力。实测 21 条事件：

- `proc_status` 全部为 `unprocessed`（后端硬编码）→ 处理状态筛选无效；
- `is_alive` 全部为 `true`（后端硬编码）→ 活跃状态筛选无效；
- `level`：high=18 / middle=3，有区分度；
- `event_count`：17/21 大于 1，高频聚合可筛选；
- `review_status`/`circular_code` 当前全空，暂不纳入本期。

## 2. 目标

1. 删除「处理状态」「活跃状态」两个无效筛选；
2. 资产筛选支持模糊查询（按资产名称/地址包含匹配，如输入「徐工」匹配「徐工集团-…」）；
3. 新增「严重级别」「事件时间范围」「关键字/IP」三个筛选；
4. 全部为前端客户端过滤（数据源 `/api/traffic/events/list`），不改后端。

## 3. 筛选区设计（改造后）

筛选区布局（一行或按需换行）：

```
[严重级别] [起始时间] [结束时间] [关键字/IP] [资产筛选(模糊)] [仅看资产相关] [刷新]
```

### 3.1 删除项

- 处理状态 `state.proc_status`（移除 NSelect 与过滤逻辑）；
- 活跃状态 `state.is_alive`（移除 NSelect 与过滤逻辑）。

### 3.2 资产筛选（改造）

- 保留 `NSelect filterable` + 资产下拉，但自定义 `:filter`：
  - 匹配范围：资产名称（`name`）+ 地址（`address`），大小写不敏感、包含即可；
  - 例如输入 `徐工` 可匹配 `徐工集团-58.218.196.193`、`徐工出口-…`；
  - 匹配结果显示在原下拉中，未匹配自动隐藏；
- `selectedAsset` 与 `onlyAssetRelated` 逻辑保持不变。

### 3.3 严重级别（新增）

- 控件：`NSelect`（clearable，单选），选项：
  - `high` → 高危
  - `medium` → 中危
  - `low` → 低危
- 过滤逻辑：`item.level === 选中值`；
- 空值/清空 = 不过滤。

### 3.4 事件时间范围（新增）

- 控件：`NDatePicker`（date 或 datetime，按当前页面风格选 date），起始/结束两个或 range 模式；
- 默认范围：空（不过滤）；
- 过滤口径（推荐）：事件 `starttime`（首次命中时间）落在 `[start, end]` 闭区间；
- 辅助说明：也可选 `last_time` 口径，待确认（见 §6）。

### 3.5 关键字/IP（新增）

- 控件：`NInput`（clearable，placeholder：`关键字/IP`）；
- 过滤逻辑：对每条事件做**包含匹配**（大小写不敏感），匹配字段：
  - `attackDevice`（威胁来源）
  - `victimDevice`（受害目标）
  - `desc` / `rule_desc`（描述）
  - `type` / `typeText`（类型）
  - `event_id`
  - `ioc.ioc_value`、`ioc.ioc_type`（情报命中值/类型）
  - `evidence_files[].name`（证据文件名）
- 支持空格分词：多个关键字按 AND 匹配（每个词都要命中至少一个字段）。

## 4. 实现要点（待执行时）

- 在 `baseRows` 过滤链依次追加：严重级别 → 时间范围 → 关键字 → 资产（保留现有 rank 排行标签逻辑）；
- `RANK_LABELS` 与排行标签保留，不作删除；
- 关键字匹配工具函数建议放在 `#/utils/ly.ts`（`matchesEventKeyword(item, keyword)`）；
- 资产模糊匹配函数建议放 `#/utils/ly-asset.ts`（`assetOptionFilter(pattern, option)`）；
- 组件新增导入：`NInput`、`NDatePicker`（若页面未引入）。

## 5. 验收清单

1. 页面不再显示「处理状态」「活跃状态」；
2. 资产下拉输入 `徐工` 可匹配包含「徐工」名称的资产并正确过滤；
3. 严重级别选择 high → 只显示 high 事件；清空恢复；
4. 时间范围选择 2026-08-05 ~ 2026-08-06 → 只显示该区间事件；
5. 关键字输入 `185.230` → 匹配 attackDevice/victimDevice 含该串的事件；
6. 关键字 `c2 185.230`（空格分词）→ 两个词都命中才显示；
7. 排行标签、资产相关、分页/刷新功能不受影响；
8. 无后端改动，构建/类型检查通过。

## 6. 待确认

1. 时间范围口径：**已确认按 `starttime`（首次命中）过滤**；
2. 严重级别：**已确认单选 clearable**；
3. 关键字匹配字段：**已确认不加入 `event_name`/`message`**。
