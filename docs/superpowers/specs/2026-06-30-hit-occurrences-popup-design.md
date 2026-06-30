# 命中频次点击弹窗（每次命中时间 + 数据包大小 + 包数）设计

- 日期：2026-06-30
- 分支：`trafficanalysis`
- 约束：**仅修改流量分析侧**——`vulnscan-backend/traffic/**` 与前端 `vulnscan-frontend/apps/web/src/{views/ly,store,utils}` 内与流量分析相关的文件；不碰 `circular/`、`di/`、`scanrunner/`、`model/` 等其它模块。

## 1. 背景与目标

流量分析「事件列表」的「命中频次」列目前展示聚合命中次数与收敛状态（active/closed）。用户希望点击该列弹窗，查看**每次命中的具体时间、数据包大小、包数**。

现状数据：每条聚合事件的 `context.occurrences` 只保留了**每次命中的时间字符串**（上限 200 条，见 `event_mapping.go:65-68` 初始构造、`services.go:127-142` 合并追加）。ta_node 每次上报其实带了 `wire_bytes`（在线字节，含 L2-L4 头）、`bytes`（载荷字节）、`packets`（包数）等（`event_mapping.go:114` 收进 `flow_stats`），但合并时未按次保留字节/包数。

**目标：** 后端按次记录数据包大小（`wire_bytes`）与包数（`packets`）；前端「命中频次」列加可点击入口，弹窗以表格展示每次命中的 序号 / 时间 / 数据包大小 / 包数。

## 2. 关键决策（已与用户确认）

1. **后端按次记录字节数**：把 `occurrences` 从「时间字符串列表」升级为「对象列表」。
2. **数据包大小口径 = `wire_bytes`**（在线字节，含 L2-L4 头）。
3. **弹窗列**：序号 + 命中时间 + 数据包大小（wire_bytes）+ 包数（packets）。
4. **命中频次列入口 = 方案 B**：在现有频次 tag 旁单独加一个「明细」小链接，`occurrences` 非空才显示；不让整个 tag 可点（避免与筛选误触）。
5. **不新增后端接口**：弹窗使用列表已加载的 `row.occurrences`，无需额外请求。

## 3. 后端改动（traffic）

### 3.1 occurrence 记录结构
每条记录为对象（JSON 写入 `context.occurrences`）：
```json
{ "time": "2026-06-30T09:00:00Z", "wire_bytes": 1480, "packets": 3 }
```
- `time`：RFC3339 命中时间（来源同现有 `occ`：`ly["occurrence_time"]` 回退 `ly["time"]`）。
- `wire_bytes`：整数，取 `ly["wire_bytes"]`；缺失则省略该键（不写 0，便于前端区分"无数据"）。
- `packets`：整数，取 `ly["packets"]`；缺失则省略该键。

### 3.2 构造点
- `traffic/internal/service/event_mapping.go:65-68`：初始 occurrence 改为构造上述对象（封装为辅助函数 `buildOccurrence(ly map[string]any) map[string]any`）。`first_time`/`last_time`/`occurrence_time` 仍存时间字符串不变。
- `traffic/internal/service/services.go:127-142`（`mergeOccurrence`）：追加同样的对象；`first_time`/`last_time` 比较仍用时间字符串。保留 `maxOccurrences=200` 截断。
- 辅助函数 `buildOccurrence` 放在 service 包内供两处复用（DRY）。

### 3.3 投影暴露
- `traffic/event_service.go` 的 `lyCompatibleEvent`：新增输出键 `"occurrences": ctx["occurrences"]`（原样透传对象列表）。其余字段不变。

### 3.4 向后兼容
- 旧库 occurrences 元素是字符串：后端原样透传（不强制转换）。**前端**负责把字符串元素视为 `{time: <string>}`、字节/包数显示 "-"。

## 4. 前端改动

### 4.1 数据贯通
- 事件行已经过 `store`/`utils` normalize。新增把投影里的 `occurrences` 透传到行对象（字段名 `occurrences`，对象数组）。若 normalize 层未保留未知字段，则显式带上。

### 4.2 命中频次列入口（方案 B）
- 在「命中频次」列 render 的 tag 组后追加一个 `NButton(text, size=small)` 文案「明细」，仅当 `row.occurrences?.length` 时显示；点击设置当前行 occurrences 并打开弹窗。

### 4.3 弹窗
- `NModal`（preset card，标题「命中明细」）内置 `NDataTable`，列：
  - 序号（index+1）
  - 命中时间（格式化展示；字符串/对象 `time` 字段都支持）
  - 数据包大小（`wire_bytes` 经 `formatBytes` → `B/KB/MB`；缺失显示 "-"）
  - 包数（`packets`；缺失显示 "-"）
- 行数据由 `occurrences` 映射；元素为字符串时按 `{time}` 处理。
- `formatBytes(n)`：小工具，1024 进制，保留 1 位小数（如 `1.4 KB`）。

## 5. 测试

- 后端单测（`traffic/internal/service` 或 `traffic` 包）：
  - `buildOccurrence`：含 `wire_bytes`/`packets` 时构造对应键；缺失时省略。
  - `mergeOccurrence`：多次合并后 occurrences 为对象列表、按次累加、超过 200 截断。
  - `lyCompatibleEvent`：输出含 `occurrences` 键且为列表。
- 前端：手工验证——点击「明细」弹窗、字节格式化、旧字符串数据显示 "-"、occurrences 为空时不显示入口。

## 6. 不做的事（YAGNI）

- 不新增后端查询接口（复用列表已加载数据）。
- 不展示 `bytes`（载荷字节）、方向、协议等额外列（仅 时间/大小/包数）。
- 不回填历史事件的字节数（旧数据该列 "-"）。
- 不改 lyserver DB（`t_event_data`）路径；本功能作用于内存/DeepSOC 投影 `lyCompatibleEvent`。
