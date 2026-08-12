# 流量分析上线前检查清单（含决策记录）

- 日期: 2026-08-05
- 状态: 执行中

## 1. 决策记录

| 序号 | 检查项 | 决策 | 状态 |
| --- | --- | --- | --- |
| 阻断-1 | traffic 模块接口无 IAM 鉴权 | **忽略**（沿用模块自身兼容鉴权语义，网关层另行治理） | 已决策 |
| 阻断-2 | internal_api_key 默认值/前端硬编码 | **忽略**（生产环境通过配置覆盖） | 已决策 |
| 阻断-3 | 配置仓库明文密钥 | **忽略**（沿用现状，密钥轮换另行排期） | 已决策 |
| 阻断-4 | 构建产物未入库 | **添加 .gitignore**（server-arm64 / *.tar / mock/） | 已完成 |
| 高危-1 | 收敛终报失败重试 | **不做失败重试**（依赖手动刷新兜底，运维监控 version<2） | 已决策 |
| 高危-2 | 全表扫描 | **改为 MySQL 条件查询**（新增 last_seen_at 列 + ListEventsConvergedDue / ListEventsByTargetIP） | 已完成 |
| 高危-3 | 月度总结同步 LLM | **改为异步任务 + 进度查询**（asset_report_jobs 表 + 任务接口） | 已完成 |
| 高危-4 | 前端入口缺失 | **补齐**（手动刷新按钮 + 月度总结页面入口，UI 风格保持一致） | 已完成 |
| 高危-5 | 新报告字段未渲染 | **补齐 PDF/DOCX 渲染** | 已完成 |
| 高危-6 | Go 工具链不一致 | **对齐 1.26.3**（go.mod toolchain 指令 + .go-version） | 已完成 |
| 中低-1 | 工作区既有改动 | **review 后保留**（用户既有改动，逐项确认） | 已完成 |
| 中低-2 | 突发窗口含义 | **保留现状并文档化**：基于最近 maxOccurrences=200 次命中做 5 分钟滑动窗口峰值，超高频长周期事件可能低估 | 已决策 |
| 中低-3 | TestStoreSettings 信息泄露 | **忽略**（随接口鉴权一并治理） | 已决策 |

## 2. 执行明细

### 2.1 .gitignore（阻断-4）

根 `.gitignore` 追加：

```gitignore
# 构建产物
vulnscan-backend/server-arm64
*.tar
vulnscan-frontend/apps/web/mock/
```

### 2.2 MySQL 条件查询（高危-2）

- events 表新增 `last_seen_at DATETIME(6) NULL` 列（含存量库幂等 ALTER）；
- `mergeOccurrence` / 事件创建时同步维护该列；
- Store 新增：
  - `ListEventsConvergedDue(threshold time.Time)`：`aggregation_closed=0 AND last_seen_at < threshold`；
  - `ListEventsByTargetIP(ip string, from, to time.Time)`：按 context 内 dst_ip/victim_target + last_seen_at 窗口查询；
- `ScanConverged` 与月度总结改用上述查询，不再全表 `ListEvents`。

### 2.3 月度总结异步化（高危-3）

- 新表 `asset_report_jobs`（job_id/period/status/total/completed/error/时间戳）；
- `POST /assets/monthly-summary/run` 改为创建任务立即返回 job_id；
- `GET /assets/monthly-summary/jobs/:jobID` 返回进度与结果；
- 后端 goroutine 逐资产执行，进度回调更新 job。

### 2.4 前端入口（高危-4）

- 事件报告详情页：新增「手动刷新分析」按钮（60 秒冷却提示）；
- 资产页面：新增「生成月度总结」与进度/结果展示，风格沿用 NCard/NButton。

### 2.5 新报告字段渲染（高危-5）

- incident 报告 PDF/DOCX 增加：事件概述（核心结论）、流量证据与IOC明细、影响评估、处置建议、附件清单；
- 无数据章节自动隐藏。

### 2.6 Go 工具链（高危-6）

- go.mod 增加 `toolchain go1.26.3`；
- 新增 `.go-version`（内容 `1.26.3`）；
- CI/部署镜像固定 Go 1.26.3。

### 2.7 工作区改动 review（中低-1）

逐项核对未提交改动，确认无调试残留/敏感信息后保留；构建产物清理见 2.1。

### 2.8 突发窗口（中低-2）

语义：对 occurrences 时间序列（最多最近 200 条）排序后做 5 分钟滑动窗口，取命中数最多的窗口。决策：保留；文档注明高频长周期事件的统计上限。

## 3. 执行记录（2026-08-05）

- 阻断-4：`.gitignore` 已追加 `vulnscan-backend/server-arm64`、`*.tar`、`vulnscan-frontend/apps/web/mock/`。
- 高危-2：events 新增 `last_seen_at` 列（含存量库 ALTER 与 context 回填）；`ScanConverged` 改用 `ListEventsConvergedDue`（`aggregation_closed=0 AND last_seen_at < ?`，LIMIT 500）；月度总结改用 `ListEventsByTargetIP`（JSON_EXTRACT dst_ip/victim_target + last_seen_at 窗口）。
- 高危-3：新增 `asset_report_jobs` 表与 `AssetReportJob` 领域模型；`POST /assets/monthly-summary/run` 返回 job_id，后台 goroutine 逐资产执行并更新进度；`GET /assets/monthly-summary/jobs/:jobID` 查询进度。
- 高危-4：事件报告弹窗新增「手动刷新分析」按钮（调用 `/report/refresh` 并提示新版本号）；资产页新增「生成月度总结」（异步 + 2s 轮询进度）与「月度总结」查看弹窗，样式沿用 NCard/NButton/NModal。
- 高危-5：incident 报告 PDF/DOCX 新增渲染「事件概述 / 流量证据与IOC明细 / 影响评估 / 处置建议 / 附件清单」，空章节自动隐藏。
- 高危-6：go.mod 增加 `toolchain go1.26.3`，新增 `.go-version`，`go mod tidy` 通过。
- 中低-1 review 结论：
  - `.env.development`：`VITE_SKIP_AUTH=true` 仅限本地调试，保留；
  - `incident-overview-stats.ts` / `incident/list/index.vue`：发现/上报时间拆分、删除改 NPopconfirm，合理保留；
  - `LyEventTable.vue`：情报卡片重构与样式升级，保留；顺手清理未使用的 `formatVolumeRole` 导入（消除 typecheck 错误）；
  - `vite.config.mts` + `mock/`：mock 插件改为按 `mock/event-mock.ts` 是否存在动态加载，避免克隆/CI 构建因 mock 目录被 gitignore 而失败；
  - `vsh.mjs`：仅权限位变更（644→755），保留；
  - `README.md`：未提交文档，入库前需确认内容。
- 中低-2：突发窗口决策已记录（保留现状）。
- 中低-3：TestStoreSettings 信息泄露项忽略。

## 4. 验证状态

- `go build ./...` 通过；traffic config/service/store 单测通过；
- `go vet ./traffic/...` 通过（在最终收尾时复跑）；
- 前端 typecheck：本次改动的 `views/ly/*`、`api/ly/*`、`vite.config.mts` 无类型错误（存量其它页面错误与本次无关）。
