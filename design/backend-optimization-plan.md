# 后端优化与合并计划

## 一、现状概览

| 指标 | 数值 |
|------|------|
| 顶层业务包 | ~30 个 |
| Handler 文件 | 44 个 |
| Service 文件 | 38 个 |
| Contract 接口 | 25 个 |
| Wire 注入模块 | 10 个 |
| 手动初始化模块 | ~15 个 |
| Model 文件 | 27 个 |
| DB 表 | ~90 张 |
| 入口二进制 | 3 个 (server / worker / monitor-agent) |
| 扫描模块 | 30+ 个 |
| scan/core 文件 | 62 个 (~280KB) |

---

## 二、核心问题

### 2.1 死代码 — 未使用的复杂抽象

| 文件/模块 | 问题 | 影响 |
|-----------|------|------|
| `scan/core/pipeline.go` | `NewPipeline()` 从未被外部调用 | 整个复杂编排逻辑无用 |
| `scan/pipeline/pipeline.go` | 未被 scheduler 或任何生产路径导入 | 死代码 |
| `scan/core/dedup_multilayer.go` | 仅被未使用的 Pipeline 引用 | 死代码 |
| `scan/core/limiter.go` (RateLimiter) | 仅被未使用的 Pipeline 引用 | 死代码 |
| `scan/core/adaptive_resource.go` | 仅在未使用的 Pipeline 中实例化 | 死代码 |
| `nuclei/executor.go` | 空文件，仅有 package 声明 | 无用文件 |
| `scheduler/runner.go:appendUniqueTargets()` | 已被 `enricher.EnrichTargets` 替代 | 死函数 |

### 2.2 重复实现

| 功能 | 实现 A | 实现 B | 建议 |
|------|--------|--------|------|
| 去重 | `core/dedup.go` (生产使用) | `core/dedup_multilayer.go` (未使用) | 删除 B |
| 限流 | `core/ratelimiter.go` TokenBucket (生产使用) | `core/limiter.go` 双层限流 (未使用) | 删除 B |
| Pipeline 编排 | `scheduler/stage_executor.go` (生产使用) | `core/pipeline.go` + `scan/pipeline/` (未使用) | 删除后两者 |
| 断路器 | `core/retry.go` CircuitBreaker | `core/adaptive.go` 内嵌断路器状态 | 统一为一个 |
| 网络空间搜索 | `scan/module/cyberspace/` (扫描用) | `cyberquery/` (API 查询用) | 提取共享 provider |

### 2.3 架构不一致

| 问题 | 涉及模块 | 影响 |
|------|----------|------|
| 响应 API 混用 | 28 个文件用 legacy `web.Resp()`，40 个文件用 chainable `web.OK()` | 维护成本高 |
| 参数绑定混用 | 14 个文件仍用 `c.ShouldBind*`（违反 CLAUDE.md 规范） | 不一致 |
| Handler 直接访问 DB | 14 个 handler 绕过 service 层 | 分层被破坏 |
| DI 方式不统一 | 10 个模块用 Wire，15 个手动初始化 | `handlers.go` 成为变更热点 |
| `scan/core/` 职责过重 | 62 个文件混合了框架、漏洞检测、策略引擎 | 包过大难以维护 |

### 2.4 超大文件（需拆分）

| 文件 | 大小 | 问题 |
|------|------|------|
| `engine/service.go` | 50KB | 混合了词库/文件库/任务/执行/Agent/告警/导入/规则 |
| `engine/handler.go` | 33KB | 端点过多 |
| `asset/asset-handler-enrich.go` | 33KB | 富化逻辑过于集中 |
| `asset/asset-handler-import.go` | 28KB | 导入逻辑过于集中 |
| `assetmgr/handler.go` | "上帝 Handler" | 11 个 service 依赖，40+ 端点方法 |
| `di/handlers.go` | 656 行 | 混合路由注册/迁移/种子/调度/联邦/WebSocket |

---

## 三、优化计划

### Phase 1: 清理死代码（低风险，立即可做）

**预计工作量：1-2 天**

1. 删除 `scan/core/pipeline.go` — 未使用的复杂 Pipeline 编排
2. 删除 `scan/pipeline/` 整个目录 — 未使用的简化 Pipeline
3. 删除 `scan/core/dedup_multilayer.go` + 对应测试 — 仅被死代码引用
4. 删除 `scan/core/limiter.go` — 仅被死代码引用的双层限流器
5. 删除 `scan/core/adaptive_resource.go` + 对应测试 — 仅被死代码引用的资源监控
6. 删除 `nuclei/executor.go` — 空文件
7. 删除 `scheduler/runner.go` 中的 `appendUniqueTargets()` 函数
8. 删除 `scan/engine/` 目录下所有已标记删除的文件（git status 显示大量 D 状态文件）
9. 删除 `cmd/master/main.go`（已标记删除）
10. 删除 `monitoragent/` 中已标记删除的引擎文件（anomaly_detector, engine_* 系列）

**验证方式：** `go build ./...` 编译通过 + 单元测试通过

---

### Phase 2: 统一编码规范（中风险，逐模块推进）

**预计工作量：3-5 天**

#### 2.1 统一响应 API → chainable 风格

将 28 个文件中的 legacy 调用迁移为 chainable API：

```go
// Before (legacy)
web.Resp(c, web.Success)
web.RespContent(c, web.Success, data)
web.RespContentWithNum(c, web.Success, count, items)

// After (chainable)
web.OK(c).Send()
web.OK(c).Data(data).Send()
web.OK(c).List(items, count).Send()
```

涉及模块：`asset`, `task`, `assetmgr`, `engine`, `dashboard`, `asm`, `tagging`, `organize`, `schedule`, `cluster`

#### 2.2 统一参数绑定 → 泛型绑定函数

将 14 个文件中的 `c.ShouldBind*` 迁移为 `web.BindJSON[T]` / `web.BindQuery[T]` / `web.BindUri[T]`：

涉及模块：`asset`, `task`, `engine`, `assetmgr`, `dashboard`, `asm`, `schedule`, `cluster`

#### 2.3 消除 Handler 直接 DB 访问

为以下模块补充 Service 层：

| 模块 | 当前状态 | 目标 |
|------|----------|------|
| `dashboard/` | Handler 直接查 DB | 提取 DashboardService |
| `notify/` | Handler + Sender 直接用 DB | 提取 NotifyService |
| `setting/` | Handler 直接用 DB + sync.Map | 提取 SettingService |
| `systemdict/` | Handler 直接用 DB | 提取 SystemDictService |
| `formdesign/` | Handler 直接用 DB | 提取 FormDesignService |
| `asm/` | Handler 直接用 DB | 提取 ASMService |
| `report/` | Handler 直接用 DB | 提取 ReportService |
| `schedule/` | Handler 直接用 DB | 提取 ScheduleService |
| `intel/` | Handler 混合 DB + CVE 同步 | 拆分 IntelService + CVESyncService |

---

### Phase 3: 拆分超大文件（中风险）

**预计工作量：3-4 天**

#### 3.1 拆分 `engine/service.go` (50KB)

拆分为：
- `engine/service_task.go` — 任务 CRUD
- `engine/service_execution.go` — 执行管理
- `engine/service_agent.go` — Agent 管理
- `engine/service_alert.go` — 告警管理
- `engine/service_library.go` — 词库/文件库
- `engine/service_rule.go` — 规则数据
- `engine/service_import.go` — 导入逻辑

#### 3.2 拆分 `engine/handler.go` (33KB)

按功能拆分为对应的 handler 文件，与 service 拆分对齐。

#### 3.3 拆分 `assetmgr/handler.go`（上帝 Handler）

参照 `circular/` 和 `incident/` 的子模块模式，将 11 个 service 依赖拆分为独立子模块：
- `assetmgr/lifecycle/`
- `assetmgr/risk/`
- `assetmgr/alert/`
- `assetmgr/verify/`
- `assetmgr/compliance/`
- `assetmgr/workflow/`
- `assetmgr/integration/`
- `assetmgr/responsible/`

#### 3.4 拆分 `di/handlers.go` (656 行)

拆分为：
- `di/handlers.go` — 核心结构体 + RouteLoad 入口
- `di/migrate.go` — DB 迁移 + 种子数据
- `di/init_modules.go` — 手动初始化的模块注册

---

### Phase 4: 统一 DI 模式（中高风险）

**预计工作量：2-3 天**

将 15 个手动初始化模块迁移到 Wire：

**优先级 A（有明确 Service 层的）：**
- `knowledge/dict/`
- `knowledge/fingerprint/`
- `poc/`
- `payloadmgr/`

**优先级 B（需先补 Service 层的，依赖 Phase 2.3）：**
- `dashboard/`
- `notify/`
- `setting/`
- `systemdict/`
- `formdesign/`
- `asm/`
- `report/`
- `schedule/`
- `intel/`

**优先级 C（特殊模块，评估后决定）：**
- `cyberquery/` — 无 DB，仅外部 API 配置
- `compliance/` — 占位模块

---

### Phase 5: scan/core 包重构（高风险，需充分测试）

**预计工作量：5-7 天**

#### 5.1 提取漏洞检测模块

将 `scan/core/vuln_*.go`（16 个文件，~80KB）迁移到 `scan/module/` 下的独立子目录：

```
scan/core/vuln_xss.go       → scan/module/xss/xss.go (已存在，合并)
scan/core/vuln_sqli.go      → scan/module/sqli/sqli.go (已存在，合并)
scan/core/vuln_ssrf.go      → scan/module/ssrf/ (新建或合并)
scan/core/vuln_xxe.go       → scan/module/xxe/ (已存在，合并)
scan/core/vuln_csrf.go      → 合并到对应模块
scan/core/vuln_crlf.go      → 合并到对应模块
...
```

#### 5.2 拆分 scan/core 为子包

```
scan/core/          → 仅保留 types.go, pool.go, stream.go (核心接口)
scan/infra/http/    → httpclient.go, client_pool.go, object_pool.go
scan/infra/rate/    → ratelimiter.go (TokenBucket)
scan/infra/dedup/   → dedup.go (FindingDeduplicator)
scan/infra/retry/   → retry.go (CircuitBreaker + RunWithRetry)
scan/strategy/      → strategy.go, tech_detector.go, module_cutter.go, waf_detector.go
scan/enricher/      → target_enricher.go, target_propagator.go
scan/verify/        → verifier.go, cve_matcher.go
```

#### 5.3 统一断路器实现

合并 `core/retry.go` 的 `CircuitBreaker` 和 `core/adaptive.go` 内嵌的断路器状态为单一实现。

---

### Phase 6: 合并重复功能（中风险）

**预计工作量：2-3 天**

#### 6.1 网络空间搜索 Provider 提取

```
scan/module/cyberspace/providers/  — 共享 provider 实现 (FOFA, Shodan, ZoomEye, Censys)
cyberquery/                        — 仅保留 API handler，调用共享 provider
scan/module/cyberspace/            — 仅保留 ScanModule 适配器，调用共享 provider
```

#### 6.2 CronScheduler 重命名

- `scheduler/cron.go` → 类型重命名为 `ScanCronScheduler`
- `engine/cron_scheduler.go` → 类型重命名为 `MonitorCronScheduler`

避免包外引用时的命名混淆。

---

## 四、优先级与依赖关系

```
Phase 1 (清理死代码)
    ↓
Phase 2 (统一规范)  ←→  Phase 3 (拆分大文件)  [可并行]
    ↓
Phase 4 (统一 DI)  [依赖 Phase 2.3 的 Service 层补充]
    ↓
Phase 5 (scan/core 重构)  [独立，可与 Phase 4 并行]
    ↓
Phase 6 (合并重复)  [独立]
```

---

## 五、风险评估

| Phase | 风险等级 | 主要风险 | 缓解措施 |
|-------|----------|----------|----------|
| 1 | 低 | 误删仍在使用的代码 | `go build ./...` + grep 确认无引用 |
| 2 | 中 | 响应格式变化影响前端 | 逐模块迁移，前端联调验证 |
| 3 | 中 | 拆分后包引用关系变化 | 保持对外接口不变，仅内部重组 |
| 4 | 中高 | Wire 生成代码变化 | 逐模块迁移，每次 `wire ./di/` 验证 |
| 5 | 高 | 扫描引擎行为变化 | 充分的集成测试 + 对比扫描结果 |
| 6 | 中 | Provider 接口变化 | 先定义共享接口，再逐步迁移 |

---

## 六、预期收益

| 维度 | 改善 |
|------|------|
| 代码量 | 减少 ~15-20%（死代码清理 + 重复消除） |
| 编译速度 | scan/core 拆分后增量编译更快 |
| 可维护性 | 统一规范降低认知负担，新人上手更快 |
| 可测试性 | Service 层隔离后可独立单测 |
| 变更影响面 | `di/handlers.go` 不再是变更热点 |
| 架构清晰度 | 每个包职责单一，依赖方向明确 |

---

## 七、总工作量估算

| Phase | 工作量 | 累计 |
|-------|--------|------|
| Phase 1 | 1-2 天 | 1-2 天 |
| Phase 2 | 3-5 天 | 4-7 天 |
| Phase 3 | 3-4 天 | 7-11 天 |
| Phase 4 | 2-3 天 | 9-14 天 |
| Phase 5 | 5-7 天 | 14-21 天 |
| Phase 6 | 2-3 天 | 16-24 天 |

**总计：16-24 个工作日（约 3-5 周）**

建议按 Phase 顺序逐步推进，每个 Phase 完成后做一次全量编译 + 测试验证。
