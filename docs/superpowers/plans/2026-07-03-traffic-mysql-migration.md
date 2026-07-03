# 流量分析存储整体迁移 MySQL 8.0 + 完全自动初始化 Implementation Plan

> **实施状态（2026-07-03）**：Task 1–5 代码全部完成并通过本机可行的全部验证（`go build/vet/test ./traffic/internal/...` 全绿、gofmt 干净、postgres 方言残留扫描零命中）。
> 本机限制：traffic 根包与 `di/` 因私有模块 `code.yt-security.com` TLS 不可达无法编译，需在正常构建环境补跑 `go build ./...` 与 `go mod tidy`。
> **修复（2026-07-03）**：t_agent 补回原始 dump 的 `UNIQUE KEY (ip)`（pg 移植期丢失）；节点保存 INSERT 改 upsert（同 IP 刷新既有记录，`LAST_INSERT_ID(id)` 保 id 稳定）；`ensureLySchemaUpgrades` 对旧 DDL 建的存量表幂等补键（存量重复 ip 仅告警放行）；UPDATE 撞键返回 400「IP 已被其他节点占用」。真库测试 `TestInitMySQLBackfillsTAgentUniqueKey` 覆盖补键与重复放行两条路径。
> **真库验证（2026-07-03）**：本地 mysql:8.0.46 容器（端口 33061）实测——`TestInitMySQLEndToEnd` + 5 个 `TestMySQL*` CRUD 集成测试全部 PASS（外键级联、唯一约束、upsert 幂等、UTC 回环均真库覆盖）；Task 6 平台级冒烟（/health、/ly 页面）仍需可编译环境。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将流量分析（traffic）模块的持久化存储从 PostgreSQL 整体迁移到 MySQL 8.0（复用平台现有 MySQL 实例），并实现**完全自动初始化**：数据库（database）不存在自动建库、37 张表不存在自动建表、种子数据自动写入，全程幂等；容器编排下 MySQL 未就绪时启动重试等待，杜绝静默回退内存。

**Architecture:** 三处独立 `sql.Open("postgres")`（store / lyserver / autopilot）收敛为**一个共享 `*sql.DB` 连接池**，由新增的 `internal/store/dbinit.go` 统一完成：建库 → 等待就绪 → 建表（store 15 张 + LY 兼容 22 张 + app_states）→ 种子。`store.Store` 接口不变，`postgres.go` 重写为 `mysql.go`；`memory` 后端保留；`postgres` 后端整体移除（git 历史可回退）。

**Tech Stack:** Go `database/sql` + `github.com/go-sql-driver/mysql`（已在依赖树，转 direct）；MySQL 8.0（utf8mb4）。移除 `github.com/lib/pq`。

## Global Constraints

- **仅修改** `vulnscan-backend/traffic/**`、`vulnscan-backend/dev.config.toml`、`vulnscan-backend/go.mod`。不碰平台 `model/`、`boot/`、`di/`（装配签名不变）。
- 分支：`trafficanalysis`。
- 目标 MySQL：**8.0**（已确认）。同实例（10.20.30.144:3306）新建独立库 `traffic`，**不得**复用平台 `vulnerability` 库（users/tasks/events 等表名冲突）。
- DSN 必须携带 `parseTime=true&charset=utf8mb4&loc=UTC`（缺 `parseTime` 则所有 `time.Time` 扫描失败）。
- 运行时连接池**不开** `multiStatements`（防注入放大）；仅 dbinit 的专用初始化连接临时开启，用完即关。
- 时间统一 UTC：列类型 `DATETIME(6)`，Go 侧沿用现有 `time.Now().UTC()`。
- JSON 列一律 **不设 DDL 默认值**（规避 8.0.13 之前不支持 JSON DEFAULT 的版本敏感），应用层保证写入 `'{}'`/`'[]'`。
- TEXT 列去掉 DEFAULT（MySQL 不支持），改 `TEXT NOT NULL` + 应用层空串（现有代码全部显式传值，无行为变化）。
- 所有 DDL `CREATE DATABASE/TABLE IF NOT EXISTS`、种子 `INSERT IGNORE` / `ON DUPLICATE KEY UPDATE`，**幂等可重复执行**。
- Go 工具链 workaround：`GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto`。

## SQL 方言转换对照（全库通用）

| PostgreSQL 现状 | MySQL 8.0 写法 | 出现位置（约数） |
|---|---|---|
| `$1,$2,...` 占位符 | `?` | 全部 ~93 处 |
| `INSERT ... RETURNING 整行` | `Exec` + `LastInsertId()` 回填 `ID`，其余字段应用侧已知 | store 14 处、lyserver 5 处 |
| `UPDATE ... RETURNING 整行` | `UPDATE` 后按业务键（user_id/event_id…）`SELECT` 回读 | 同上 |
| `ON CONFLICT (k) DO UPDATE SET x=EXCLUDED.x` | `ON DUPLICATE KEY UPDATE x=VALUES(x)`（8.0.20+ 仅弃用告警，可用） | ~24 处；冲突键均已有 UNIQUE 约束，逐表核对 |
| `ON CONFLICT DO NOTHING` | `INSERT IGNORE` | 种子/会话若干 |
| `$n::jsonb` 强转 | 去掉强转，直接传 JSON 字符串（JSON 列自校验） | ~15 处 |
| `meta->>'key'` | `meta->>'$.key'` | lyserver ~14 处 |
| `meta \|\| $2::jsonb`（合并） | `JSON_MERGE_PATCH(meta, CAST(? AS JSON))` | lyserver 4 处 |
| `now()` / `now()+interval '12 hours'` | `NOW(6)` / `NOW(6) + INTERVAL 12 HOUR` | 全部 |
| `BIGSERIAL PRIMARY KEY` | `BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY` | 37 张表 |
| `TIMESTAMPTZ` | `DATETIME(6)`（UTC 语义靠 DSN `loc=UTC` + 应用层） | 全部时间列 |
| `JSONB` | `JSON`（无 DEFAULT） | ~10 列 |
| `BOOLEAN` / `true/false` 字面量 | `TINYINT(1)`，driver 原生映射 | users.is_active、t_user.enabled 等 |
| information_schema `udt_name`、`column_default` | `COLUMNS` 表的 `DATA_TYPE`/`COLUMN_TYPE`/`COLUMN_DEFAULT` | autopilot 内省 1 处 |
| `pqQuoteIdent`（双引号转义） | 反引号 `` `ident` `` 转义 | autopilot |

---

### Task 1: MySQL Schema（store 15 张表）

**Files:**
- Modify: `vulnscan-backend/traffic/internal/store/schema.go`（`PostgresSchema` → `MySQLSchema`，DDL 整体转方言）

**表清单：** users, events, messages, tasks, actions, commands, executions, summaries, event_maps, sync_cursors, pushed_events, traffic_assets, audit_logs, prompts, settings

**Steps:**
- [x] 按方言对照表转换全部 DDL；每表补 `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
- [x] 核对每个原 `ON CONFLICT` 目标列在 MySQL 版本中有对应 `UNIQUE KEY`（user_id/username/event_id/message_id/task_id/action_id/command_id/execution_id/idempotency_key/address/fp/name/key）
- [x] 原 pg 部分索引/表达式索引（如有）降级为普通二级索引
- [x] 验证：`go vet ./traffic/internal/store/`

### Task 2: store 层 MySQL 实现

**Files:**
- Add: `vulnscan-backend/traffic/internal/store/mysql.go`（以 `postgres.go` 为蓝本逐方法移植，~800 行）
- Delete: `vulnscan-backend/traffic/internal/store/postgres.go`
- Modify: `vulnscan-backend/traffic/internal/store/store.go`（接口不变，仅注释）

**Interfaces:**
- Produces: `NewMySQLStore(db *sql.DB) *MySQLStore` —— **接收共享连接池**，不再自己 `sql.Open`/`Migrate`（初始化职责移交 Task 4 的 dbinit）
- `MySQLStore` 实现 `store.Store` 全部 45 个方法，语义与 memory/postgres 版完全一致（含 `CreateAsset` 重复地址报错、`UpdateXxx` patch 语义）

**Steps:**
- [x] 移植全部方法：占位符、RETURNING→LastInsertId/回读、upsert 改写、JSON 直传
- [x] `go test ./traffic/internal/store/`（现有 memory 用例回归）
- [x] 新增 `mysql_integration_test.go`：读 `TRAFFIC_TEST_MYSQL_DSN` 环境变量，未设置则 `t.Skip`；覆盖 事件 CRUD+upsert、资产唯一约束、JSON 字段写读回环、时间字段 UTC 回环

### Task 3: LY 兼容层 + autopilot 转方言

**Files:**
- Modify: `vulnscan-backend/traffic/internal/lyserver/handlers.go`（22 占位、5 RETURNING、5 upsert、`->>'$.key'`、`JSON_MERGE_PATCH`、`interval` 语法）
- Modify: `vulnscan-backend/traffic/internal/lyserver/query_handlers.go`（11 占位、JSON 取值）
- Modify: `vulnscan-backend/traffic/internal/lyserver/rules.go`（如含 SQL 同步处理）
- Modify: `vulnscan-backend/traffic/internal/autopilot/autopilot.go`（app_states DDL 转 MySQL、upsert 改写、information_schema 内省改 MySQL 列、`pqQuoteIdent`→反引号、动态 INSERT 拼接适配）

**Interfaces:**
- Changed: `lyserver.New(db *sql.DB) *Service`（原 `New(databaseURL string)`）——共享连接池注入；`db==nil` 时保持现有"未启用"降级语义
- Changed: autopilot 各函数 `(ctx, databaseURL string)` → `(ctx, db *sql.DB)`，去掉每次调用 open/close 的开销；调用方 `traffic/internal/httpapi/driving_mode_hooks.go`、`traffic/handler.go` 同步改签名

**Steps:**
- [x] lyserver 两文件全量转方言（重点自测 `JSON_MERGE_PATCH` 与 `->>'$.x'` 空值行为：pg `->>` 缺键返回 NULL，MySQL 同为 NULL，`COALESCE` 包裹保持不变）
- [x] autopilot 转写 + 调用方签名联动
- [x] `go build ./traffic/...`

### Task 4: dbinit —— 完全自动初始化（核心新增）

**Files:**
- Add: `vulnscan-backend/traffic/internal/store/dbinit.go`
- Modify: `vulnscan-backend/traffic/internal/bootstrap/lyserver_postgres.go` → Rename `lyserver_mysql.go`（`LyServerMySQLSchema` 22 张 t_* 表 + 参考数据种子；供 dbinit 引用）
- Modify: `vulnscan-backend/traffic/internal/bootstrap/bootstrap.go`（独立 `-init` 流程改 MySQL：`sql.Open("mysql")`、校验 `STORE_BACKEND=mysql`、种子 SQL 转方言，复用 dbinit）

**Interfaces:**
- Produces: `InitMySQL(ctx, dsn string, autoMigrate bool, waitSeconds int) (*sql.DB, error)`，流程：
  1. **建库**：`mysql.ParseDSN(dsn)` 取出 `DBName`（为空则报错）；克隆 cfg 置 `DBName=""` 建临时连接，执行 ``CREATE DATABASE IF NOT EXISTS `<db>` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci``；**权限不足（Error 1044/1142）仅告警继续**（库可能已由 DBA 预建）
  2. **等待就绪**：对目标库 `PingContext` 重试（1s 起指数退避，上限 `waitSeconds`，默认 30）——解决 compose 下 MySQL 容器慢启动导致的静默回退
  3. **建表 + 种子**（`autoMigrate=true` 时）：专用 `multiStatements=true` 初始化连接依次执行 `MySQLSchema`（store 15 张）、`LyServerMySQLSchema`（t_* 22 张）、app_states DDL；随后用普通连接**逐条参数化**执行种子：store admin 用户、`DefaultPrompts`、LY 参考数据（原 `seedLyServerReferenceData` 的多语句 SQL **必须拆成逐条 Exec**——运行时池不开 multiStatements）
  4. 返回配置好连接池参数（MaxOpen 20 / MaxIdle 5 / Lifetime 30m）的共享 `*sql.DB`
- 全流程幂等；每步失败返回带上下文的 error，由调用方决定回退

**Steps:**
- [x] 实现 dbinit + 单测（ParseDSN 剥库名、退避计时用注入 clock）
- [x] `bootstrap.go` / `lyserver_mysql.go` 转方言并接入 dbinit（消除第 4、5 处独立 `sql.Open`）
- [x] 验证：对本地/开发 MySQL 8.0 跑两遍 `InitMySQL` 确认幂等（第二遍零 DDL 报错、种子不重复）——`TestInitMySQLEndToEnd` 对 mysql:8.0.46 容器实测通过（自动建库→38 表→种子→二次幂等→既有数据存活→UTC 回环）

### Task 5: 装配与配置收口

**Files:**
- Modify: `vulnscan-backend/traffic/traffic.go`（`loadStore` → `loadDB`+`loadStore`：先 `InitMySQL` 得共享池；成功→`NewMySQLStore(db)` 并把同一 `db` 注入 `lyserver.New(db)`、autopilot；失败→打 ERROR 日志回退 `NewMemoryStore()` 且 lyserver 传 nil 保持降级）
- Modify: `vulnscan-backend/traffic/internal/config/config.go`（`STORE_BACKEND` 默认 `"memory"`→`"mysql"`；新增 `DBWaitSeconds`，env `DB_WAIT_SECONDS` 默认 30）
- Modify: `vulnscan-backend/traffic/internal/httpapi/server.go`（standalone 路径同步接共享池）
- Modify: `vulnscan-backend/dev.config.toml`（`store_backend = "mysql"`；`database_url` 示例改 `db:****@tcp(10.20.30.144:3306)/traffic?parseTime=true&charset=utf8mb4&loc=UTC`；注释同步；新增 `db_wait_seconds = 30`）
- Modify: `vulnscan-backend/traffic/traffic.go` `Config` 结构体（`DBWaitSeconds int` + toml tag；`toInternal` 透传）
- Modify: `vulnscan-backend/go.mod`（`go-sql-driver/mysql` indirect→direct；移除 `lib/pq`；`go mod tidy`）

**Steps:**
- [x] 上述改动 + `store_backend` 取值收敛为 `mysql | memory`（出现 `postgres` 时打告警按 mysql 处理，平滑旧配置）
- [ ] `go build ./traffic/... ./di/...`、`go vet ./traffic/...`
- [ ] 确认 `/api/traffic/health`、`system_service.go` 返回的 `store_backend` 字段值正确

### Task 6: 冒烟验收（部署视角）

**Steps:**
- [ ] 全新 MySQL 8.0（无 `traffic` 库）+ 配置 DSN → 启动平台：日志依次出现 建库/等待就绪/建表/种子；`SHOW TABLES` = 37 张 + app_states
- [ ] 重启进程：零 DDL 报错（幂等）；事件/资产数据仍在（持久化生效）
- [ ] 功能链路：建事件→发消息→审核→`/ly` 节点配置页读写（考验 JSON 函数）→ driving-mode 开关（app_states）
- [ ] MySQL 后启动场景：先启平台后启 MySQL（30s 内），确认等待重试成功不回退内存
- [ ] `database_url` 留空场景：明确 ERROR 日志 + 回退 memory，`/health` 显示 `store_backend` 实际值
- [ ] 镜像验证：`MODE=dev` 构建，容器内 `/app/config.toml` 为新配置

---

## 部署前提与运维备注

- MySQL 账号需要 ``GRANT CREATE ON `traffic`.* ``（自动建库用）+ ``GRANT ALL ON `traffic`.* ``；若 DBA 预建库则只需后者。
- compose 建议仍给 MySQL 配 healthcheck + `depends_on: condition: service_healthy`，`db_wait_seconds` 是兜底不是替代。
- 无存量数据迁移：postgres 路径从未在部署环境启用（此前默认 memory，database_url 一直为空）。
- 回退方案：`git revert` 本计划提交串即恢复 postgres 版本（接口未变，回退无残留）。
- 后续如需保留双方言，以 `store.Store` 接口 + dbinit 抽象为基础另立计划，本次不做。

## 工作量估算

| Task | 内容 | 估时 |
|---|---|---|
| 1+2 | store schema + mysql.go 移植 + 集成测试 | ~1.5 人日 |
| 3 | lyserver + autopilot 转方言 | ~1 人日 |
| 4 | dbinit 自动初始化 + bootstrap 对齐 | ~0.5 人日 |
| 5+6 | 装配/配置/tidy + 冒烟 | ~0.5 人日 |
| **合计** | | **~3.5 人日** |
