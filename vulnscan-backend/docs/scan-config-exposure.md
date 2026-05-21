# 扫描配置暴露与规则来源

## 应在 UI 暴露什么？

### 创建任务 · 模块参数微调（按模板主模块）

| 主模块 | 暴露项 | 配置键 (module_configs) |
|--------|--------|-------------------------|
| `host_discover` | 端口范围 | `ports`: top100 / top1000 / full |
| `web_vuln_scan` | 验证级别 | `verification_level`: both / principle / exploit |
| `nuclei-poc` | 见任务级 parameters | `rate_limit`, `nuclei_template_dir`, `nuclei_interactsh_disable` |
| 其他主模块 | 一般无需逐项暴露 | 细调使用 `?legacy=1` 的模块配置 API |

### 创建任务 · 高级选项（任务级 parameters）

| 项 | 键 | 来源 |
|----|-----|------|
| 引擎预设 | `engine_preset` | `scanrunner/presets.go` |
| 自动推导性能 | `auto` 时由 `scanrunner/derive.go` 写入 | 可用 `rate_limit` 等覆盖 |
| 验证级别（默认） | `verification_level` | 可被 `web_vuln_scan` 覆盖 |
| 无 HTTP 跳过 Web 漏洞 | `engine.auto_skip_web_vulns_without_http` | `scanrunner/engine_gating.go`，默认关闭 |

### 系统级（非单次任务弹窗）

- **全局扫描配置**：`scan/scanconfig` + 表 `vs_scan_config`
- **扫描排除规则**：排除规则 API / `scanrunner/filter.go`
- **误报规则**：误报规则管理
- **PoC / 字典**：知识库与系统字典

## 知识库接入（已实现）

- `ModuleFactory`：`rulestore.New(db)`、`dict.NewStore(db)`、`payload.LoadAll()`
- 启动日志：`[Knowledge]` 标明文库 payload 缺失、字典是否仅用内嵌、规则加载数量
- `weak_pass` / `dir_scan` / `brute_force` / `subdomain` 使用同一 `dict.Store`
- 文库为空时漏洞模块仍用代码内嵌兜底，并打 **Warn** 日志
- **热重载**：`KnowledgeRegistry` 单例；数据文库增删改 / PoC CRUD / `POST /api/scan/knowledge/reload` / 数据文库「重载缓存」会刷新 payload、ScanRule、PoC 缓存；**进行中的扫描任务**仍用启动时模块实例，**新任务**使用新数据

## 不应在 UI 重复暴露的

- 每个子模块的 `concurrency` / `timeout` / `enabled`（已合并进主模块；legacy 模式仍可查）
- `engine_gating.go` 中的 Web 端口白名单（80/443/8080…）—— 整体用门控开关代替逐项配置
- `derive.go` 的分档阈值 —— 用 `engine_preset=auto` + 覆盖单键即可

## 规则来源 API

- `GET /api/scan/engine-rules` — 规则清单与 `source` 文件路径
- `GET /api/scan/task-parameter-schema` — 建议的任务级参数字段
- `GET /api/pipeline/modules/config?legacy=1` — 含通用三参数的旧版完整列表
