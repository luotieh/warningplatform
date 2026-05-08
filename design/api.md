# 漏洞扫描系统 — API 接口设计

## 1. API 总览

| 模块 | 前缀 | 说明 |
|------|------|------|
| 认证 | `/api/v1/auth` | 登录/注销/Token |
| 资产 | `/api/v1/assets` | 资产 CRUD、指纹 |
| 域名 | `/api/v1/domains` | 子域名管理 |
| 任务 | `/api/v1/tasks` | 扫描任务管理 |
| 漏洞 | `/api/v1/vulns` | 漏洞查看/处置 |
| 报告 | `/api/v1/reports` | 报告生成/下载 |
| 插件 | `/api/v1/plugins` | PoC 管理 |
| 集群 | `/api/v1/cluster` | Worker 状态 |
| 统计 | `/api/v1/dashboard` | 仪表盘数据 |
| 通知 | `/api/v1/notifications` | 通知配置 |
| 系统 | `/api/v1/system` | 系统设置 |
| WebSocket | `/ws/v1` | 实时推送 |

**通用约定：**

```
认证: Authorization: Bearer <jwt_token>

分页: ?page=1&size=20
排序: ?sort=created_at&order=desc
搜索: ?keyword=xxx

成功响应:
{
  "code": 0,
  "msg": "success",
  "data": { ... }
}

列表响应:
{
  "code": 0,
  "msg": "success",
  "data": {
    "items": [...],
    "total": 100,
    "page": 1,
    "size": 20
  }
}

错误响应:
{
  "code": 40001,
  "msg": "参数错误: targets 不能为空"
}
```

---

## 2. 认证 API

```
POST   /api/v1/auth/login          登录
POST   /api/v1/auth/logout         注销
POST   /api/v1/auth/refresh        刷新 Token
GET    /api/v1/auth/me             获取当前用户信息
```

### POST /api/v1/auth/login

```json
// Request
{ "username": "admin", "password": "xxx" }

// Response
{
  "access_token": "eyJhbGci...",
  "refresh_token": "eyJhbGci...",
  "expires_in": 7200,
  "user": {
    "id": "01HX...",
    "username": "admin",
    "role": "admin",
    "avatar": ""
  }
}
```

---

## 3. 资产管理 API

```
GET    /api/v1/assets                     资产列表
POST   /api/v1/assets                     创建资产
GET    /api/v1/assets/:id                 资产详情
PUT    /api/v1/assets/:id                 更新资产
DELETE /api/v1/assets/:id                 删除资产
POST   /api/v1/assets/import              批量导入
GET    /api/v1/assets/:id/fingerprints    资产指纹
GET    /api/v1/assets/:id/vulns           资产关联漏洞
GET    /api/v1/assets/:id/history         扫描历史

GET    /api/v1/asset-groups               资产组列表
POST   /api/v1/asset-groups               创建资产组
PUT    /api/v1/asset-groups/:id           更新资产组
DELETE /api/v1/asset-groups/:id           删除资产组
```

### GET /api/v1/assets

查询参数:
| 参数 | 类型 | 说明 |
|------|------|------|
| page | int | 页码 |
| size | int | 每页数量 |
| type | string | 类型过滤: ip/domain/url/cidr |
| group_id | string | 资产组 |
| status | string | 状态: active/inactive |
| keyword | string | 搜索: IP/域名/标签 |
| sort | string | 排序字段 |
| has_vuln | bool | 是否有漏洞 |

### POST /api/v1/assets

```json
// 单个
{ "type": "ip", "value": "192.168.1.1", "group_id": "xxx", "tags": ["内网", "生产"] }

// 批量
{ "type": "cidr", "value": "192.168.1.0/24", "group_id": "xxx" }
```

### POST /api/v1/assets/import

```json
// 文件上传（CSV/TXT）
// Content-Type: multipart/form-data
// file: assets.csv
// group_id: xxx
```

---

## 4. 扫描任务 API

```
GET    /api/v1/tasks                      任务列表
POST   /api/v1/tasks                      创建任务
GET    /api/v1/tasks/:id                  任务详情
PUT    /api/v1/tasks/:id                  更新任务（仅 pending 状态）
DELETE /api/v1/tasks/:id                  删除任务
POST   /api/v1/tasks/:id/start           启动任务
POST   /api/v1/tasks/:id/pause           暂停任务
POST   /api/v1/tasks/:id/resume          恢复任务
POST   /api/v1/tasks/:id/cancel          取消任务
GET    /api/v1/tasks/:id/progress        实时进度
GET    /api/v1/tasks/:id/subtasks        子任务列表
GET    /api/v1/tasks/:id/vulns           任务发现的漏洞
GET    /api/v1/tasks/:id/logs            扫描日志

GET    /api/v1/scheduled-tasks            定时任务列表
POST   /api/v1/scheduled-tasks            创建定时任务
PUT    /api/v1/scheduled-tasks/:id        更新定时任务
DELETE /api/v1/scheduled-tasks/:id        删除定时任务
POST   /api/v1/scheduled-tasks/:id/toggle 启用/禁用
```

### POST /api/v1/tasks

```json
{
  "name": "内网全量扫描",
  "type": "full",
  "targets": ["192.168.1.0/24", "192.168.2.0/24"],
  "priority": 1,
  "group_id": "xxx",
  "config": {
    "ports": "top1000",
    "rate_limit": 500,
    "timeout_ms": 5000,
    "modules": ["portscan", "fingerprint", "vuln", "weakpass"],
    "poc_tags": ["rce", "sqli", "info_leak"],
    "exclude_ips": ["192.168.1.1"],
    "concurrent_per_host": 10
  }
}
```

### GET /api/v1/tasks/:id/progress

```json
{
  "status": "running",
  "started_at": "2026-04-30T10:00:00Z",
  "elapsed_seconds": 3600,
  "progress": {
    "total_targets": 512,
    "completed_targets": 256,
    "percent": 50.0,
    "current_stage": "vuln_check",
    "stages": {
      "resolve": { "total": 512, "done": 512, "status": "completed" },
      "portscan": { "total": 512, "done": 512, "open_ports": 1234, "status": "completed" },
      "fingerprint": { "total": 1234, "done": 800, "status": "running" },
      "vuln_check": { "total": 0, "done": 0, "status": "pending" }
    },
    "stats": {
      "hosts_alive": 312,
      "open_ports": 1234,
      "fingerprints": 456,
      "vulns_found": 23,
      "vulns_by_severity": { "critical": 2, "high": 8, "medium": 10, "low": 3 }
    }
  },
  "subtasks": {
    "total": 8,
    "completed": 4,
    "running": 3,
    "failed": 1
  }
}
```

---

## 5. 漏洞管理 API

```
GET    /api/v1/vulns                      漏洞列表
GET    /api/v1/vulns/:id                  漏洞详情
PUT    /api/v1/vulns/:id/status           更新漏洞状态（确认/修复/忽略/误报）
POST   /api/v1/vulns/:id/verify           重新验证漏洞
POST   /api/v1/vulns/batch-status         批量更新状态
GET    /api/v1/vulns/stats                漏洞统计
GET    /api/v1/vulns/trends               漏洞趋势（按天/周/月）
POST   /api/v1/vulns/export               导出漏洞（CSV/JSON）
```

### GET /api/v1/vulns

查询参数:
| 参数 | 类型 | 说明 |
|------|------|------|
| severity | string | critical/high/medium/low/info |
| type | string | sqli/xss/rce/ssrf/info_leak/weak_pass/... |
| status | string | open/confirmed/fixed/ignored/false_positive |
| task_id | string | 关联任务 |
| asset_id | string | 关联资产 |
| plugin_id | string | 触发的插件 |
| target | string | 目标 URL/IP |
| keyword | string | 搜索 |
| date_from | string | 发现时间起始 |
| date_to | string | 发现时间结束 |

### GET /api/v1/vulns/:id

```json
{
  "id": "01HX...",
  "plugin_id": "CVE-2024-XXXX",
  "name": "Apache Struts2 远程代码执行",
  "severity": "critical",
  "cvss_score": 9.8,
  "type": "rce",
  "status": "open",
  "target": "https://example.com/struts2/action",
  "asset": { "id": "...", "value": "example.com", "type": "domain" },
  "task": { "id": "...", "name": "每周全量扫描" },
  "detail": {
    "url": "https://example.com/struts2/action",
    "method": "POST",
    "param": "Content-Type",
    "payload": "...",
    "evidence": "Response contains 'uid=0(root)'",
    "request": "POST /struts2/action HTTP/1.1\n...",
    "response": "HTTP/1.1 200 OK\n..."
  },
  "solution": "升级 Apache Struts2 到最新版本",
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-XXXX",
    "https://struts.apache.org/announce-2024"
  ],
  "first_found_at": "2026-04-28T10:30:00Z",
  "last_found_at": "2026-04-30T10:30:00Z"
}
```

### PUT /api/v1/vulns/:id/status

```json
{ "status": "confirmed", "comment": "已确认，通知开发修复" }
// 或
{ "status": "false_positive", "comment": "误报：WAF 自动返回了匹配关键词" }
```

---

## 6. 报告 API

```
GET    /api/v1/reports                    报告列表
POST   /api/v1/reports                    生成报告
GET    /api/v1/reports/:id                报告详情
GET    /api/v1/reports/:id/download       下载报告文件
DELETE /api/v1/reports/:id                删除报告
```

### POST /api/v1/reports

```json
{
  "name": "2026年4月安全扫描报告",
  "type": "full",          // full, executive, compliance, diff
  "format": "pdf",          // pdf, html, json, csv
  "task_ids": ["xxx"],      // 关联的任务
  "date_range": {
    "from": "2026-04-01",
    "to": "2026-04-30"
  },
  "options": {
    "include_evidence": true,
    "include_solution": true,
    "severity_filter": ["critical", "high"]
  }
}
```

---

## 7. 插件管理 API

```
GET    /api/v1/plugins                    插件列表
GET    /api/v1/plugins/:id                插件详情
POST   /api/v1/plugins                    上传 PoC
PUT    /api/v1/plugins/:id                更新 PoC
DELETE /api/v1/plugins/:id                删除 PoC
POST   /api/v1/plugins/:id/toggle         启用/禁用
GET    /api/v1/plugins/stats              插件统计（按类型/严重程度）
POST   /api/v1/plugins/sync              从远程仓库同步
```

---

## 8. 集群管理 API

```
GET    /api/v1/cluster/workers            Worker 节点列表
GET    /api/v1/cluster/workers/:id        Worker 详情
POST   /api/v1/cluster/workers/:id/drain  设为 draining（不再分配新任务）
POST   /api/v1/cluster/workers/:id/online 设为 online
GET    /api/v1/cluster/overview           集群概览
GET    /api/v1/cluster/metrics            集群指标
```

### GET /api/v1/cluster/overview

```json
{
  "total_workers": 5,
  "online_workers": 4,
  "offline_workers": 1,
  "total_capacity": 2500,
  "current_load": 890,
  "load_percent": 35.6,
  "running_tasks": 12,
  "queued_tasks": 45,
  "avg_cpu_percent": 42.3,
  "avg_mem_percent": 56.1
}
```

---

## 9. 仪表盘 API

```
GET    /api/v1/dashboard/overview         总览数据
GET    /api/v1/dashboard/vuln-trends      漏洞趋势图
GET    /api/v1/dashboard/task-stats       任务统计
GET    /api/v1/dashboard/severity-dist    漏洞严重程度分布
GET    /api/v1/dashboard/top-vulns        TOP 漏洞类型
GET    /api/v1/dashboard/top-assets       高风险资产 TOP
GET    /api/v1/dashboard/recent-vulns     最近发现的漏洞
GET    /api/v1/dashboard/recent-tasks     最近的任务
```

### GET /api/v1/dashboard/overview

```json
{
  "assets": { "total": 5200, "active": 4800, "new_this_week": 120 },
  "vulnerabilities": {
    "total": 3400,
    "open": 890,
    "by_severity": { "critical": 12, "high": 89, "medium": 456, "low": 333 },
    "new_this_week": 45,
    "fixed_this_week": 23
  },
  "tasks": {
    "total": 280,
    "running": 3,
    "completed_this_week": 12
  },
  "cluster": {
    "workers_online": 4,
    "load_percent": 35.6
  }
}
```

---

## 10. WebSocket 实时推送

```
连接: ws://host/ws/v1?token=<jwt>

消息格式:
{
  "type": "event_type",
  "data": { ... },
  "timestamp": 1714463000
}
```

### 事件类型

| type | 说明 | 推送时机 |
|------|------|----------|
| `task.progress` | 任务进度 | 每 2 秒 |
| `task.status_changed` | 任务状态变更 | 启动/完成/失败/暂停 |
| `vuln.found` | 新漏洞发现 | 实时 |
| `worker.status_changed` | Worker 上下线 | 实时 |
| `scan.stage_changed` | 扫描阶段切换 | 实时 |
| `notification` | 系统通知 | 实时 |

### 订阅机制

```json
// 客户端发送：订阅指定任务
{ "action": "subscribe", "channel": "task:01HX..." }

// 客户端发送：取消订阅
{ "action": "unsubscribe", "channel": "task:01HX..." }

// 客户端发送：订阅所有漏洞
{ "action": "subscribe", "channel": "vulns" }
```

---

## 11. 通知配置 API

```
GET    /api/v1/notifications/channels     通知渠道列表
POST   /api/v1/notifications/channels     创建通知渠道
PUT    /api/v1/notifications/channels/:id 更新渠道
DELETE /api/v1/notifications/channels/:id 删除渠道
POST   /api/v1/notifications/test         测试通知发送
GET    /api/v1/notifications/rules        通知规则列表
POST   /api/v1/notifications/rules        创建通知规则
```

### 通知规则示例

```json
{
  "name": "高危漏洞即时通知",
  "enabled": true,
  "conditions": {
    "event": "vuln.found",
    "severity": ["critical", "high"],
    "types": ["rce", "sqli"]
  },
  "channels": ["email:security@company.com", "webhook:https://hooks.dingtalk.com/..."],
  "cooldown_minutes": 30
}
```
