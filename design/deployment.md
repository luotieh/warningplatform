# 漏洞扫描系统 — 部署与运维设计

## 1. 部署模式

### 1.1 单机模式 (All-in-One)

适用于开发调试、小规模扫描（<1000 目标）。

```yaml
# docker-compose.standalone.yml
services:
  vulnscan:
    build: .
    command: ["./vulnscan", "serve", "--mode=standalone"]
    ports:
      - "8080:8080"   # API + Web
      - "9090:9090"   # gRPC (内部)
    environment:
      - DB_DSN=postgres://vulnscan:pass@postgres:5432/vulnscan?sslmode=disable
      - REDIS_ADDR=redis:6379
      - MINIO_ENDPOINT=minio:9000
    depends_on:
      - postgres
      - redis
      - minio

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: vulnscan
      POSTGRES_USER: vulnscan
      POSTGRES_PASSWORD: pass
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    volumes:
      - miniodata:/data
    ports:
      - "9000:9000"
      - "9001:9001"

volumes:
  pgdata:
  miniodata:
```

### 1.2 分布式模式

适用于生产环境，各组件独立部署和扩缩容。

```yaml
# docker-compose.distributed.yml
services:
  # --- API 服务 (无状态，可多副本) ---
  api:
    build: .
    command: ["./vulnscan", "serve", "--mode=api"]
    ports:
      - "8080:8080"
    deploy:
      replicas: 2
    environment:
      - DB_DSN=postgres://vulnscan:pass@postgres:5432/vulnscan?sslmode=disable
      - REDIS_ADDR=redis:6379
      - NATS_URL=nats://nats:4222

  # --- Master 调度器 (主备模式) ---
  master:
    build: .
    command: ["./vulnscan", "serve", "--mode=master"]
    deploy:
      replicas: 2  # 主备，通过 Redis 锁选举
    environment:
      - DB_DSN=postgres://vulnscan:pass@postgres:5432/vulnscan?sslmode=disable
      - REDIS_ADDR=redis:6379
      - NATS_URL=nats://nats:4222
      - GRPC_PORT=9090

  # --- Worker 扫描节点 (无状态，水平扩展) ---
  worker:
    build: .
    command: ["./vulnscan", "serve", "--mode=worker"]
    deploy:
      replicas: 4
    environment:
      - MASTER_ADDR=master:9090
      - REDIS_ADDR=redis:6379
      - NATS_URL=nats://nats:4222
      - WORKER_MAX_CONCURRENT=500
    volumes:
      - ./plugins:/app/plugins:ro

  # --- 基础设施 ---
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: vulnscan
      POSTGRES_USER: vulnscan
      POSTGRES_PASSWORD: ${PG_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}

  nats:
    image: nats:2-alpine
    command: ["-js", "-sd", "/data"]
    volumes:
      - natsdata:/data

  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: ${MINIO_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_PASSWORD}
    volumes:
      - miniodata:/data

  clickhouse:
    image: clickhouse/clickhouse-server:latest
    volumes:
      - chdata:/var/lib/clickhouse

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./deploy/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./web/dist:/usr/share/nginx/html:ro

volumes:
  pgdata:
  natsdata:
  miniodata:
  chdata:
```

### 1.3 K8s 模式

```yaml
# deploy/k8s/worker-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnscan-worker
spec:
  replicas: 4
  selector:
    matchLabels:
      app: vulnscan-worker
  template:
    metadata:
      labels:
        app: vulnscan-worker
    spec:
      containers:
        - name: worker
          image: vulnscan:latest
          command: ["./vulnscan", "serve", "--mode=worker"]
          resources:
            requests: { cpu: "500m", memory: "512Mi" }
            limits:   { cpu: "2000m", memory: "2Gi" }
          env:
            - name: MASTER_ADDR
              value: "vulnscan-master:9090"
            - name: WORKER_MAX_CONCURRENT
              value: "500"
          volumeMounts:
            - name: plugins
              mountPath: /app/plugins
              readOnly: true
      volumes:
        - name: plugins
          configMap:
            name: vulnscan-plugins
---
# Worker HPA (基于 Redis 队列长度自动扩缩容)
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: vulnscan-worker-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: vulnscan-worker
  minReplicas: 2
  maxReplicas: 20
  metrics:
    - type: External
      external:
        metric:
          name: redis_queue_length
          selector:
            matchLabels:
              queue: "task:queue"
        target:
          type: AverageValue
          averageValue: "50"
```

## 2. 构建

### Dockerfile

```dockerfile
# ── Build Stage ──
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=$(git describe --tags --always)" \
    -o vulnscan ./cmd/vulnscan

# ── Runtime Stage ──
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/vulnscan .
COPY --from=builder /app/plugins ./plugins
COPY --from=builder /app/configs ./configs

EXPOSE 8080 9090
ENTRYPOINT ["./vulnscan"]
CMD ["serve", "--mode=standalone"]
```

### Makefile

```makefile
VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build run test lint docker

build:
	go build $(LDFLAGS) -o bin/vulnscan ./cmd/vulnscan

run-standalone:
	go run ./cmd/vulnscan serve --mode=standalone

run-api:
	go run ./cmd/vulnscan serve --mode=api

run-master:
	go run ./cmd/vulnscan serve --mode=master

run-worker:
	go run ./cmd/vulnscan serve --mode=worker

test:
	go test ./... -v -race -coverprofile=coverage.out

lint:
	golangci-lint run ./...

docker:
	docker build -t vulnscan:$(VERSION) .

docker-compose-up:
	docker compose -f deploy/docker/docker-compose.yml up -d

docker-compose-down:
	docker compose -f deploy/docker/docker-compose.yml down

migrate:
	go run ./cmd/vulnscan migrate up

migrate-down:
	go run ./cmd/vulnscan migrate down
```

## 3. 配置管理

```yaml
# configs/config.yaml
server:
  mode: standalone          # standalone, api, master, worker
  http_port: 8080
  grpc_port: 9090
  debug: false

database:
  dsn: "postgres://vulnscan:pass@localhost:5432/vulnscan?sslmode=disable"
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 1h

redis:
  addr: "localhost:6379"
  password: ""
  db: 0
  pool_size: 20

nats:
  url: "nats://localhost:4222"
  cluster_id: "vulnscan"

minio:
  endpoint: "localhost:9000"
  access_key: "minioadmin"
  secret_key: "minioadmin"
  bucket: "vulnscan-reports"
  use_ssl: false

clickhouse:
  dsn: "tcp://localhost:9000?database=vulnscan"

engine:
  max_concurrent: 500
  global_rps: 1000
  per_target_rps: 50
  connect_timeout: 5s
  read_timeout: 10s
  poc_timeout: 30s
  plugin_dir: "./plugins"

master:
  heartbeat_interval: 10s
  heartbeat_timeout: 30s
  dispatch_interval: 1s
  max_retry: 3

worker:
  master_addr: "localhost:9090"
  max_concurrent: 500
  heartbeat_interval: 10s
  labels:
    region: "default"
    network: "internal"

auth:
  jwt_secret: "${JWT_SECRET}"
  token_expire: 2h
  refresh_expire: 168h

notify:
  email:
    host: "smtp.example.com"
    port: 587
    username: "alert@example.com"
    password: "${SMTP_PASSWORD}"
  webhook:
    timeout: 10s

logging:
  level: info               # debug, info, warn, error
  format: json              # json, text
  output: stdout            # stdout, file
  file:
    path: "./logs/vulnscan.log"
    max_size_mb: 100
    max_backups: 10
    max_age_days: 30
```

## 4. 监控

### 4.1 Prometheus 指标

```
# 应用指标 (通过 /metrics 暴露)
vulnscan_tasks_total{status}              总任务数（按状态）
vulnscan_tasks_active                     当前运行中的任务
vulnscan_subtasks_total{status}           子任务数
vulnscan_vulns_found_total{severity}      发现的漏洞总数（按严重程度）
vulnscan_scan_requests_total{module}      扫描请求总数（按模块）
vulnscan_scan_latency_seconds{module}     扫描延迟（直方图）
vulnscan_scan_errors_total{module,type}   扫描错误数

# Worker 指标
vulnscan_worker_load_percent              Worker 负载百分比
vulnscan_worker_goroutines                Worker goroutine 数
vulnscan_worker_connections_active        活跃连接数

# 集群指标
vulnscan_cluster_workers_total{status}    Worker 总数（按状态）
vulnscan_cluster_queue_length{priority}   队列长度（按优先级）
```

### 4.2 健康检查

```
GET /healthz            → 200 OK (存活检查)
GET /readyz             → 200 OK (就绪检查，DB/Redis 连通)
GET /metrics            → Prometheus 格式指标
```

## 5. 安全加固

| 维度 | 措施 |
|------|------|
| 认证 | JWT Token + 刷新机制 |
| 授权 | RBAC (admin / operator / viewer) |
| 传输 | HTTPS + gRPC TLS |
| 存储 | 敏感配置环境变量注入，漏洞证据加密存储 |
| API 安全 | 限流、参数校验、输入过滤 |
| 审计 | 所有操作记录审计日志 |
| 扫描授权 | 目标白名单机制，需在系统中明确添加授权目标 |
| 容器安全 | Non-root 运行、只读文件系统、最小权限 |

## 6. 备份与恢复

```bash
# PostgreSQL 备份（每日 cron）
pg_dump -U vulnscan -F c vulnscan > backup/pg_$(date +%Y%m%d).dump

# Redis RDB 快照
redis-cli BGSAVE

# MinIO 备份
mc mirror minio/vulnscan-reports backup/minio/

# 恢复
pg_restore -U vulnscan -d vulnscan backup/pg_20260430.dump
```

## 7. 日志管理

```
日志分级：
- API 请求日志 → stdout → 采集到 ELK/Loki
- 扫描日志 → ClickHouse (结构化，可查询)
- 审计日志 → PostgreSQL (强一致，不可删)
- 错误日志 → stdout + 文件 → 告警

日志格式 (JSON):
{
  "time": "2026-04-30T10:00:00Z",
  "level": "info",
  "msg": "task started",
  "task_id": "01HX...",
  "targets_count": 512,
  "worker_id": "worker-01",
  "trace_id": "abc123"
}
```

## 8. 升级策略

| 组件 | 策略 |
|------|------|
| API | 滚动更新 (zero-downtime)，新旧版本共存 |
| Master | 主备切换，新版本先部署备节点 |
| Worker | 滚动替换，drain → 等待当前任务完成 → 更新 → 上线 |
| 数据库 | Migration 脚本，向前兼容 |
| 插件 | 热加载，不需要重启 Worker |

## 9. 容量规划参考

| 规模 | 目标数 | Worker 数 | CPU | 内存 | PG | Redis |
|------|--------|-----------|-----|------|----|-------|
| 小型 | <1K | 1 (standalone) | 2C | 4G | 单实例 | 单实例 |
| 中型 | 1K-10K | 2-4 | 4C×4 | 8G×4 | 单实例 | 单实例 |
| 大型 | 10K-100K | 5-20 | 8C×20 | 16G×20 | 主备 | 哨兵 |
| 超大 | 100K+ | 20-100 | 8C×100 | 16G×100 | PG集群 | Redis集群 |
