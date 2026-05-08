# 漏洞扫描系统 — 分布式调度与任务系统设计

## 1. 调度架构

```
┌──────────────────────────────────────────────────────┐
│                    Master Scheduler                   │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐ │
│  │ Task     │  │ Shard    │  │ Worker Registry    │ │
│  │ Manager  │  │ Engine   │  │ & Health Monitor   │ │
│  │          │  │          │  │                    │ │
│  │ 创建     │  │ 按IP段   │  │ 注册/注销         │ │
│  │ 排队     │  │ 按域名   │  │ 心跳检测          │ │
│  │ 状态机   │  │ 按端口范围│  │ 负载感知          │ │
│  └────┬─────┘  └────┬─────┘  └────────┬───────────┘ │
│       │             │                  │             │
│  ┌────▼─────────────▼──────────────────▼───────────┐ │
│  │              Dispatch Engine                     │ │
│  │  优先级队列 │ 负载均衡 │ 故障转移 │ 去重        │ │
│  └──────────────────────┬──────────────────────────┘ │
└─────────────────────────┼────────────────────────────┘
                          │ gRPC / NATS
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
    ┌──────────┐   ┌──────────┐   ┌──────────┐
    │ Worker-1 │   │ Worker-2 │   │ Worker-N │
    │ cap: 500 │   │ cap: 300 │   │ cap: 800 │
    │ load: 40%│   │ load: 65%│   │ load: 20%│
    └──────────┘   └──────────┘   └──────────┘
```

## 2. 任务状态机

```
                     ┌──────────┐
         create ──→  │ pending  │
                     └────┬─────┘
                          │ enqueue
                     ┌────▼─────┐
                     │  queued  │ ──→ [cancel] ──→ cancelled
                     └────┬─────┘
                          │ dispatch to worker
                     ┌────▼─────┐
          ┌──────→   │ running  │ ──→ [cancel] ──→ cancelled
          │          └─┬──┬──┬──┘
          │ resume     │  │  │
     ┌────┴─────┐      │  │  └──→ [error] ──→ failed
     │  paused  │ ◄────┘  │                       │
     └──────────┘  pause  │                  retry │ (≤3次)
                          │                       │
                          ▼                  ┌────▼─────┐
                    ┌──────────┐             │  queued  │
                    │completed │             └──────────┘
                    └──────────┘
```

**状态转移规则：**

| 当前状态 | 事件 | 目标状态 | 条件 |
|----------|------|----------|------|
| pending | 系统检查通过 | queued | 目标有效、配额充足 |
| queued | 调度到 Worker | running | 有空闲 Worker |
| running | 所有子任务完成 | completed | - |
| running | 任何子任务失败 | failed | 超过重试上限 |
| running | 用户操作 | paused | - |
| running | 用户操作 | cancelled | - |
| paused | 用户操作 | running | 重新分配子任务 |
| failed | 自动重试 | queued | retry_count < max_retries |

## 3. 分片策略

### 3.1 分片算法

```go
type ShardStrategy interface {
    Shard(targets []string, numWorkers int) [][]string
}

// IPRangeShard 按 IP 段均匀分片
type IPRangeShard struct{}

func (s *IPRangeShard) Shard(targets []string, numWorkers int) [][]string {
    // 1. 将所有目标展开为 IP 列表
    ips := expandTargets(targets) // CIDR → IPs, domains → resolve

    // 2. 按 numWorkers 均匀分组
    shards := make([][]string, numWorkers)
    for i, ip := range ips {
        shards[i%numWorkers] = append(shards[i%numWorkers], ip)
    }
    return shards
}

// HashShard 一致性哈希分片（适合增量扫描）
type HashShard struct {
    ring *consistent.HashRing
}

func (s *HashShard) Shard(targets []string, numWorkers int) [][]string {
    shards := make([][]string, numWorkers)
    for _, target := range targets {
        workerIdx := s.ring.Get(target) // 一致性哈希
        shards[workerIdx] = append(shards[workerIdx], target)
    }
    return shards
}

// PortRangeShard 按端口范围分片（大量端口扫描场景）
type PortRangeShard struct{}

func (s *PortRangeShard) Shard(targets []string, numWorkers int) [][]string {
    // 每个 Worker 负责一段端口
    // Worker-0: ports 1-10000
    // Worker-1: ports 10001-20000
    // ...
    portRanges := splitPortRange(1, 65535, numWorkers)
    shards := make([][]string, numWorkers)
    for i, pr := range portRanges {
        for _, target := range targets {
            shards[i] = append(shards[i], fmt.Sprintf("%s:%d-%d", target, pr.Start, pr.End))
        }
    }
    return shards
}
```

### 3.2 分片选择规则

| 任务类型 | 默认分片策略 | 说明 |
|----------|-------------|------|
| full (全量扫描) | IPRangeShard | 按目标 IP 均匀分 |
| port (端口扫描) | PortRangeShard | 大端口范围按段分 |
| web (Web 扫描) | IPRangeShard | 按 URL 域名分 |
| subdomain (子域名) | 不分片 | 单 Worker 执行 |
| vuln (漏洞验证) | IPRangeShard | 按目标分 |
| custom | 由配置决定 | 用户指定 |

## 4. Worker 注册与健康检查

### 4.1 注册协议 (gRPC)

```protobuf
service SchedulerService {
    // Worker 注册
    rpc Register(RegisterRequest) returns (RegisterResponse);
    // 心跳上报
    rpc Heartbeat(stream HeartbeatRequest) returns (stream HeartbeatResponse);
    // 拉取任务
    rpc PullTask(PullTaskRequest) returns (PullTaskResponse);
    // 上报结果
    rpc ReportResult(stream ResultReport) returns (ReportAck);
    // 上报进度
    rpc ReportProgress(ProgressReport) returns (ReportAck);
}

message RegisterRequest {
    string worker_id = 1;
    string hostname = 2;
    string ip = 3;
    int32 port = 4;
    string version = 5;
    WorkerCapacity capacity = 6;
    map<string, string> labels = 7;
}

message WorkerCapacity {
    int32 max_concurrent = 1;
    int32 cpu_cores = 2;
    int64 memory_bytes = 3;
    int64 bandwidth_bps = 4;
}

message HeartbeatRequest {
    string worker_id = 1;
    WorkerLoad current_load = 2;
    int64 timestamp = 3;
}

message WorkerLoad {
    int32 running_tasks = 1;
    float cpu_percent = 2;
    float mem_percent = 3;
    int64 net_bytes_sent = 4;
    int64 net_bytes_recv = 5;
}
```

### 4.2 健康检查逻辑

```go
type WorkerRegistry struct {
    mu      sync.RWMutex
    workers map[string]*WorkerInfo
    // 心跳超时（连续 3 次未收到心跳视为离线）
    heartbeatTimeout time.Duration // 默认 30s
}

type WorkerInfo struct {
    ID           string
    Hostname     string
    IP           string
    Port         int
    Version      string
    Capacity     WorkerCapacity
    CurrentLoad  WorkerLoad
    Labels       map[string]string
    Status       string    // online, offline, draining
    LastHeartbeat time.Time
    RegisteredAt time.Time
}

func (r *WorkerRegistry) CheckHealth() {
    r.mu.Lock()
    defer r.mu.Unlock()

    cutoff := time.Now().Add(-r.heartbeatTimeout)
    for id, w := range r.workers {
        if w.LastHeartbeat.Before(cutoff) && w.Status == "online" {
            w.Status = "offline"
            // 触发故障转移：将该 Worker 的子任务重新入队
            go r.failoverWorker(id)
        }
    }
}
```

## 5. 负载均衡调度

```go
type LoadBalancer interface {
    SelectWorker(workers []*WorkerInfo, task *SubTask) *WorkerInfo
}

// WeightedLoadBalancer 加权负载均衡
type WeightedLoadBalancer struct{}

func (lb *WeightedLoadBalancer) SelectWorker(workers []*WorkerInfo, task *SubTask) *WorkerInfo {
    var best *WorkerInfo
    bestScore := float64(-1)

    for _, w := range workers {
        if w.Status != "online" {
            continue
        }
        if w.CurrentLoad.RunningTasks >= w.Capacity.MaxConcurrent {
            continue
        }

        // 评分公式：空闲容量越大、负载越低 → 分数越高
        capacityRatio := 1.0 - float64(w.CurrentLoad.RunningTasks)/float64(w.Capacity.MaxConcurrent)
        cpuScore := 1.0 - float64(w.CurrentLoad.CpuPercent)/100.0
        memScore := 1.0 - float64(w.CurrentLoad.MemPercent)/100.0

        score := capacityRatio*0.5 + cpuScore*0.3 + memScore*0.2

        // 标签亲和：如果任务指定了 region/network，匹配的 Worker 加分
        if matchLabels(w.Labels, task.Labels) {
            score += 0.2
        }

        if score > bestScore {
            bestScore = score
            best = w
        }
    }
    return best
}
```

## 6. 故障转移

```go
// FailoverManager 故障转移管理器
type FailoverManager struct {
    registry  *WorkerRegistry
    taskStore TaskStore
    queue     TaskQueue
}

func (fm *FailoverManager) HandleWorkerDown(workerID string) {
    // 1. 查找该 Worker 上所有 running 的子任务
    subtasks := fm.taskStore.GetRunningSubtasks(workerID)

    for _, st := range subtasks {
        // 2. 检查重试次数
        if st.RetryCount >= 3 {
            fm.taskStore.UpdateSubtaskStatus(st.ID, "failed", "worker offline, max retries exceeded")
            continue
        }

        // 3. 重置状态，重新入队
        st.RetryCount++
        st.WorkerID = ""
        st.Status = "queued"
        fm.taskStore.UpdateSubtask(st)
        fm.queue.Enqueue(st)
    }
}
```

## 7. 进度追踪与实时推送

```go
// ProgressTracker 进度追踪器
type ProgressTracker struct {
    redis  redis.Client
    wsHub  *WebSocketHub
}

// UpdateProgress Worker 上报子任务进度
func (pt *ProgressTracker) UpdateProgress(taskID, subtaskID string, progress SubtaskProgress) {
    // 1. 更新 Redis 中的子任务进度
    key := fmt.Sprintf("task:%s:subtask:%s:progress", taskID, subtaskID)
    pt.redis.HSet(ctx, key, map[string]interface{}{
        "hosts_scanned": progress.HostsScanned,
        "ports_scanned": progress.PortsScanned,
        "vulns_found":   progress.VulnsFound,
        "stage":         progress.CurrentStage,
        "updated_at":    time.Now().Unix(),
    })

    // 2. 聚合父任务进度
    taskProgress := pt.aggregateTaskProgress(taskID)

    // 3. 推送 WebSocket
    pt.wsHub.Broadcast(taskID, WSMessage{
        Type: "task.progress",
        Data: taskProgress,
    })
}

func (pt *ProgressTracker) aggregateTaskProgress(taskID string) TaskProgress {
    // 从 Redis 聚合所有子任务进度
    pattern := fmt.Sprintf("task:%s:subtask:*:progress", taskID)
    keys := pt.redis.Keys(ctx, pattern).Val()

    var total TaskProgress
    for _, key := range keys {
        vals := pt.redis.HGetAll(ctx, key).Val()
        total.HostsScanned += parseInt(vals["hosts_scanned"])
        total.PortsScanned += parseInt(vals["ports_scanned"])
        total.VulnsFound += parseInt(vals["vulns_found"])
    }
    return total
}
```

## 8. 优先级队列

```go
// PriorityQueue 基于 Redis Sorted Set 的优先级队列
type PriorityQueue struct {
    redis redis.Client
    // 4 个优先级对应 4 个 ZSET
    keys [4]string // task:queue:p0, p1, p2, p3
}

func (q *PriorityQueue) Enqueue(subtask *SubTask) {
    score := float64(time.Now().UnixMilli())
    data, _ := json.Marshal(subtask)
    q.redis.ZAdd(ctx, q.keys[subtask.Priority], &redis.Z{
        Score:  score,
        Member: string(data),
    })
}

func (q *PriorityQueue) Dequeue() (*SubTask, error) {
    // 从高优先级到低优先级依次弹出
    for _, key := range q.keys {
        result, err := q.redis.ZPopMin(ctx, key, 1).Result()
        if err != nil || len(result) == 0 {
            continue
        }
        var st SubTask
        if err := json.Unmarshal([]byte(result[0].Member.(string)), &st); err != nil {
            continue
        }
        return &st, nil
    }
    return nil, ErrQueueEmpty
}
```

## 9. 定时任务调度

```go
// CronScheduler 定时任务调度器
type CronScheduler struct {
    store     ScheduledTaskStore
    taskMgr   *TaskManager
    ticker    *time.Ticker
    stopCh    chan struct{}
}

func (cs *CronScheduler) Run() {
    cs.ticker = time.NewTicker(30 * time.Second) // 每 30 秒检查一次
    for {
        select {
        case <-cs.ticker.C:
            cs.checkAndDispatch()
        case <-cs.stopCh:
            return
        }
    }
}

func (cs *CronScheduler) checkAndDispatch() {
    now := time.Now()
    tasks := cs.store.GetDueScheduledTasks(now)

    for _, st := range tasks {
        // 创建扫描任务
        task := cs.taskMgr.CreateFromTemplate(st.TaskConfig)
        task.ScheduledTaskID = st.ID

        // 更新下次执行时间
        nextRun := cronexpr.MustParse(st.CronExpr).Next(now)
        cs.store.UpdateNextRun(st.ID, nextRun)
    }
}
```

## 10. 并发安全保证

| 场景 | 机制 |
|------|------|
| 多 Master 竞争调度 | Redis 分布式锁 `lock:scheduler:dispatch` |
| 同一目标并行扫描 | Redis 锁 `lock:target:{ip}:{port}`，TTL 10min |
| Worker 任务认领 | Redis ZPOPMIN 原子操作 |
| 子任务状态更新 | PostgreSQL 行锁 + 乐观锁（updated_at） |
| 进度写入竞态 | Redis HINCRBY 原子递增 |
| 定时任务重复触发 | Redis `SETNX lock:cron:{task_id}` TTL=执行间隔 |
