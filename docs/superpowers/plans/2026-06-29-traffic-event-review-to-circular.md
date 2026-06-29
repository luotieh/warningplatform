# 流量分析安全事件审核 → 通报处置 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为流量分析安全事件增加人工审核，通过审核的事件经 HTTP（透传用户 token）推送到通报处置 `/api/circular/transfers`，并把事件字段对齐到 `TransferIncidentReq`。

**Architecture:** 纯 traffic 侧改动。给 `events` 表/`domain.Event` 增审核字段；新增 `CircularClient`（仿 `DeepSOCClient`）与 `Event→TransferIncidentReq` 映射；新增 `POST /events/detail/:eventID/review` 接口；前端事件列表加审核按钮与状态列。鉴权靠审核请求透传入站 `Authorization` 头。

**Tech Stack:** Go（gin、database/sql、google/wire）、Vue3 + naive-ui（vben admin）。

## Global Constraints

- **仅修改流量分析侧**：只动 `vulnscan-backend/traffic/**` 与前端 `vulnscan-frontend/apps/web/src/{api/ly,views/ly}/**`。**不得修改** `circular/`、`di/`、`scanrunner/`、`model/` 等其它模块或目录。
- 分支：`trafficanalysis`。
- circular 接收端：`POST {base}/api/circular/transfers`，请求体 `TransferIncidentReq`，**走 IAM 鉴权**——必须携带有效用户 `Authorization: Bearer <token>`。
- 必填字段（circular 校验）：`incident_no`、`name`。
- 仅 `event_status == "round_finished"` 的事件可审核/推送。
- 幂等：`Event.circular_code` 非空即视为已推送，approve 不重复推送。
- Go module 根：`vulnscan-backend`（在该目录下 `go test`/`go build`）。

---

### Task 1: events 表与 domain.Event 增加审核字段

给事件主表加审核/推送字段，并放开 `UpdateEvent` patch 白名单（postgres + memory 两实现）。

**Files:**
- Modify: `vulnscan-backend/traffic/internal/domain/models.go:29-44`（`Event` 结构）
- Modify: `vulnscan-backend/traffic/internal/store/schema.go:19-34`（建表）+ 文件内迁移区
- Modify: `vulnscan-backend/traffic/internal/store/postgres.go`（`CreateEvent` 165-192、`GetEvent` 194-200、`ListEvents` 202-219、`UpdateEvent` 221-250、`scanEvent` 649-657）
- Modify: `vulnscan-backend/traffic/internal/store/memory.go:223-248`（`UpdateEvent`）
- Test: `vulnscan-backend/traffic/internal/store/event_review_test.go`（新建）

**Interfaces:**
- Produces:
  - `domain.Event` 新增字段：`ReviewStatus string`(json `review_status`)、`ReviewComment string`(json `review_comment`)、`ReviewedBy string`(json `reviewed_by`)、`ReviewedAt *time.Time`(json `reviewed_at,omitempty`)、`CircularCode string`(json `circular_code`)。
  - `store.UpdateEvent(eventID, patch)` 新支持 patch key：`review_status`、`review_comment`、`reviewed_by`、`circular_code`（字符串）、`reviewed_at`（RFC3339 字符串 → 解析为 `*time.Time`）。

- [ ] **Step 1: 写失败测试**

新建 `vulnscan-backend/traffic/internal/store/event_review_test.go`：

```go
package store

import (
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

func TestMemoryStoreUpdateEventReviewFields(t *testing.T) {
	s := NewMemoryStore()
	created, err := s.CreateEvent(domain.Event{EventID: "evt-review-1", EventStatus: "round_finished"})
	if err != nil {
		t.Fatalf("create event: %v", err)
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	updated, ok := s.UpdateEvent(created.EventID, map[string]any{
		"review_status":  "approved",
		"review_comment": "ok",
		"reviewed_by":    "alice",
		"reviewed_at":    ts,
		"circular_code":  "XF-2026-0001",
	})
	if !ok {
		t.Fatal("update returned not ok")
	}
	if updated.ReviewStatus != "approved" || updated.ReviewComment != "ok" ||
		updated.ReviewedBy != "alice" || updated.CircularCode != "XF-2026-0001" {
		t.Fatalf("review fields not patched: %+v", updated)
	}
	if updated.ReviewedAt == nil {
		t.Fatal("reviewed_at not set")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd vulnscan-backend && go test ./traffic/internal/store/ -run TestMemoryStoreUpdateEventReviewFields -v`
Expected: 编译失败（`ReviewStatus` 等字段未定义）。

- [ ] **Step 3: 给 `domain.Event` 加字段**

在 `models.go` 把 `Event` 结构改为（在 `UpdatedAt` 后追加 5 个字段）：

```go
type Event struct {
	ID            int64      `json:"id"`
	EventID       string     `json:"event_id"`
	EventName     string     `json:"event_name,omitempty"`
	Title         string     `json:"title,omitempty"`
	Message       string     `json:"message"`
	Context       string     `json:"context,omitempty"`
	Source        string     `json:"source,omitempty"`
	Severity      string     `json:"severity"`
	Category      string     `json:"category,omitempty"`
	EventStatus   string     `json:"event_status"`
	CurrentRound  int        `json:"current_round"`
	Observables   []IOC      `json:"observables,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ReviewStatus  string     `json:"review_status"`
	ReviewComment string     `json:"review_comment,omitempty"`
	ReviewedBy    string     `json:"reviewed_by,omitempty"`
	ReviewedAt    *time.Time `json:"reviewed_at,omitempty"`
	CircularCode  string     `json:"circular_code,omitempty"`
}
```

- [ ] **Step 4: 改建表语句与迁移**

`schema.go` 把 `events` 建表的 `updated_at` 行后补列（注意末列无逗号）：

```sql
CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(128) UNIQUE NOT NULL,
    event_name VARCHAR(256) NOT NULL DEFAULT '',
    title VARCHAR(256) NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    context TEXT NOT NULL DEFAULT '',
    source VARCHAR(64) NOT NULL DEFAULT '',
    severity VARCHAR(32) NOT NULL DEFAULT 'medium',
    category VARCHAR(128) NOT NULL DEFAULT '',
    event_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    current_round INTEGER NOT NULL DEFAULT 1,
    observables JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    review_status VARCHAR(32) NOT NULL DEFAULT '',
    review_comment TEXT NOT NULL DEFAULT '',
    reviewed_by VARCHAR(128) NOT NULL DEFAULT '',
    reviewed_at TIMESTAMPTZ NULL,
    circular_code VARCHAR(70) NOT NULL DEFAULT ''
);
```

同文件末尾（索引定义附近，`PostgresSchema` 常量内）追加幂等迁移，保证旧库增量加列：

```sql
ALTER TABLE events ADD COLUMN IF NOT EXISTS review_status VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS review_comment TEXT NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS reviewed_by VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ NULL;
ALTER TABLE events ADD COLUMN IF NOT EXISTS circular_code VARCHAR(70) NOT NULL DEFAULT '';
```

> 说明：`PostgresSchema` 整体作为一条多语句字符串执行；`CREATE TABLE IF NOT EXISTS` 对已存在表不会补列，故必须显式 `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`。

- [ ] **Step 5: 改 postgres store 的 SQL 与 scan**

`postgres.go` — `scanEvent`（649-657）改为：

```go
func scanEvent(row scanner) (domain.Event, error) {
	var e domain.Event
	var obs []byte
	err := row.Scan(&e.ID, &e.EventID, &e.EventName, &e.Title, &e.Message, &e.Context, &e.Source, &e.Severity, &e.Category, &e.EventStatus, &e.CurrentRound, &obs, &e.CreatedAt, &e.UpdatedAt, &e.ReviewStatus, &e.ReviewComment, &e.ReviewedBy, &e.ReviewedAt, &e.CircularCode)
	if len(obs) > 0 {
		_ = json.Unmarshal(obs, &e.Observables)
	}
	return e, err
}
```

`CreateEvent`（186-191）的 INSERT 改为带新列（新事件审核字段默认空，`RETURNING` 末尾补 5 列）：

```go
	row := s.db.QueryRowContext(context.Background(), `
INSERT INTO events (event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13)
RETURNING id, event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, created_at, updated_at, review_status, review_comment, reviewed_by, reviewed_at, circular_code`,
		e.EventID, e.EventName, e.Title, e.Message, e.Context, e.Source, e.Severity, e.Category, e.EventStatus, e.CurrentRound, string(toJSON(e.Observables)), e.CreatedAt, e.UpdatedAt)
	return scanEvent(row)
```

`GetEvent`（194-200）与 `ListEvents`（202-219）的 `SELECT` 列尾同样补 `, review_status, review_comment, reviewed_by, reviewed_at, circular_code`：

```go
// GetEvent
	row := s.db.QueryRowContext(context.Background(), `
SELECT id, event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, created_at, updated_at, review_status, review_comment, reviewed_by, reviewed_at, circular_code
FROM events WHERE event_id=$1`, eventID)
```

```go
// ListEvents
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, created_at, updated_at, review_status, review_comment, reviewed_by, reviewed_at, circular_code
FROM events ORDER BY created_at DESC, id DESC`)
```

`UpdateEvent`（221-250）：在 `event_status` patch 分支后、`e.UpdatedAt=` 之前插入新字段处理，并把 UPDATE 语句补列：

```go
	if v, ok := stringPatch(patch, "event_status"); ok {
		e.EventStatus = v
	}
	if v, ok := stringPatch(patch, "review_status"); ok {
		e.ReviewStatus = v
	}
	if v, ok := stringPatch(patch, "review_comment"); ok {
		e.ReviewComment = v
	}
	if v, ok := stringPatch(patch, "reviewed_by"); ok {
		e.ReviewedBy = v
	}
	if v, ok := stringPatch(patch, "circular_code"); ok {
		e.CircularCode = v
	}
	if v, ok := stringPatch(patch, "reviewed_at"); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			tu := t.UTC()
			e.ReviewedAt = &tu
		}
	}
	e.UpdatedAt = time.Now().UTC()
	row := s.db.QueryRowContext(context.Background(), `
UPDATE events
SET event_name=$2, title=$3, message=$4, context=$5, source=$6, severity=$7, category=$8, event_status=$9, current_round=$10, observables=$11::jsonb, updated_at=$12, review_status=$13, review_comment=$14, reviewed_by=$15, reviewed_at=$16, circular_code=$17
WHERE event_id=$1
RETURNING id, event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, created_at, updated_at, review_status, review_comment, reviewed_by, reviewed_at, circular_code`,
		eventID, e.EventName, e.Title, e.Message, e.Context, e.Source, e.Severity, e.Category, e.EventStatus, e.CurrentRound, string(toJSON(e.Observables)), e.UpdatedAt, e.ReviewStatus, e.ReviewComment, e.ReviewedBy, e.ReviewedAt, e.CircularCode)
	updated, err := scanEvent(row)
	return updated, err == nil
```

- [ ] **Step 6: 改 memory store 的 UpdateEvent**

`memory.go` `UpdateEvent`（223-248）在 `event_status` 分支后插入同样的新字段处理（写回 `s.events[eventID]=e` 之前）：

```go
	if v, ok := stringPatch(patch, "event_status"); ok {
		e.EventStatus = v
	}
	if v, ok := stringPatch(patch, "review_status"); ok {
		e.ReviewStatus = v
	}
	if v, ok := stringPatch(patch, "review_comment"); ok {
		e.ReviewComment = v
	}
	if v, ok := stringPatch(patch, "reviewed_by"); ok {
		e.ReviewedBy = v
	}
	if v, ok := stringPatch(patch, "circular_code"); ok {
		e.CircularCode = v
	}
	if v, ok := stringPatch(patch, "reviewed_at"); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			tu := t.UTC()
			e.ReviewedAt = &tu
		}
	}
	e.UpdatedAt = time.Now().UTC()
	s.events[eventID] = e
	return e, true
```

确认 `memory.go` 顶部已 import `"time"`（现有代码已用 `time.Now()`，无需新增）。

- [ ] **Step 7: 运行测试确认通过**

Run: `cd vulnscan-backend && go test ./traffic/internal/store/ -run TestMemoryStoreUpdateEventReviewFields -v`
Expected: PASS。

- [ ] **Step 8: 提交**

```bash
git add vulnscan-backend/traffic/internal/domain/models.go vulnscan-backend/traffic/internal/store/
git commit -m "feat(traffic): events 表新增审核字段并放开 UpdateEvent patch 白名单"
```

---

### Task 2: CircularClient + 配置（CircularBaseURL）

新增对 circular transfer 接口的 HTTP 客户端，透传 bearer，base 留空时由调用方提供回退 base。

**Files:**
- Create: `vulnscan-backend/traffic/internal/client/circular.go`
- Modify: `vulnscan-backend/traffic/internal/config/config.go:14-39,51-80`（Config 增字段 + Load）
- Test: `vulnscan-backend/traffic/internal/client/circular_test.go`（新建）

**Interfaces:**
- Produces:
  - 类型 `client.TransferIncidentReq` / `client.TransferAssetInfo` / `client.TransferMetadataInfo`（json tag 对齐 circular contract）。
  - `client.CircularClient{ BaseURL string; HTTP *http.Client }`。
  - 方法 `func (c CircularClient) ReceiveIncident(ctx context.Context, req TransferIncidentReq, bearer, fallbackBase string) (string, error)`，返回 circular 编号字符串。
  - `config.Config.CircularBaseURL string`（env `CIRCULAR_BASE_URL`，默认 `""`）。

- [ ] **Step 1: 写失败测试**

新建 `vulnscan-backend/traffic/internal/client/circular_test.go`：

```go
package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCircularClientReceiveIncident(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody TransferIncidentReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"circular_code":"XF-2026-0001"},"msg":""}`))
	}))
	defer srv.Close()

	c := CircularClient{HTTP: srv.Client()}
	// BaseURL 为空 → 用 fallbackBase
	code, err := c.ReceiveIncident(context.Background(), TransferIncidentReq{
		IncidentNo: "evt-1", Name: "测试事件",
	}, "Bearer tok-123", srv.URL)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if code != "XF-2026-0001" {
		t.Fatalf("unexpected code %q", code)
	}
	if gotAuth != "Bearer tok-123" {
		t.Fatalf("bearer not forwarded: %q", gotAuth)
	}
	if gotPath != "/api/circular/transfers" {
		t.Fatalf("unexpected path %q", gotPath)
	}
	if gotBody.IncidentNo != "evt-1" || gotBody.Name != "测试事件" {
		t.Fatalf("body mismatch: %+v", gotBody)
	}
}

func TestCircularClientMissingBase(t *testing.T) {
	c := CircularClient{HTTP: http.DefaultClient}
	_, err := c.ReceiveIncident(context.Background(), TransferIncidentReq{IncidentNo: "x", Name: "y"}, "", "")
	if err == nil {
		t.Fatal("expected error when base url empty")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd vulnscan-backend && go test ./traffic/internal/client/ -run TestCircularClient -v`
Expected: 编译失败（`CircularClient`/`TransferIncidentReq` 未定义）。

- [ ] **Step 3: 实现 CircularClient**

新建 `vulnscan-backend/traffic/internal/client/circular.go`：

```go
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// TransferIncidentReq 对齐 circular/transfer 的请求体（json tag 与 circular contract 一致）。
// 在 traffic 侧本地定义以避免跨模块 import。
type TransferIncidentReq struct {
	IncidentID   string                `json:"incident_id,omitempty"`
	IncidentNo   string                `json:"incident_no"`
	Name         string                `json:"name"`
	Level        int                   `json:"level,omitempty"`
	AiOpinion    string                `json:"ai_opinion,omitempty"`
	AiConfidence float64               `json:"ai_confidence,omitempty"`
	AssetInfo    *TransferAssetInfo    `json:"asset_info,omitempty"`
	MetadataInfo *TransferMetadataInfo `json:"metadata_info,omitempty"`
	SourceSystem string                `json:"source_system,omitempty"`
}

type TransferAssetInfo struct {
	AssetName    string `json:"asset_name,omitempty"`
	SystemName   string `json:"system_name,omitempty"`
	DomainIP     string `json:"domain_ip,omitempty"`
	SiteIP       string `json:"site_ip,omitempty"`
	Unit         string `json:"unit,omitempty"`
	UnitType     string `json:"unit_type,omitempty"`
	Industry     string `json:"industry,omitempty"`
	MLPSRecordNo string `json:"mlps_record_no,omitempty"`
	MLPSLevel    string `json:"mlps_level,omitempty"`
	Region       string `json:"region,omitempty"`
}

type TransferMetadataInfo struct {
	DataNo              string  `json:"data_no,omitempty"`
	IncidentType        string  `json:"incident_type,omitempty"`
	IncidentURL         string  `json:"incident_url,omitempty"`
	IncidentDescription string  `json:"incident_description,omitempty"`
	CvssScore           float64 `json:"cvss_score,omitempty"`
	CveId               string  `json:"cve_id,omitempty"`
}

// CircularClient 调用通报处置「安全事件流转」接口。
type CircularClient struct {
	BaseURL string // 配置项；留空则使用 ReceiveIncident 传入的 fallbackBase
	HTTP    *http.Client
}

// ReceiveIncident POST {base}/api/circular/transfers，透传调用方的 bearer。
// 返回通报处置生成的 circular_code。
func (c CircularClient) ReceiveIncident(ctx context.Context, req TransferIncidentReq, bearer, fallbackBase string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(fallbackBase), "/")
	}
	if base == "" {
		return "", errors.New("circular base url is empty")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/circular/transfers", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(bearer) != "" {
		httpReq.Header.Set("Authorization", bearer)
	}
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			CircularCode string `json:"circular_code"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("circular transfer failed: status=%d msg=%s", resp.StatusCode, out.Msg)
	}
	return out.Data.CircularCode, nil
}
```

- [ ] **Step 4: 配置增加 CircularBaseURL**

`config.go` 在 `Config` 结构（14-39）`DeepSOCAPIKey` 行后加：

```go
	CircularBaseURL         string
```

在 `Load()`（51-77）的 `DeepSOCAPIKey: ...` 行后加：

```go
		CircularBaseURL:         get("CIRCULAR_BASE_URL", ""),
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cd vulnscan-backend && go test ./traffic/internal/client/ -run TestCircularClient -v`
Expected: PASS（两个用例）。

- [ ] **Step 6: 提交**

```bash
git add vulnscan-backend/traffic/internal/client/circular.go vulnscan-backend/traffic/internal/client/circular_test.go vulnscan-backend/traffic/internal/config/config.go
git commit -m "feat(traffic): 新增 CircularClient 与 CIRCULAR_BASE_URL 配置"
```

---

### Task 3: Event → TransferIncidentReq 字段映射

把 `domain.Event`(+summaries) 映射为 `client.TransferIncidentReq`，含 severity→level、名称回退、IOC 资产解析、context 容错。

**Files:**
- Create: `vulnscan-backend/traffic/circular_mapping.go`（package `traffic`）
- Test: `vulnscan-backend/traffic/circular_mapping_test.go`（新建）

**Interfaces:**
- Consumes: `domain.Event`、`[]domain.Summary`、`client.TransferIncidentReq`（Task 2）。
- Produces: `func buildTransferIncidentReq(event domain.Event, summaries []domain.Summary) client.TransferIncidentReq`。
- Produces: `func severityToLevel(severity string) int`（critical→1, high→2, medium/middle→3, low→4, 其它→4）。

- [ ] **Step 1: 写失败测试**

新建 `vulnscan-backend/traffic/circular_mapping_test.go`：

```go
package traffic

import (
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func TestSeverityToLevel(t *testing.T) {
	cases := map[string]int{"critical": 1, "high": 2, "medium": 3, "middle": 3, "low": 4, "unknown": 4, "": 4}
	for sev, want := range cases {
		if got := severityToLevel(sev); got != want {
			t.Fatalf("severityToLevel(%q)=%d want %d", sev, got, want)
		}
	}
}

func TestBuildTransferIncidentReq(t *testing.T) {
	event := domain.Event{
		EventID:  "evt-9",
		Title:    "可疑横向移动",
		Message:  "命中规则：SMB 暴力破解",
		Severity: "high",
		Category: "lateral_movement",
		Context:  `{"victim_target":"DB-01","cve_id":"CVE-2024-1","cvss_score":7.5,"ai_confidence":0.92}`,
		Observables: []domain.IOC{
			{Type: "ip", Value: "10.0.0.5", Role: "source"},
			{Type: "ip", Value: "10.0.0.9", Role: "destination"},
		},
	}
	summaries := []domain.Summary{{EventSummary: "研判：确为攻击"}}

	req := buildTransferIncidentReq(event, summaries)

	if req.IncidentNo != "evt-9" {
		t.Fatalf("IncidentNo=%q", req.IncidentNo)
	}
	if req.Name != "可疑横向移动" {
		t.Fatalf("Name=%q", req.Name)
	}
	if req.Level != 2 {
		t.Fatalf("Level=%d want 2", req.Level)
	}
	if req.AiOpinion != "研判：确为攻击" {
		t.Fatalf("AiOpinion=%q", req.AiOpinion)
	}
	if req.AiConfidence != 0.92 {
		t.Fatalf("AiConfidence=%v", req.AiConfidence)
	}
	if req.SourceSystem == "" {
		t.Fatal("SourceSystem empty")
	}
	if req.AssetInfo == nil || req.AssetInfo.SiteIP != "10.0.0.9" {
		t.Fatalf("AssetInfo.SiteIP mismatch: %+v", req.AssetInfo)
	}
	if req.AssetInfo.AssetName != "DB-01" {
		t.Fatalf("AssetInfo.AssetName=%q", req.AssetInfo.AssetName)
	}
	if req.MetadataInfo == nil || req.MetadataInfo.CveId != "CVE-2024-1" || req.MetadataInfo.CvssScore != 7.5 {
		t.Fatalf("MetadataInfo mismatch: %+v", req.MetadataInfo)
	}
	if req.MetadataInfo.IncidentType != "lateral_movement" {
		t.Fatalf("IncidentType=%q", req.MetadataInfo.IncidentType)
	}
}

func TestBuildTransferIncidentReqNameFallback(t *testing.T) {
	req := buildTransferIncidentReq(domain.Event{EventID: "evt-x"}, nil)
	if req.Name != "流量分析事件 evt-x" {
		t.Fatalf("fallback Name=%q", req.Name)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd vulnscan-backend && go test ./traffic/ -run 'TestSeverityToLevel|TestBuildTransferIncidentReq' -v`
Expected: 编译失败（`buildTransferIncidentReq`/`severityToLevel` 未定义）。

- [ ] **Step 3: 实现映射**

新建 `vulnscan-backend/traffic/circular_mapping.go`：

```go
package traffic

import (
	"encoding/json"

	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
)

const circularSourceSystem = "流量分析(trafficAnalysis)"

// buildTransferIncidentReq 把流量分析事件映射为通报处置「安全事件流转」请求体。
func buildTransferIncidentReq(event domain.Event, summaries []domain.Summary) client.TransferIncidentReq {
	ctx := map[string]any{}
	if event.Context != "" {
		_ = json.Unmarshal([]byte(event.Context), &ctx)
	}

	source, destination := observablePair(event.Observables)
	source = firstNonEmpty(source, stringValue(ctx["threat_source"]), stringValue(ctx["src_ip"]))
	destination = firstNonEmpty(destination, stringValue(ctx["victim_target"]), stringValue(ctx["dst_ip"]))

	name := firstNonEmpty(event.Title, event.EventName)
	if name == "" {
		name = "流量分析事件 " + event.EventID
	}

	aiOpinion := ""
	if len(summaries) > 0 {
		aiOpinion = summaries[len(summaries)-1].EventSummary
	}
	if aiOpinion == "" {
		aiOpinion = event.Message
	}

	req := client.TransferIncidentReq{
		IncidentNo:   event.EventID,
		Name:         name,
		Level:        severityToLevel(event.Severity),
		AiOpinion:    aiOpinion,
		AiConfidence: floatValue(ctx["ai_confidence"]),
		SourceSystem: circularSourceSystem,
		AssetInfo: &client.TransferAssetInfo{
			AssetName:  firstNonEmpty(destination, stringValue(ctx["victim_target"])),
			SystemName: stringValue(ctx["system_name"]),
			DomainIP:   firstNonEmpty(stringValue(ctx["dst_domain"]), destination),
			SiteIP:     destination,
			Region:     stringValue(ctx["region"]),
		},
		MetadataInfo: &client.TransferMetadataInfo{
			IncidentType:        firstNonEmpty(event.Category, stringValue(ctx["event_type"]), stringValue(ctx["type"])),
			IncidentURL:         stringValue(ctx["incident_url"]),
			IncidentDescription: firstNonEmpty(event.Message, event.Title),
			CveId:               stringValue(ctx["cve_id"]),
			CvssScore:           floatValue(ctx["cvss_score"]),
		},
	}
	return req
}

// severityToLevel 把流量事件 severity 映射到通报处置 Level：1特别重大/2重大/3较大/4一般。
func severityToLevel(severity string) int {
	switch severity {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium", "middle":
		return 3
	case "low":
		return 4
	default:
		return 4
	}
}

func floatValue(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	default:
		return 0
	}
}
```

> 复用：`observablePair`、`firstNonEmpty`、`stringValue` 已存在于 package `traffic`（分别在 `event_service.go:201`、`chat_service.go:208`、`response.go:74`），无需重复定义。

- [ ] **Step 4: 运行测试确认通过**

Run: `cd vulnscan-backend && go test ./traffic/ -run 'TestSeverityToLevel|TestBuildTransferIncidentReq' -v`
Expected: PASS（3 个用例）。

- [ ] **Step 5: 提交**

```bash
git add vulnscan-backend/traffic/circular_mapping.go vulnscan-backend/traffic/circular_mapping_test.go
git commit -m "feat(traffic): Event→TransferIncidentReq 字段映射"
```

---

### Task 4: 审核服务、接口与 CircularClient 装配

`EventService.Review` 落审核状态并在通过时推送；新增 handler + 路由；把 `CircularClient` 接入 `Services` 与 `NewTraffic`。

**Files:**
- Modify: `vulnscan-backend/traffic/internal/service/services.go:19-29`（Services 增 `Circular` 字段）
- Modify: `vulnscan-backend/traffic/traffic.go:32-56`（module Config 增字段）、`58-102`（NewTraffic 装配）、`118-180`（toInternal 映射）
- Modify: `vulnscan-backend/traffic/event_service.go`（新增 `Review` 方法）
- Modify: `vulnscan-backend/traffic/handler.go`（新增 `ReviewEvent` + `requestBaseURL` 辅助）
- Modify: `vulnscan-backend/traffic/traffic.go:237-257`（注册 review 路由）
- Test: `vulnscan-backend/traffic/event_review_service_test.go`（新建）

**Interfaces:**
- Consumes: `buildTransferIncidentReq`(Task 3)、`client.CircularClient`(Task 2)、`store.UpdateEvent` 新字段(Task 1)。
- Produces: `func (s *EventService) Review(ctx context.Context, eventID, action, comment, bearer, fallbackBase string) (map[string]any, error)`。
- Produces: `service.Services.Circular client.CircularClient`。

- [ ] **Step 1: 写失败测试**

新建 `vulnscan-backend/traffic/event_review_service_test.go`。用 httptest 充当 circular，并用 memory store 直接构造 `Services`：

```go
package traffic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func newTestEventService(t *testing.T, circularURL string) (*EventService, store.Store) {
	t.Helper()
	st := store.NewMemoryStore()
	svc := trafficservice.Services{
		Store:    st,
		Circular: client.CircularClient{HTTP: http.DefaultClient},
	}
	return NewEventService(svc), st
}

func TestReviewApprovePushesAndStoresCode(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"circular_code":"XF-1"},"msg":""}`))
	}))
	defer srv.Close()

	es, st := newTestEventService(t, srv.URL)
	_, _ = st.CreateEvent(domain.Event{EventID: "evt-1", EventStatus: "round_finished", Severity: "high", Title: "x"})

	res, err := es.Review(context.Background(), "evt-1", "approve", "ok", "Bearer tok", srv.URL)
	if err != nil {
		t.Fatalf("review approve: %v", err)
	}
	if res["circular_code"] != "XF-1" || res["review_status"] != "approved" {
		t.Fatalf("unexpected result: %+v", res)
	}
	got, _ := st.GetEvent("evt-1")
	if got.CircularCode != "XF-1" || got.ReviewStatus != "approved" {
		t.Fatalf("event not updated: %+v", got)
	}

	// 幂等：再次 approve 不应再次调用 circular
	_, err = es.Review(context.Background(), "evt-1", "approve", "", "Bearer tok", srv.URL)
	if err != nil {
		t.Fatalf("second approve: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 circular call, got %d", calls)
	}
}

func TestReviewRejectDoesNotPush(t *testing.T) {
	es, st := newTestEventService(t, "")
	_, _ = st.CreateEvent(domain.Event{EventID: "evt-2", EventStatus: "round_finished", Severity: "low"})
	res, err := es.Review(context.Background(), "evt-2", "reject", "误报", "", "")
	if err != nil {
		t.Fatalf("review reject: %v", err)
	}
	if res["review_status"] != "rejected" {
		t.Fatalf("unexpected: %+v", res)
	}
	got, _ := st.GetEvent("evt-2")
	if got.ReviewStatus != "rejected" || got.ReviewComment != "误报" {
		t.Fatalf("event not updated: %+v", got)
	}
}

func TestReviewRejectsNonFinished(t *testing.T) {
	es, st := newTestEventService(t, "")
	_, _ = st.CreateEvent(domain.Event{EventID: "evt-3", EventStatus: "processing"})
	_, err := es.Review(context.Background(), "evt-3", "approve", "", "Bearer tok", "http://x")
	if err == nil {
		t.Fatal("expected guard error for non round_finished event")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd vulnscan-backend && go test ./traffic/ -run TestReview -v`
Expected: 编译失败（`Services.Circular`、`EventService.Review` 未定义）。

- [ ] **Step 3: Services 增 Circular 字段**

`services.go`（19-29）在 `FlowShadow` 后加字段：

```go
type Services struct {
	Store      store.Store
	DeepSOC    client.DeepSOCClient
	FlowShadow client.FlowShadowClient
	Circular   client.CircularClient
	// LLM ... (保持原注释与字段)
	LLM   *client.LLMClient
	Queue mq.Queue
}
```

- [ ] **Step 4: 实现 EventService.Review**

`event_service.go` 末尾（`unixLike` 之后）新增：

```go
// Review 处理人工审核；approve 时把事件推送到通报处置并记录 circular_code。
// 仅 event_status == "round_finished" 的事件可审核。bearer/fallbackBase 透传给 CircularClient。
func (s *EventService) Review(ctx context.Context, eventID, action, comment, bearer, fallbackBase string) (map[string]any, error) {
	event, ok := s.core.Store.GetEvent(eventID)
	if !ok {
		return nil, errors.New("事件不存在")
	}
	if event.EventStatus != "round_finished" {
		return nil, errors.New("仅 AI 分析完成的事件可审核")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	switch action {
	case "reject":
		s.core.Store.UpdateEvent(eventID, map[string]any{
			"review_status":  "rejected",
			"review_comment": comment,
			"reviewed_at":    now,
		})
		return map[string]any{"review_status": "rejected"}, nil

	case "approve":
		// 幂等：已推送过则直接返回既有编号
		if event.CircularCode != "" {
			return map[string]any{"review_status": "approved", "circular_code": event.CircularCode}, nil
		}
		req := buildTransferIncidentReq(event, s.core.Store.ListSummaries(eventID))
		code, err := s.core.Circular.ReceiveIncident(ctx, req, bearer, fallbackBase)
		if err != nil {
			return nil, err
		}
		s.core.Store.UpdateEvent(eventID, map[string]any{
			"review_status":  "approved",
			"review_comment": comment,
			"reviewed_at":    now,
			"circular_code":  code,
		})
		return map[string]any{"review_status": "approved", "circular_code": code}, nil

	default:
		return nil, errors.New("无效的审核动作")
	}
}
```

（`event_service.go` 顶部已 import `errors`、`time`、`domain`，无需新增。）

- [ ] **Step 5: 运行 service 测试确认通过**

Run: `cd vulnscan-backend && go test ./traffic/ -run TestReview -v`
Expected: PASS（4 个用例）。

- [ ] **Step 6: 新增 handler 与路由**

`handler.go` 在 `EventHierarchy`（195-197）后新增：

```go
func (h *Handler) ReviewEvent(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	action := strings.ToLower(strings.TrimSpace(firstString(body, "action")))
	comment := firstString(body, "comment", "review_comment")
	bearer := c.GetHeader("Authorization")
	result, err := h.events.Review(c.Request.Context(), c.Param("eventID"), action, comment, bearer, requestBaseURL(c))
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	ok(c, result)
}

// requestBaseURL 由入站请求推导同机 base（CircularClient.BaseURL 为空时使用）。
func requestBaseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + c.Request.Host
}
```

（`handler.go` 顶部已 import `strings`、`net/http`、`gin`，无需新增。）

`traffic.go` 在 `/events` group（254 `事件层级` 行后）新增路由：

```go
				{Name: "事件层级", Path: "detail/:eventID/hierarchy", Method: "GET", Handler: m.api.EventHierarchy, Enabled: true},
				{Name: "事件审核", Path: "detail/:eventID/review", Method: "POST", Handler: m.api.ReviewEvent, Enabled: true},
```

- [ ] **Step 7: NewTraffic 装配 CircularClient + Config 透传**

`traffic.go` module `Config`（32-56）在 `DeepSOCAPIKey` 行后加：

```go
	CircularBaseURL         string `json:"circular_base_url" toml:"circular_base_url"`
```

`NewTraffic`（66-87）在 `services` 字面量里 `FlowShadow{...}` 后加：

```go
		Circular: client.CircularClient{
			BaseURL: cfg.CircularBaseURL,
			HTTP:    httpClient,
		},
```

`toInternal()`（118-180）在 `DeepSOCAPIKey` 映射块（145-147）后加：

```go
	if c.CircularBaseURL != "" {
		cfg.CircularBaseURL = c.CircularBaseURL
	}
```

- [ ] **Step 8: 运行整包测试 + 构建**

Run: `cd vulnscan-backend && go test ./traffic/... && go build ./traffic/...`
Expected: 全部 PASS，build 无错误。
（若遇 Go 工具链下载问题，参见仓库 memory「Build/toolchain notes」的 1.26 工作区办法。）

- [ ] **Step 9: 提交**

```bash
git add vulnscan-backend/traffic/internal/service/services.go vulnscan-backend/traffic/event_service.go vulnscan-backend/traffic/handler.go vulnscan-backend/traffic/traffic.go vulnscan-backend/traffic/event_review_service_test.go
git commit -m "feat(traffic): 事件审核接口与 CircularClient 装配，通过审核推送通报处置"
```

---

### Task 5: ly 兼容投影输出审核字段

前端事件列表消费 ly 投影，需带出 `review_status` / `circular_code`，并把硬编码 `proc_status` 改为真实审核态映射。

**Files:**
- Modify: `vulnscan-backend/traffic/event_service.go:126-184`（`lyCompatibleEvent`）
- Test: `vulnscan-backend/traffic/ly_projection_test.go`（新建）

**Interfaces:**
- Consumes: `domain.Event` 新字段(Task 1)。
- Produces: `lyCompatibleEvent` 返回 map 新增 key `review_status`、`circular_code`。

- [ ] **Step 1: 写失败测试**

新建 `vulnscan-backend/traffic/ly_projection_test.go`：

```go
package traffic

import (
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func TestLyCompatibleEventIncludesReviewFields(t *testing.T) {
	row := lyCompatibleEvent(domain.Event{
		EventID:      "evt-1",
		EventStatus:  "round_finished",
		ReviewStatus: "approved",
		CircularCode: "XF-1",
	})
	if row["review_status"] != "approved" {
		t.Fatalf("review_status=%v", row["review_status"])
	}
	if row["circular_code"] != "XF-1" {
		t.Fatalf("circular_code=%v", row["circular_code"])
	}
}

func TestLyCompatibleEventDefaultReviewStatus(t *testing.T) {
	row := lyCompatibleEvent(domain.Event{EventID: "evt-2", EventStatus: "processing"})
	if row["review_status"] != "" {
		t.Fatalf("expected empty review_status, got %v", row["review_status"])
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd vulnscan-backend && go test ./traffic/ -run TestLyCompatibleEvent -v`
Expected: FAIL（map 无 `review_status` key，返回 nil）。

- [ ] **Step 3: 投影补字段**

`event_service.go` 在 `lyCompatibleEvent` 返回的 map 里（`"is_final": isFinal,` 行后、闭合 `}` 前）加两个 key：

```go
		"aggregation_status": aggregationStatus,
		"is_final":           isFinal,
		// 审核状态：供事件列表展示「待审核/已通过/已驳回」与通报编号
		"review_status": event.ReviewStatus,
		"circular_code": event.CircularCode,
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd vulnscan-backend && go test ./traffic/ -run TestLyCompatibleEvent -v`
Expected: PASS（2 个用例）。

- [ ] **Step 5: 提交**

```bash
git add vulnscan-backend/traffic/event_service.go vulnscan-backend/traffic/ly_projection_test.go
git commit -m "feat(traffic): ly 投影输出 review_status/circular_code"
```

---

### Task 6: 前端事件列表审核按钮与状态列

事件列表新增「审核状态」列与「审核通过/驳回」操作；新增 API。仅前端，手工验证。

**Files:**
- Modify: `vulnscan-frontend/apps/web/src/api/ly/index.ts`（新增 `lyEventReview`）
- Modify: `vulnscan-frontend/apps/web/src/views/ly/event/list/index.vue`

**Interfaces:**
- Consumes: 后端 `POST /api/traffic/events/detail/:eventID/review`(Task 4)、行字段 `review_status`/`circular_code`(Task 5)。
- Produces: `lyEventReview({ eventId, action, comment? }): Promise<any>`。

- [ ] **Step 1: 新增 API**

`api/ly/index.ts` 在 `lyEventPushToAi`（131-133）后加：

```ts
export function lyEventReview(params: {
  eventId: number | string;
  action: 'approve' | 'reject';
  comment?: string;
}) {
  const { eventId, action, comment } = params;
  return post(
    `/events/detail/${eventId}/review`,
    { action, comment: comment ?? '' },
    '/api/traffic',
  );
}
```

> `post` 第三参 prefix 用 `/api/traffic`（review 路由在 `/events` group 下，非 `/ly`）；`createHeaders()` 已带 `Authorization: Bearer`。

- [ ] **Step 2: 列表引入 API 与审核处理**

`views/ly/event/list/index.vue` 的 import（15 行附近）改为：

```ts
import { lyEventPushToAi, lyEventReview } from '#/api/ly';
```

`<script setup>` 内（`openAiDetail` 之后）新增审核处理：

```ts
function reviewStatusMeta(row: Record<string, any>) {
  const map: Record<string, { text: string; type: string }> = {
    approved: { text: '已通过', type: 'success' },
    rejected: { text: '已驳回', type: 'error' },
    pending_review: { text: '待审核', type: 'warning' },
  };
  if (row.review_status && map[row.review_status]) return map[row.review_status];
  // round_finished 但未审核 → 待审核
  if (row.analysisStatus === 'completed') return map.pending_review;
  return { text: '—', type: 'default' };
}

async function reviewEvent(row: Record<string, any>, action: 'approve' | 'reject') {
  const eventId = String(row.event_id || row.deepsoc_event_id || row.id || '');
  if (!eventId) {
    message.error('事件尚未生成分析，无法审核');
    return;
  }
  if (row.analysisStatus !== 'completed') {
    message.error('仅 AI 分析完成的事件可审核');
    return;
  }
  try {
    const res = await lyEventReview({ eventId, action });
    row.review_status = res?.review_status || (action === 'approve' ? 'approved' : 'rejected');
    if (res?.circular_code) row.circular_code = res.circular_code;
    message.success(action === 'approve' ? `已推送通报处置${res?.circular_code ? '：' + res.circular_code : ''}` : '已驳回');
  } catch (error) {
    message.error(error instanceof Error ? error.message : '审核失败');
  }
}
```

- [ ] **Step 3: 新增「审核状态」列并扩展操作列**

`columns` 数组里，在「分析状态」列后插入审核状态列：

```ts
  {
    title: '审核状态',
    key: 'review_status',
    width: 140,
    render: (row: Record<string, any>) => {
      const meta = reviewStatusMeta(row);
      const tags = [h(NTag, { size: 'small', type: meta.type as any }, { default: () => meta.text })];
      if (row.circular_code) {
        tags.push(h(NTag, { size: 'small', type: 'info', style: 'margin-left:4px' }, { default: () => row.circular_code }));
      }
      return h('div', { style: 'display:flex;flex-wrap:wrap;gap:4px' }, tags);
    },
  },
```

把「操作」列（218-227）的 render 改为「查看报告 + 审核通过 + 驳回」，仅 `analysisStatus==='completed'` 且未通过时可审核：

```ts
  {
    title: '操作',
    key: 'actions',
    width: 220,
    render: (row: Record<string, any>) => {
      const canReview = row.analysisStatus === 'completed';
      const reviewed = row.review_status === 'approved';
      return h(NSpace, { size: 4 }, {
        default: () => [
          h(NButton, {
            text: true, type: 'success',
            loading: state.analyzingIds.has(String(row.id)),
            onClick: () => openAiDetail(row),
          }, { default: () => '查看报告' }),
          h(NButton, {
            text: true, type: 'primary', disabled: !canReview || reviewed,
            onClick: () => reviewEvent(row, 'approve'),
          }, { default: () => '审核通过' }),
          h(NButton, {
            text: true, type: 'error', disabled: !canReview || reviewed,
            onClick: () => reviewEvent(row, 'reject'),
          }, { default: () => '驳回' }),
        ],
      });
    },
  },
```

（`NSpace` 已在文件顶部 import。）

- [ ] **Step 4: 前端校验（lint/typecheck）**

Run: `cd vulnscan-frontend && pnpm --filter @vben/web run typecheck`
Expected: 无新增类型错误（若该脚本不存在，改用 `pnpm -C apps/web run build` 做产物构建校验；参见 memory「Build/toolchain notes」前端产物构建前置条件）。

- [ ] **Step 5: 手工验证**

启动平台，进入 流量分析 → 事件列表：
1. 一条 AI 分析完成（分析状态=已生成）的事件，审核状态显示「待审核」，「审核通过/驳回」可点。
2. 点「审核通过」→ 成功提示带通报编号；审核状态变「已通过」并显示编号；通报处置模块出现对应通报。
3. 另一条点「驳回」→ 审核状态变「已驳回」，通报处置不出现该事件。
4. 未分析完成的事件审核按钮禁用。

- [ ] **Step 6: 提交**

```bash
git add vulnscan-frontend/apps/web/src/api/ly/index.ts vulnscan-frontend/apps/web/src/views/ly/event/list/index.vue
git commit -m "feat(traffic-frontend): 事件列表新增审核状态列与审核通过/驳回操作"
```

---

## Self-Review

**1. Spec coverage:**
- 数据模型变更（spec §3）→ Task 1。✓
- 审核状态流转 + 幂等（spec §4）→ Task 4（含幂等用例）。✓
- 字段对齐（spec §5）→ Task 3。✓
- HTTP 接口（spec §6）→ Task 4（route + handler）；返回体带 review_status/circular_code → Task 5（ly 投影）+ `domain.Event` json（Task 1）。✓
- CircularClient + 透传 bearer + base 回退（spec §7）→ Task 2（client）+ Task 4（handler 计算 fallbackBase、透传 Authorization）。✓
- 前端（spec §8）→ Task 6。✓
- 测试（spec §9）→ 各 Task 含 store/client/mapping/service/projection 单测；前端手工。✓
- YAGNI（spec §10：不碰 circular/di/scanrunner/model）→ 所有改动限定在 `traffic/**` 与 `vulnscan-frontend/.../ly`。✓

**2. Placeholder scan:** 无 TBD/TODO；每个代码步骤含完整代码。✓

**3. Type consistency:**
- `buildTransferIncidentReq(event, summaries) client.TransferIncidentReq` — Task 3 定义、Task 4 调用，签名一致。✓
- `CircularClient.ReceiveIncident(ctx, req, bearer, fallbackBase) (string, error)` — Task 2 定义、Task 4 调用，一致。✓
- `EventService.Review(ctx, eventID, action, comment, bearer, fallbackBase)` — Task 4 定义、handler 调用，一致。✓
- `Services.Circular client.CircularClient` — Task 4 Step 3 定义、NewTraffic（Step 7）与测试（Step 1）使用，一致。✓
- patch key（`review_status`/`review_comment`/`reviewed_by`/`reviewed_at`/`circular_code`）— Task 1 store 支持、Task 4 service 使用，一致。✓
