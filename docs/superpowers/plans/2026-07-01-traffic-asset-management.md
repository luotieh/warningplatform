# 流量分析侧资产管理 + 关联筛选 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在流量分析侧新增精简资产管理（IP + 域名网站资产，含导入），并与事件的威胁来源/受害目标做关联筛选（事件列表按资产筛选 + 资产页关联事件数与跳转）。

**Architecture:** 纯 traffic 侧 + 前端流量分析页。后端加 `traffic_assets` 表与 `store.Store` 资产 CRUD（memory+postgres）、`AssetService`（校验/归一化/导入解析）、`/api/traffic/assets` 路由；前端加 `/ly/assets` 资产页、`utils/ly-asset.ts` 客户端匹配、事件列表资产筛选。

**Tech Stack:** Go（database/sql、encoding/csv、github.com/xuri/excelize/v2）、Vue3 + naive-ui（vben admin）。

## Global Constraints

- **仅修改流量分析侧**：`vulnscan-backend/traffic/**` 与前端 `vulnscan-frontend/apps/web/src/{views/ly,api/ly,utils,router/routes/modules}`。**不碰** 平台 `asset/`、`assetmgr/`、`model/`、`di/`、`circular/`、`scanrunner/`。
- 分支：`trafficanalysis`。
- 资产类型枚举：`ip` / `domain_site`；中文别名 `IP资产→ip`、`域名网站→domain_site`。
- `address` 归一化：`strings.ToLower(strings.TrimSpace(...))`；唯一。
- 匹配 = 精确相等（归一化后），比对 `event.attackDevice` / `event.victimDevice`，任一命中即关联。
- 导入支持 `.csv`（encoding/csv）与 `.xlsx`（excelize v2，已在 go.mod）。
- Go module 根：`vulnscan-backend`；测试用工具链 workaround：`GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto`。
- 前端 typecheck：`pnpm --filter @vben/web-template run typecheck`。

---

### Task 1: 资产数据层（domain + schema + store CRUD）

`domain.Asset` + `traffic_assets` 表 + `store.Store` 资产方法（memory + postgres）。

**Files:**
- Modify: `vulnscan-backend/traffic/internal/domain/models.go`（新增 `Asset`）
- Modify: `vulnscan-backend/traffic/internal/store/store.go`（接口加 5 方法）
- Modify: `vulnscan-backend/traffic/internal/store/schema.go`（建表）
- Modify: `vulnscan-backend/traffic/internal/store/common.go`（加 `intPatch`）
- Modify: `vulnscan-backend/traffic/internal/store/memory.go`（实现 + 结构字段）
- Modify: `vulnscan-backend/traffic/internal/store/postgres.go`（实现）
- Test: `vulnscan-backend/traffic/internal/store/asset_test.go`（新建）

**Interfaces:**
- Produces: `domain.Asset{ID,Name,AssetType,Address,Unit,Owner,Status int,Remark,CreatedAt,UpdatedAt}`。
- Produces（`store.Store` 新增）：
  - `CreateAsset(a domain.Asset) (domain.Asset, error)` — Address 重复返回 error；空 ID 用 `newID("asset")`；Status 默认 1。
  - `ListAssets() []domain.Asset`（按 CreatedAt 倒序）
  - `GetAsset(id string) (domain.Asset, bool)`
  - `UpdateAsset(id string, patch map[string]any) (domain.Asset, bool)` — patch key：`name`/`asset_type`/`address`/`unit`/`owner`/`remark`(string)、`status`(int)。
  - `DeleteAsset(id string) bool`

- [ ] **Step 1: 写失败测试**

新建 `vulnscan-backend/traffic/internal/store/asset_test.go`：

```go
package store

import (
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func TestMemoryAssetCRUD(t *testing.T) {
	s := NewMemoryStore()
	a, err := s.CreateAsset(domain.Asset{Name: "web-1", AssetType: "ip", Address: "10.0.0.9"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.ID == "" || a.Status != 1 {
		t.Fatalf("defaults not applied: %+v", a)
	}
	// 重复 address 冲突
	if _, err := s.CreateAsset(domain.Asset{Name: "web-dup", AssetType: "ip", Address: "10.0.0.9"}); err == nil {
		t.Fatal("expected duplicate address error")
	}
	// list
	if len(s.ListAssets()) != 1 {
		t.Fatalf("list want 1 got %d", len(s.ListAssets()))
	}
	// update
	up, ok := s.UpdateAsset(a.ID, map[string]any{"name": "web-2", "status": 0})
	if !ok || up.Name != "web-2" || up.Status != 0 {
		t.Fatalf("update failed: %+v ok=%v", up, ok)
	}
	// get
	got, ok := s.GetAsset(a.ID)
	if !ok || got.Name != "web-2" {
		t.Fatalf("get failed: %+v", got)
	}
	// delete
	if !s.DeleteAsset(a.ID) || len(s.ListAssets()) != 0 {
		t.Fatal("delete failed")
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cd vulnscan-backend && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go test ./traffic/internal/store/ -run TestMemoryAssetCRUD -v`
Expected: 编译失败（`Asset`/`CreateAsset` 等未定义）。

- [ ] **Step 3: domain.Asset**

`domain/models.go` 末尾新增：

```go
type Asset struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AssetType string    `json:"asset_type"`
	Address   string    `json:"address"`
	Unit      string    `json:"unit,omitempty"`
	Owner     string    `json:"owner,omitempty"`
	Status    int       `json:"status"`
	Remark    string    `json:"remark,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
```

- [ ] **Step 4: store 接口 + intPatch + 别名**

`store/store.go` 接口内（`UpdateEvent` 行后）加：

```go
	CreateAsset(a domain.Asset) (domain.Asset, error)
	GetAsset(id string) (domain.Asset, bool)
	ListAssets() []domain.Asset
	UpdateAsset(id string, patch map[string]any) (domain.Asset, bool)
	DeleteAsset(id string) bool
```

`store/common.go` 加 `intPatch` 与测试别名：

```go
func intPatch(p map[string]any, key string) (int, bool) {
	v, ok := p[key]
	if !ok || v == nil {
		return 0, false
	}
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		return int(x), true
	default:
		return 0, false
	}
}
```

（`intPatch` 只用标准类型，`common.go` 无需新增 import。）

- [ ] **Step 5: schema 建表**

`store/schema.go` 的 `PostgresSchema` 常量内（events 表之后）追加：

```sql
CREATE TABLE IF NOT EXISTS traffic_assets (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(256) NOT NULL DEFAULT '',
    asset_type VARCHAR(32) NOT NULL DEFAULT 'ip',
    address VARCHAR(256) UNIQUE NOT NULL,
    unit VARCHAR(128) NOT NULL DEFAULT '',
    owner VARCHAR(128) NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 1,
    remark TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

- [ ] **Step 6: memory 实现**

`store/memory.go`：结构体 `MemoryStore` 加字段（在 `audits` 附近）：

```go
	assets map[string]domain.Asset
```

`NewMemoryStore()` 的字面量里加初始化：

```go
		assets:           map[string]domain.Asset{},
```

文件内新增方法：

```go
func (s *MemoryStore) CreateAsset(a domain.Asset) (domain.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.ID == "" {
		a.ID = newID("asset")
	}
	if a.Status == 0 {
		a.Status = 1
	}
	for _, ex := range s.assets {
		if ex.Address == a.Address {
			return domain.Asset{}, errors.New("asset address already exists")
		}
	}
	now := time.Now().UTC()
	a.CreatedAt = now
	a.UpdatedAt = now
	s.assets[a.ID] = a
	return a, nil
}

func (s *MemoryStore) GetAsset(id string) (domain.Asset, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	return a, ok
}

func (s *MemoryStore) ListAssets() []domain.Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Asset, 0, len(s.assets))
	for _, a := range s.assets {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *MemoryStore) UpdateAsset(id string, patch map[string]any) (domain.Asset, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assets[id]
	if !ok {
		return domain.Asset{}, false
	}
	if v, ok := stringPatch(patch, "name"); ok {
		a.Name = v
	}
	if v, ok := stringPatch(patch, "asset_type"); ok {
		a.AssetType = v
	}
	if v, ok := stringPatch(patch, "address"); ok {
		a.Address = v
	}
	if v, ok := stringPatch(patch, "unit"); ok {
		a.Unit = v
	}
	if v, ok := stringPatch(patch, "owner"); ok {
		a.Owner = v
	}
	if v, ok := stringPatch(patch, "remark"); ok {
		a.Remark = v
	}
	if v, ok := intPatch(patch, "status"); ok {
		a.Status = v
	}
	a.UpdatedAt = time.Now().UTC()
	s.assets[id] = a
	return a, true
}

func (s *MemoryStore) DeleteAsset(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.assets[id]; !ok {
		return false
	}
	delete(s.assets, id)
	return true
}
```

- [ ] **Step 7: postgres 实现**

`store/postgres.go` 文件末尾新增：

```go
func (s *PostgresStore) CreateAsset(a domain.Asset) (domain.Asset, error) {
	if a.ID == "" {
		a.ID = newID("asset")
	}
	if a.Status == 0 {
		a.Status = 1
	}
	now := time.Now().UTC()
	a.CreatedAt = now
	a.UpdatedAt = now
	_, err := s.db.ExecContext(context.Background(), `
INSERT INTO traffic_assets (id, name, asset_type, address, unit, owner, status, remark, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		a.ID, a.Name, a.AssetType, a.Address, a.Unit, a.Owner, a.Status, a.Remark, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		return domain.Asset{}, err
	}
	return a, nil
}

func scanAsset(row scanner) (domain.Asset, error) {
	var a domain.Asset
	err := row.Scan(&a.ID, &a.Name, &a.AssetType, &a.Address, &a.Unit, &a.Owner, &a.Status, &a.Remark, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}

func (s *PostgresStore) GetAsset(id string) (domain.Asset, bool) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT id, name, asset_type, address, unit, owner, status, remark, created_at, updated_at
FROM traffic_assets WHERE id=$1`, id)
	a, err := scanAsset(row)
	return a, err == nil
}

func (s *PostgresStore) ListAssets() []domain.Asset {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, name, asset_type, address, unit, owner, status, remark, created_at, updated_at
FROM traffic_assets ORDER BY created_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []domain.Asset{}
	for rows.Next() {
		if a, err := scanAsset(rows); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func (s *PostgresStore) UpdateAsset(id string, patch map[string]any) (domain.Asset, bool) {
	a, ok := s.GetAsset(id)
	if !ok {
		return domain.Asset{}, false
	}
	if v, ok := stringPatch(patch, "name"); ok {
		a.Name = v
	}
	if v, ok := stringPatch(patch, "asset_type"); ok {
		a.AssetType = v
	}
	if v, ok := stringPatch(patch, "address"); ok {
		a.Address = v
	}
	if v, ok := stringPatch(patch, "unit"); ok {
		a.Unit = v
	}
	if v, ok := stringPatch(patch, "owner"); ok {
		a.Owner = v
	}
	if v, ok := stringPatch(patch, "remark"); ok {
		a.Remark = v
	}
	if v, ok := intPatch(patch, "status"); ok {
		a.Status = v
	}
	a.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(context.Background(), `
UPDATE traffic_assets SET name=$2, asset_type=$3, address=$4, unit=$5, owner=$6, status=$7, remark=$8, updated_at=$9
WHERE id=$1`,
		id, a.Name, a.AssetType, a.Address, a.Unit, a.Owner, a.Status, a.Remark, a.UpdatedAt)
	if err != nil {
		return domain.Asset{}, false
	}
	return a, true
}

func (s *PostgresStore) DeleteAsset(id string) bool {
	res, err := s.db.ExecContext(context.Background(), `DELETE FROM traffic_assets WHERE id=$1`, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}
```

> `scanner` 接口已存在于 postgres.go（`scanEvent` 使用）。`context`/`time` 已 import。

- [ ] **Step 8: 运行确认通过 + 全包编译**

Run: `cd vulnscan-backend && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go test ./traffic/internal/store/ -run TestMemoryAssetCRUD -v && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go build ./traffic/...`
Expected: PASS + build 无错误。

- [ ] **Step 9: 提交**

```bash
git add vulnscan-backend/traffic/internal/domain/models.go vulnscan-backend/traffic/internal/store/
git commit -m "feat(traffic): 资产数据层 domain.Asset + traffic_assets 表 + store CRUD"
```

---

### Task 2: AssetService（校验/归一化/CRUD/导入解析）+ 装配

业务层：地址归一化、类型校验、CRUD 包装、导入解析（csv/xlsx）。装配进 Services/NewTraffic。

**Files:**
- Create: `vulnscan-backend/traffic/asset_service.go`
- Modify: `vulnscan-backend/traffic/internal/service/services.go`（Services 加 Store 已有；AssetService 直接用 store，见下）
- Modify: `vulnscan-backend/traffic/traffic.go`（NewTraffic 装配 AssetService 进 Handler）
- Test: `vulnscan-backend/traffic/asset_service_test.go`（新建）

**Interfaces:**
- Consumes: `store.Store`（Task 1 方法）。
- Produces（package `traffic`）:
  - `type AssetService struct{ store store.Store }` + `func NewAssetService(st store.Store) *AssetService`。
  - `func (s *AssetService) List() []domain.Asset`
  - `func (s *AssetService) Create(in domain.Asset) (domain.Asset, error)`（归一化+校验）
  - `func (s *AssetService) Update(id string, patch map[string]any) (domain.Asset, bool, error)`（校验后 patch）
  - `func (s *AssetService) Delete(id string) bool`
  - `func (s *AssetService) Import(filename string, data []byte) (imported int, errs []AssetImportError)`
  - `type AssetImportError struct{ Row int `json:"row"`; Message string `json:"message"` }`
  - `func normalizeAssetType(raw string) string` / `func normalizeAddr(raw string) string` / `func validateAsset(a domain.Asset) error`

- [ ] **Step 1: 写失败测试**

新建 `vulnscan-backend/traffic/asset_service_test.go`：

```go
package traffic

import (
	"testing"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestAssetServiceCreateValidatesAndNormalizes(t *testing.T) {
	svc := NewAssetService(store.NewMemoryStore())
	a, err := svc.Create(domain.Asset{Name: "web", AssetType: "IP资产", Address: "  10.0.0.9 "})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.AssetType != "ip" {
		t.Fatalf("type alias not normalized: %q", a.AssetType)
	}
	if a.Address != "10.0.0.9" {
		t.Fatalf("address not normalized: %q", a.Address)
	}
	// 缺 name
	if _, err := svc.Create(domain.Asset{AssetType: "ip", Address: "1.1.1.1"}); err == nil {
		t.Fatal("expected name required error")
	}
	// 非法 ip
	if _, err := svc.Create(domain.Asset{Name: "x", AssetType: "ip", Address: "not-an-ip"}); err == nil {
		t.Fatal("expected invalid ip error")
	}
}

func TestAssetServiceImportCSV(t *testing.T) {
	svc := NewAssetService(store.NewMemoryStore())
	csv := "资产名称,资产类型,地址,所属单位,责任人,备注\n" +
		"网站A,域名网站,example.com,单位甲,张三,备注1\n" +
		"主机B,IP资产,10.0.0.5,单位乙,李四,\n" +
		",IP资产,1.2.3.4,,,\n" // 第3行缺名称 → 错误
	imported, errs := svc.Import("assets.csv", []byte(csv))
	if imported != 2 {
		t.Fatalf("imported=%d want 2", imported)
	}
	if len(errs) != 1 || errs[0].Row != 4 {
		t.Fatalf("expected 1 error at row 4, got %+v", errs)
	}
	if len(svc.List()) != 2 {
		t.Fatalf("list want 2 got %d", len(svc.List()))
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cd vulnscan-backend && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go test ./traffic/ -run TestAssetService -v`
Expected: 编译失败（`NewAssetService` 未定义）。

- [ ] **Step 3: 实现 asset_service.go**

新建 `vulnscan-backend/traffic/asset_service.go`：

```go
package traffic

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/xuri/excelize/v2"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

type AssetService struct {
	store store.Store
}

func NewAssetService(st store.Store) *AssetService {
	return &AssetService{store: st}
}

type AssetImportError struct {
	Row     int    `json:"row"`
	Message string `json:"message"`
}

func (s *AssetService) List() []domain.Asset { return s.store.ListAssets() }

func (s *AssetService) Create(in domain.Asset) (domain.Asset, error) {
	in.AssetType = normalizeAssetType(in.AssetType)
	in.Address = normalizeAddr(in.Address)
	in.Name = strings.TrimSpace(in.Name)
	if err := validateAsset(in); err != nil {
		return domain.Asset{}, err
	}
	return s.store.CreateAsset(in)
}

func (s *AssetService) Update(id string, patch map[string]any) (domain.Asset, bool, error) {
	if v, ok := patch["asset_type"]; ok {
		patch["asset_type"] = normalizeAssetType(fmt.Sprint(v))
	}
	if v, ok := patch["address"]; ok {
		patch["address"] = normalizeAddr(fmt.Sprint(v))
	}
	// 组装校验用快照
	cur, ok := s.store.GetAsset(id)
	if !ok {
		return domain.Asset{}, false, nil
	}
	merged := cur
	if v, ok := patch["name"]; ok {
		merged.Name = strings.TrimSpace(fmt.Sprint(v))
		patch["name"] = merged.Name
	}
	if v, ok := patch["asset_type"]; ok {
		merged.AssetType = fmt.Sprint(v)
	}
	if v, ok := patch["address"]; ok {
		merged.Address = fmt.Sprint(v)
	}
	if err := validateAsset(merged); err != nil {
		return domain.Asset{}, false, err
	}
	updated, ok := s.store.UpdateAsset(id, patch)
	return updated, ok, nil
}

func (s *AssetService) Delete(id string) bool { return s.store.DeleteAsset(id) }

func normalizeAssetType(raw string) string {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "ip", "ip资产":
		return "ip"
	case "domain_site", "域名网站", "domain", "website", "site":
		return "domain_site"
	}
	// 中文别名大小写无关比较
	switch strings.TrimSpace(raw) {
	case "IP资产":
		return "ip"
	case "域名网站":
		return "domain_site"
	}
	return strings.TrimSpace(strings.ToLower(raw))
}

func normalizeAddr(raw string) string {
	v := strings.TrimSpace(strings.ToLower(raw))
	// 去掉 URL scheme 与路径，只留主机（域名资产友好）
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

func validateAsset(a domain.Asset) error {
	if a.Name == "" {
		return errors.New("资产名称不能为空")
	}
	if a.Address == "" {
		return errors.New("地址不能为空")
	}
	switch a.AssetType {
	case "ip":
		if net.ParseIP(a.Address) == nil {
			return errors.New("IP 地址格式非法")
		}
	case "domain_site":
		if !strings.Contains(a.Address, ".") || strings.ContainsAny(a.Address, " ") {
			return errors.New("域名格式非法")
		}
	default:
		return errors.New("资产类型必须为 ip 或 domain_site")
	}
	return nil
}

var assetImportHeaders = []string{"资产名称", "资产类型", "地址", "所属单位", "责任人", "备注"}

// Import 解析 csv/xlsx 并逐行导入；返回成功数与逐行错误（行号从 1 起、含表头行）。
func (s *AssetService) Import(filename string, data []byte) (int, []AssetImportError) {
	rows, err := parseAssetRows(filename, data)
	if err != nil {
		return 0, []AssetImportError{{Row: 0, Message: err.Error()}}
	}
	imported := 0
	errs := []AssetImportError{}
	for i, r := range rows {
		rowNum := i + 2 // +1 表头 +1 从1计
		if len(r) == 0 || strings.TrimSpace(strings.Join(r, "")) == "" {
			continue
		}
		a := domain.Asset{
			Name:      field(r, 0),
			AssetType: field(r, 1),
			Address:   field(r, 2),
			Unit:      field(r, 3),
			Owner:     field(r, 4),
			Remark:    field(r, 5),
		}
		if _, err := s.Create(a); err != nil {
			errs = append(errs, AssetImportError{Row: rowNum, Message: err.Error()})
			continue
		}
		imported++
	}
	return imported, errs
}

func field(r []string, i int) string {
	if i < len(r) {
		return strings.TrimSpace(r[i])
	}
	return ""
}

// parseAssetRows 返回不含表头的数据行。
func parseAssetRows(filename string, data []byte) ([][]string, error) {
	lower := strings.ToLower(strings.TrimSpace(filename))
	if strings.HasSuffix(lower, ".xlsx") {
		f, err := excelize.OpenReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("解析 xlsx 失败: %w", err)
		}
		defer f.Close()
		sheets := f.GetSheetList()
		if len(sheets) == 0 {
			return nil, errors.New("xlsx 无工作表")
		}
		all, err := f.GetRows(sheets[0])
		if err != nil {
			return nil, err
		}
		if len(all) <= 1 {
			return [][]string{}, nil
		}
		return all[1:], nil
	}
	// 默认按 CSV
	rd := csv.NewReader(bytes.NewReader(data))
	rd.FieldsPerRecord = -1
	all, err := rd.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("解析 csv 失败: %w", err)
	}
	if len(all) <= 1 {
		return [][]string{}, nil
	}
	return all[1:], nil
}

// AssetImportTemplateCSV 返回导入模板 CSV 字节（带表头与一行示例）。
func AssetImportTemplateCSV() []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write(assetImportHeaders)
	_ = w.Write([]string{"示例网站", "域名网站", "example.com", "单位甲", "张三", "关注资产"})
	_ = w.Write([]string{"示例主机", "IP资产", "10.0.0.9", "单位乙", "李四", ""})
	w.Flush()
	return b.Bytes()
}
```

- [ ] **Step 4: 装配进 Handler / NewTraffic**

`traffic/handler.go` 的 `Handler` 结构体加字段 `assets *AssetService`，构造函数 `NewHandler` 增加参数并赋值。当前签名：

```go
func NewHandler(events *EventService, account *AccountService, chat *ChatService, system *SystemService, inner *InternalService, ly *lyserver.Service, socket *socketio.Hub) *Handler {
	return &Handler{events: events, account: account, chat: chat, system: system, inner: inner, ly: ly, socket: socket}
}
```

改为（加 `assets`）：

```go
type Handler struct {
	events  *EventService
	assets  *AssetService
	account *AccountService
	chat    *ChatService
	system  *SystemService
	inner   *InternalService
	ly      *lyserver.Service
	socket  *socketio.Hub
}

func NewHandler(events *EventService, assets *AssetService, account *AccountService, chat *ChatService, system *SystemService, inner *InternalService, ly *lyserver.Service, socket *socketio.Hub) *Handler {
	return &Handler{events: events, assets: assets, account: account, chat: chat, system: system, inner: inner, ly: ly, socket: socket}
}
```

`traffic/traffic.go` 的 `NewTraffic` 中 `NewHandler(` 调用处，第 2 实参加入 `NewAssetService(st)`（`st` 是已 `loadStore(cfg)` 得到的 store）：

```go
		api: NewHandler(
			NewEventService(services),
			NewAssetService(st),
			NewAccountService(services),
			NewChatService(services),
			NewSystemService(cfg, services),
			NewInternalService(cfg, services),
			lyserver.New(cfg.DatabaseURL),
			socketHub,
		),
```

- [ ] **Step 5: 运行 service 测试 + 全包编译**

Run: `cd vulnscan-backend && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go test ./traffic/ -run TestAssetService -v && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go build ./traffic/...`
Expected: PASS（2 用例）+ build 无错误。

- [ ] **Step 6: 提交**

```bash
git add vulnscan-backend/traffic/asset_service.go vulnscan-backend/traffic/asset_service_test.go vulnscan-backend/traffic/handler.go vulnscan-backend/traffic/traffic.go
git commit -m "feat(traffic): AssetService 校验/归一化/CRUD/导入解析 + 装配"
```

---

### Task 3: 资产 HTTP 接口（/assets 组）

CRUD + 导入 + 模板下载 handler 与路由。

**Files:**
- Modify: `vulnscan-backend/traffic/handler.go`（新增 asset handlers）
- Modify: `vulnscan-backend/traffic/traffic.go`（注册 `/assets` 组）
- Test: 手工 curl（见 Step 5）

**Interfaces:**
- Consumes: `h.assets *AssetService`（Task 2）、既有 helper `readBody`/`ok`/`okMessage`/`fail`/`firstString`/`stringValue`/`intFromBody`。
- Produces: HTTP 路由 `GET/POST /api/traffic/assets*`。

- [ ] **Step 1: 新增 asset handlers**

`traffic/handler.go` 在事件相关 handler 附近新增：

```go
func (h *Handler) ListAssets(c *gin.Context) {
	keyword := strings.ToLower(strings.TrimSpace(c.Query("keyword")))
	typ := strings.TrimSpace(c.Query("type"))
	statusQ := strings.TrimSpace(c.Query("status"))
	out := []any{}
	for _, a := range h.assets.List() {
		if typ != "" && a.AssetType != typ {
			continue
		}
		if statusQ != "" && stringValue(a.Status) != statusQ {
			continue
		}
		if keyword != "" &&
			!strings.Contains(strings.ToLower(a.Name), keyword) &&
			!strings.Contains(strings.ToLower(a.Address), keyword) {
			continue
		}
		out = append(out, a)
	}
	ok(c, out)
}

func (h *Handler) CreateAsset(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	created, err := h.assets.Create(domain.Asset{
		Name:      firstString(body, "name"),
		AssetType: firstString(body, "asset_type", "type"),
		Address:   firstString(body, "address"),
		Unit:      firstString(body, "unit"),
		Owner:     firstString(body, "owner"),
		Remark:    firstString(body, "remark"),
		Status:    intFromBody(body["status"]),
	})
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	okMessage(c, "资产已创建", created)
}

func (h *Handler) UpdateAsset(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	patch := map[string]any{}
	for _, k := range []string{"name", "address", "unit", "owner", "remark"} {
		if v, ok := body[k]; ok {
			patch[k] = stringValue(v)
		}
	}
	if v, ok := body["asset_type"]; ok {
		patch["asset_type"] = stringValue(v)
	} else if v, ok := body["type"]; ok {
		patch["asset_type"] = stringValue(v)
	}
	if v, ok := body["status"]; ok {
		patch["status"] = intFromBody(v)
	}
	updated, found, err := h.assets.Update(c.Param("id"), patch)
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	if !found {
		fail(c, 404, "资产不存在")
		return
	}
	okMessage(c, "资产已更新", updated)
}

func (h *Handler) DeleteAsset(c *gin.Context) {
	if !h.assets.Delete(c.Param("id")) {
		fail(c, 404, "资产不存在")
		return
	}
	okMessage(c, "资产已删除", nil)
}

func (h *Handler) ImportAssets(c *gin.Context) {
	fh, err := c.FormFile("file")
	if err != nil {
		fail(c, 400, "文件上传失败")
		return
	}
	f, err := fh.Open()
	if err != nil {
		fail(c, 400, "文件打开失败")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		fail(c, 400, "文件读取失败")
		return
	}
	imported, errs := h.assets.Import(fh.Filename, data)
	ok(c, map[string]any{"imported": imported, "errors": errs})
}

func (h *Handler) AssetImportTemplate(c *gin.Context) {
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename=asset_import_template.csv")
	// 加 UTF-8 BOM，Excel 打开中文不乱码
	c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})
	c.Writer.Write(AssetImportTemplateCSV())
}
```

确认 `handler.go` 顶部 import 含 `"io"` 与 `"vulnscan-backend/traffic/internal/domain"`；缺则补。

- [ ] **Step 2: 注册路由**

`traffic/traffic.go` 的 `RoutesWithGroup` 内，`/events` 组 `append` 之后新增：

```go
	all = append(all, authorize.RegisterRoutes(e.Group("/assets"), []authorize.Route{
		{
			Name:    "流量资产管理",
			Enabled: true,
			Children: []authorize.Route{
				{Name: "资产列表", Path: "list", Method: "GET", Handler: m.api.ListAssets, Enabled: true},
				{Name: "创建资产", Method: "POST", Handler: m.api.CreateAsset, Enabled: true},
				{Name: "更新资产", Path: ":id", Method: "PUT", Handler: m.api.UpdateAsset, Enabled: true},
				{Name: "删除资产", Path: ":id", Method: "DELETE", Handler: m.api.DeleteAsset, Enabled: true},
				{Name: "导入资产", Path: "import", Method: "POST", Handler: m.api.ImportAssets, Enabled: true},
				{Name: "导入模板", Path: "import/template", Method: "GET", Handler: m.api.AssetImportTemplate, Enabled: true},
			},
		},
	})...)
```

- [ ] **Step 3: 编译**

Run: `cd vulnscan-backend && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go build ./traffic/...`
Expected: build 无错误。

- [ ] **Step 4: 冒烟自测（起服务）**

Run（后台起服务后）:
```bash
cd vulnscan-backend && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go build -o /tmp/traffic-smoke ./cmd/server
```
Expected: 生成二进制无错误（完整起服务由集成阶段做，本步仅确保可构建）。

- [ ] **Step 5: 提交**

```bash
git add vulnscan-backend/traffic/handler.go vulnscan-backend/traffic/traffic.go
git commit -m "feat(traffic): 资产 CRUD/导入/模板 HTTP 接口 /assets"
```

---

### Task 4: 前端资产匹配工具

`utils/ly-asset.ts`：归一化与匹配/计数（纯函数，供资产页与事件列表共用）。

**Files:**
- Create: `vulnscan-frontend/apps/web/src/utils/ly-asset.ts`
- Test: `vulnscan-frontend/apps/web/src/utils/ly-asset.test.ts`（新建，vitest）

**Interfaces:**
- Produces:
  - `normalizeAddr(v?: string): string` — trim + toLowerCase。
  - `assetMatchesEvent(asset: {address?: string}, event: {attackDevice?: string; victimDevice?: string}): boolean`
  - `countAssetEvents(asset, events): number`
  - `eventMatchesAnyAsset(event, assets: Array<{address?: string; status?: number}>): boolean` — 仅 `status===1` 参与。

- [ ] **Step 1: 写失败测试**

新建 `vulnscan-frontend/apps/web/src/utils/ly-asset.test.ts`：

```ts
import { describe, expect, it } from 'vitest';

import {
  assetMatchesEvent,
  countAssetEvents,
  eventMatchesAnyAsset,
  normalizeAddr,
} from './ly-asset';

describe('ly-asset', () => {
  it('normalizeAddr trims and lowercases', () => {
    expect(normalizeAddr('  Example.COM ')).toBe('example.com');
    expect(normalizeAddr(undefined)).toBe('');
  });

  it('assetMatchesEvent matches attacker or victim', () => {
    const asset = { address: '10.0.0.9' };
    expect(assetMatchesEvent(asset, { attackDevice: '10.0.0.9', victimDevice: 'x' })).toBe(true);
    expect(assetMatchesEvent(asset, { attackDevice: 'x', victimDevice: '10.0.0.9' })).toBe(true);
    expect(assetMatchesEvent(asset, { attackDevice: 'a', victimDevice: 'b' })).toBe(false);
  });

  it('countAssetEvents counts matches', () => {
    const events = [
      { attackDevice: '10.0.0.9', victimDevice: 'x' },
      { attackDevice: 'y', victimDevice: '10.0.0.9' },
      { attackDevice: 'a', victimDevice: 'b' },
    ];
    expect(countAssetEvents({ address: '10.0.0.9' }, events)).toBe(2);
  });

  it('eventMatchesAnyAsset only considers enabled assets', () => {
    const assets = [
      { address: '10.0.0.9', status: 0 },
      { address: '1.1.1.1', status: 1 },
    ];
    expect(eventMatchesAnyAsset({ attackDevice: '1.1.1.1' }, assets)).toBe(true);
    expect(eventMatchesAnyAsset({ attackDevice: '10.0.0.9' }, assets)).toBe(false);
  });
});
```

- [ ] **Step 2: 运行确认失败**

Run: `cd vulnscan-frontend && pnpm --filter @vben/web-template exec vitest run src/utils/ly-asset.test.ts`
Expected: FAIL（模块不存在）。若该 vitest 调用方式在本仓不可用，改用 `pnpm -C apps/web exec vitest run src/utils/ly-asset.test.ts`；两者均不可用则记录并在实现后靠 typecheck + 手工验证兜底。

- [ ] **Step 3: 实现 ly-asset.ts**

新建 `vulnscan-frontend/apps/web/src/utils/ly-asset.ts`：

```ts
export function normalizeAddr(v?: string): string {
  return String(v ?? '').trim().toLowerCase();
}

interface EventLike {
  attackDevice?: string;
  victimDevice?: string;
}
interface AssetLike {
  address?: string;
  status?: number;
}

export function assetMatchesEvent(asset: AssetLike, event: EventLike): boolean {
  const addr = normalizeAddr(asset.address);
  if (!addr) return false;
  return (
    normalizeAddr(event.attackDevice) === addr ||
    normalizeAddr(event.victimDevice) === addr
  );
}

export function countAssetEvents(asset: AssetLike, events: EventLike[]): number {
  return (events || []).reduce(
    (n, e) => (assetMatchesEvent(asset, e) ? n + 1 : n),
    0,
  );
}

export function eventMatchesAnyAsset(event: EventLike, assets: AssetLike[]): boolean {
  return (assets || []).some(
    (a) => a.status === 1 && assetMatchesEvent(a, event),
  );
}
```

- [ ] **Step 4: 运行确认通过**

Run: `cd vulnscan-frontend && pnpm --filter @vben/web-template exec vitest run src/utils/ly-asset.test.ts`
Expected: PASS（4 用例）。（若 vitest 不可用，跑 `pnpm --filter @vben/web-template run typecheck` 确认无类型错误。）

- [ ] **Step 5: 提交**

```bash
git add vulnscan-frontend/apps/web/src/utils/ly-asset.ts vulnscan-frontend/apps/web/src/utils/ly-asset.test.ts
git commit -m "feat(traffic-frontend): 资产-事件匹配工具 ly-asset"
```

---

### Task 5: 资产管理页 + API + 路由

`api/ly/assets.ts` + 路由 `/ly/assets` + 页面（表格/筛选/CRUD/导入/关联数/跳转）。

**Files:**
- Create: `vulnscan-frontend/apps/web/src/api/ly/assets.ts`
- Create: `vulnscan-frontend/apps/web/src/views/ly/assets/index.vue`
- Modify: `vulnscan-frontend/apps/web/src/router/routes/modules/traffic-analysis.ts`（加 `/ly/assets` 子路由）

**Interfaces:**
- Consumes: Task 3 后端 `/api/traffic/assets*`；Task 4 `countAssetEvents`；`store/ly` 的 `useLyStore`（`events`/`loadEvents`）。
- Produces: `lyAssetList/lyAssetCreate/lyAssetUpdate/lyAssetDelete/lyAssetImport` + `lyAssetTemplateUrl`。

- [ ] **Step 1: API 层**

新建 `vulnscan-frontend/apps/web/src/api/ly/assets.ts`：

```ts
import { preferences } from '@vben/preferences';
import { useAccessStore } from '@vben/stores';

const PREFIX = '/api/traffic/assets';

function headers(json = true) {
  const accessStore = useAccessStore();
  const h = new Headers();
  if (json) h.set('Content-Type', 'application/json');
  h.set('Accept-Language', preferences.app.locale);
  if (accessStore.accessToken) h.set('Authorization', `Bearer ${accessStore.accessToken}`);
  return h;
}

async function parse(res: Response) {
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  if (data?.code !== undefined && ![0, 200, 2000].includes(data.code)) {
    throw new Error(data.msg || data.message || '请求失败');
  }
  return data?.data !== undefined ? data.data : data;
}

export interface LyAsset extends Record<string, any> {
  id?: string;
  name: string;
  asset_type: 'domain_site' | 'ip';
  address: string;
  unit?: string;
  owner?: string;
  status?: number;
  remark?: string;
}

export function lyAssetList(params?: Record<string, any>) {
  const q = new URLSearchParams();
  Object.entries(params ?? {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') q.set(k, String(v));
  });
  const qs = q.toString();
  return fetch(`${PREFIX}/list${qs ? `?${qs}` : ''}`, { headers: headers(false) }).then(parse) as Promise<LyAsset[]>;
}

export function lyAssetCreate(data: LyAsset) {
  return fetch(PREFIX, { method: 'POST', headers: headers(), body: JSON.stringify(data) }).then(parse);
}

export function lyAssetUpdate(id: string, data: Partial<LyAsset>) {
  return fetch(`${PREFIX}/${id}`, { method: 'PUT', headers: headers(), body: JSON.stringify(data) }).then(parse);
}

export function lyAssetDelete(id: string) {
  return fetch(`${PREFIX}/${id}`, { method: 'DELETE', headers: headers() }).then(parse);
}

export function lyAssetImport(file: File) {
  const fd = new FormData();
  fd.append('file', file);
  return fetch(`${PREFIX}/import`, { method: 'POST', headers: headers(false), body: fd }).then(parse) as Promise<{
    imported: number;
    errors: Array<{ row: number; message: string }>;
  }>;
}

export function lyAssetTemplateUrl() {
  return `${PREFIX}/import/template`;
}
```

- [ ] **Step 2: 路由**

`router/routes/modules/traffic-analysis.ts` 的 `children` 数组里，在事件列表(order 20)与配置(order 30)之间加：

```ts
      {
        name: 'LyAssets',
        path: '/ly/assets',
        component: () => import('#/views/ly/assets/index.vue'),
        meta: {
          icon: 'lucide:database',
          order: 25,
          title: '资产管理',
        },
      },
```

- [ ] **Step 3: 资产页**

新建 `vulnscan-frontend/apps/web/src/views/ly/assets/index.vue`：

```vue
<script lang="ts" setup>
import { computed, h, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPagination,
  NSelect,
  NSpace,
  NTag,
  NUpload,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import {
  lyAssetCreate,
  lyAssetDelete,
  lyAssetImport,
  lyAssetList,
  lyAssetTemplateUrl,
  lyAssetUpdate,
  type LyAsset,
} from '#/api/ly/assets';
import { useLyStore } from '#/store/ly';
import { countAssetEvents } from '#/utils/ly-asset';
import { paginate } from '#/utils/ly';

defineOptions({ name: 'LyAssets' });

const router = useRouter();
const lyStore = useLyStore();

const assets = ref<LyAsset[]>([]);
const loading = ref(false);
const state = reactive({ keyword: '', type: '', status: '', page: 1, pageSize: 10 });

const typeOptions = [
  { label: 'IP资产', value: 'ip' },
  { label: '域名网站', value: 'domain_site' },
];
const statusOptions = [
  { label: '启用', value: '1' },
  { label: '停用', value: '0' },
];

const filtered = computed(() =>
  assets.value.filter((a) => {
    if (state.type && a.asset_type !== state.type) return false;
    if (state.status !== '' && String(a.status ?? 1) !== state.status) return false;
    if (state.keyword) {
      const k = state.keyword.toLowerCase();
      if (!String(a.name).toLowerCase().includes(k) && !String(a.address).toLowerCase().includes(k)) return false;
    }
    return true;
  }),
);
const paged = computed(() => paginate(filtered.value, state.page, state.pageSize));

async function load() {
  loading.value = true;
  try {
    assets.value = (await lyAssetList()) || [];
    if (!lyStore.events.length) await lyStore.loadEvents();
  } catch (error) {
    message.error(error instanceof Error ? error.message : '加载失败');
  } finally {
    loading.value = false;
  }
}

// 新增/编辑
const editVisible = ref(false);
const editing = ref(false);
const form = reactive<LyAsset>({ name: '', asset_type: 'ip', address: '', unit: '', owner: '', remark: '', status: 1 });
let editId = '';

function openCreate() {
  editing.value = false;
  editId = '';
  Object.assign(form, { name: '', asset_type: 'ip', address: '', unit: '', owner: '', remark: '', status: 1 });
  editVisible.value = true;
}
function openEdit(row: LyAsset) {
  editing.value = true;
  editId = String(row.id);
  Object.assign(form, { ...row });
  editVisible.value = true;
}
async function submit() {
  if (!form.name.trim() || !form.address.trim()) {
    message.error('资产名称与地址必填');
    return;
  }
  try {
    if (editing.value) {
      await lyAssetUpdate(editId, { ...form });
      message.success('已更新');
    } else {
      await lyAssetCreate({ ...form });
      message.success('已创建');
    }
    editVisible.value = false;
    await load();
  } catch (error) {
    message.error(error instanceof Error ? error.message : '保存失败');
  }
}
async function remove(row: LyAsset) {
  try {
    await lyAssetDelete(String(row.id));
    message.success('已删除');
    await load();
  } catch (error) {
    message.error(error instanceof Error ? error.message : '删除失败');
  }
}

// 导入
const importVisible = ref(false);
const importResult = ref<{ imported: number; errors: Array<{ row: number; message: string }> } | null>(null);
async function onUpload({ file }: { file: { file?: File | null } }) {
  if (!file.file) return;
  try {
    importResult.value = await lyAssetImport(file.file);
    message.success(`导入成功 ${importResult.value.imported} 条`);
    await load();
  } catch (error) {
    message.error(error instanceof Error ? error.message : '导入失败');
  }
}

function jumpToEvents(row: LyAsset) {
  router.push({ path: '/ly/event/list', query: { asset: row.address } });
}

const columns = [
  { title: '名称', key: 'name', minWidth: 140 },
  {
    title: '类型',
    key: 'asset_type',
    width: 110,
    render: (row: LyAsset) =>
      h(NTag, { size: 'small', type: row.asset_type === 'ip' ? 'info' : 'warning' }, { default: () => (row.asset_type === 'ip' ? 'IP资产' : '域名网站') }),
  },
  { title: '地址', key: 'address', minWidth: 160 },
  { title: '所属单位', key: 'unit', minWidth: 120 },
  { title: '责任人', key: 'owner', width: 100 },
  {
    title: '状态',
    key: 'status',
    width: 90,
    render: (row: LyAsset) =>
      h(NTag, { size: 'small', type: (row.status ?? 1) === 1 ? 'success' : 'default' }, { default: () => ((row.status ?? 1) === 1 ? '启用' : '停用') }),
  },
  {
    title: '关联事件数',
    key: 'related',
    width: 110,
    render: (row: LyAsset) => {
      const n = countAssetEvents(row, lyStore.events || []);
      return h(NButton, { text: true, type: 'primary', disabled: n === 0, onClick: () => jumpToEvents(row) }, { default: () => String(n) });
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 140,
    render: (row: LyAsset) =>
      h(NSpace, { size: 4 }, {
        default: () => [
          h(NButton, { text: true, type: 'primary', onClick: () => openEdit(row) }, { default: () => '编辑' }),
          h(NButton, { text: true, type: 'error', onClick: () => remove(row) }, { default: () => '删除' }),
        ],
      }),
  },
];

onMounted(load);
</script>

<template>
  <div class="ly-page">
    <NSpace vertical :size="12">
      <NCard size="small">
        <NSpace>
          <NInput v-model:value="state.keyword" clearable placeholder="名称或地址" style="width: 200px" />
          <NSelect v-model:value="state.type" clearable placeholder="类型" :options="typeOptions" style="width: 140px" />
          <NSelect v-model:value="state.status" clearable placeholder="状态" :options="statusOptions" style="width: 120px" />
          <NButton type="primary" @click="openCreate">新增资产</NButton>
          <NButton @click="importVisible = true">导入</NButton>
          <NButton @click="load">刷新</NButton>
        </NSpace>
      </NCard>

      <NCard size="small">
        <NDataTable :columns="columns" :data="paged" :loading="loading" size="small" :bordered="false" />
        <div class="pager-wrap">
          <NPagination v-model:page="state.page" v-model:page-size="state.pageSize" :item-count="filtered.length" show-size-picker :page-sizes="[10, 20, 50]" />
        </div>
      </NCard>
    </NSpace>

    <NModal v-model:show="editVisible" preset="card" :title="editing ? '编辑资产' : '新增资产'" style="width: 520px">
      <NForm label-placement="left" label-width="90">
        <NFormItem label="资产名称" required>
          <NInput v-model:value="form.name" placeholder="资产名称" />
        </NFormItem>
        <NFormItem label="类型" required>
          <NSelect v-model:value="form.asset_type" :options="typeOptions" />
        </NFormItem>
        <NFormItem label="地址" required>
          <NInput v-model:value="form.address" placeholder="IP 或 域名" />
        </NFormItem>
        <NFormItem label="所属单位">
          <NInput v-model:value="form.unit" />
        </NFormItem>
        <NFormItem label="责任人">
          <NInput v-model:value="form.owner" />
        </NFormItem>
        <NFormItem label="状态">
          <NSelect v-model:value="form.status" :options="[{ label: '启用', value: 1 }, { label: '停用', value: 0 }]" />
        </NFormItem>
        <NFormItem label="备注">
          <NInput v-model:value="form.remark" type="textarea" :rows="2" />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="editVisible = false">取消</NButton>
          <NButton type="primary" @click="submit">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <NModal v-model:show="importVisible" preset="card" title="导入资产" style="width: 520px">
      <NSpace vertical>
        <a :href="lyAssetTemplateUrl()" download>下载导入模板（CSV）</a>
        <NUpload :show-file-list="false" accept=".csv,.xlsx" :custom-request="() => {}" @change="onUpload">
          <NButton>选择文件并导入（.csv/.xlsx）</NButton>
        </NUpload>
        <div v-if="importResult">
          成功导入 {{ importResult.imported }} 条<span v-if="importResult.errors?.length">，失败 {{ importResult.errors.length }} 条：</span>
          <ul v-if="importResult.errors?.length">
            <li v-for="e in importResult.errors" :key="e.row">第 {{ e.row }} 行：{{ e.message }}</li>
          </ul>
        </div>
      </NSpace>
    </NModal>
  </div>
</template>

<style scoped>
.ly-page { padding: 12px; }
.pager-wrap { display: flex; justify-content: flex-end; margin-top: 12px; }
</style>
```

- [ ] **Step 4: 校验**

Run: `cd vulnscan-frontend && pnpm --filter @vben/web-template run typecheck`
Expected: `src/views/ly/` 与 `src/api/ly/` 无新增类型错误（存量无关模块错误可忽略）。

- [ ] **Step 5: 提交**

```bash
git add vulnscan-frontend/apps/web/src/api/ly/assets.ts vulnscan-frontend/apps/web/src/views/ly/assets/ vulnscan-frontend/apps/web/src/router/routes/modules/traffic-analysis.ts
git commit -m "feat(traffic-frontend): 资产管理页 + API + /ly/assets 路由"
```

---

### Task 6: 事件列表按资产筛选

事件列表加「按资产筛选」下拉 +「仅看已登记资产相关事件」开关，并支持 `?asset=` 跳入。

**Files:**
- Modify: `vulnscan-frontend/apps/web/src/views/ly/event/list/index.vue`

**Interfaces:**
- Consumes: `lyAssetList`（Task 5 API）、`assetMatchesEvent`/`eventMatchesAnyAsset`（Task 4）、`useRoute` query。

- [ ] **Step 1: 引入依赖与状态**

`views/ly/event/list/index.vue` 顶部补充 import：

```ts
import { useRoute, useRouter } from 'vue-router';
import { lyAssetList, type LyAsset } from '#/api/ly/assets';
import { assetMatchesEvent, eventMatchesAnyAsset } from '#/utils/ly-asset';
```

（`useRouter` 若已 import 则合并；新增 `useRoute`。）

`<script setup>` 内新增状态与加载：

```ts
const route = useRoute();
const assets = ref<LyAsset[]>([]);
const selectedAsset = ref<string>((route.query.asset as string) || '');
const onlyAssetRelated = ref(false);

const assetOptions = computed(() =>
  assets.value.map((a) => ({ label: `${a.name}（${a.address}）`, value: a.address })),
);

async function loadAssets() {
  try {
    assets.value = (await lyAssetList()) || [];
  } catch {
    assets.value = [];
  }
}
```

- [ ] **Step 2: 过滤逻辑接入**

把现有 `filteredRows` computed 增加资产过滤分支（在 proc_status/is_alive 之后）：

```ts
const filteredRows = computed(() => {
  return (lyStore.events || []).filter((item) => {
    if (state.proc_status && item.proc_status !== state.proc_status) return false;
    if (state.is_alive) {
      const alive = String(item.is_alive) === state.is_alive;
      if (!alive) return false;
    }
    if (selectedAsset.value) {
      if (!assetMatchesEvent({ address: selectedAsset.value }, item)) return false;
    } else if (onlyAssetRelated.value) {
      if (!eventMatchesAnyAsset(item, assets.value)) return false;
    }
    return true;
  });
});
```

- [ ] **Step 3: 筛选 UI**

在事件列表筛选卡（含 proc_status / is_alive 的 `NSpace`）里追加控件：

```vue
          <NSelect
            v-model:value="selectedAsset"
            clearable
            filterable
            placeholder="按资产筛选"
            :options="assetOptions"
            style="width: 240px"
          />
          <NCheckbox v-model:checked="onlyAssetRelated" :disabled="!!selectedAsset">
            仅看已登记资产相关事件
          </NCheckbox>
```

顶部 naive-ui import 补 `NCheckbox`（若未引入）。

- [ ] **Step 4: 挂载加载资产**

现有 `onMounted` 内追加 `void loadAssets();`：

```ts
onMounted(async () => {
  if (!lyStore.events.length) {
    await lyStore.loadEvents();
  }
  void loadAssets();
  void analyzeHistorySequentially();
});
```

- [ ] **Step 5: 校验**

Run: `cd vulnscan-frontend && pnpm --filter @vben/web-template run typecheck`
Expected: `src/views/ly/event/list/` 无新增类型错误。

- [ ] **Step 6: 手工验证**

事件列表出现「按资产筛选」下拉与开关：选资产 → 仅显示其命中威胁来源/受害目标的事件；开关开 → 仅显示命中任一启用资产的事件；从资产页点关联数跳入时 `?asset=` 预选生效。

- [ ] **Step 7: 提交**

```bash
git add vulnscan-frontend/apps/web/src/views/ly/event/list/index.vue
git commit -m "feat(traffic-frontend): 事件列表按资产关联筛选"
```

---

## Self-Review

**1. Spec coverage:**
- §3.1/§3.2 domain.Asset + 表 → Task 1。✓
- §3.3 store 方法（memory+postgres）→ Task 1。✓
- §3.4 AssetService + Handler + 路由 + 装配 → Task 2（service+装配）、Task 3（handler+路由）。✓
- §3.5 导入列/别名/校验 → Task 2（Import + normalizeAssetType + 模板）、Task 3（multipart handler + 模板下载）。✓
- §4 关联匹配工具 → Task 4。✓
- §5.1 路由/菜单 → Task 5 Step 2。✓
- §5.2 资产页（表格/筛选/CRUD/导入/关联数/跳转）→ Task 5 Step 3。✓
- §5.3 API → Task 5 Step 1。✓
- §5.4 事件列表集成（下拉/开关/?asset=）→ Task 6。✓
- §6 测试 → Task 1（store）、Task 2（service+import）、Task 4（util vitest）；页面/集成手工。✓
- §7 YAGNI（不碰平台 asset/model/di；不做分组/网段/后端关联表/导出等）→ 计划未涉及。✓

**2. Placeholder scan:** 无 TBD/TODO；每个代码步骤含完整代码。Task 1 Step 1 的 `Asset0`/别名写法给了明确二选一说明，非占位。✓

**3. Type consistency:**
- `domain.Asset` 字段（Name/AssetType/Address/Unit/Owner/Status/Remark）— Task 1 定义，Task 2 service、Task 3 handler、Task 5 前端 `LyAsset`（asset_type/address/...）键名一致（后端 json tag `asset_type`/`address` ↔ 前端同名）。✓
- store 方法签名（CreateAsset/ListAssets/GetAsset/UpdateAsset/DeleteAsset）— Task 1 定义、Task 2 消费，一致。✓
- `AssetService` 方法（List/Create/Update/Delete/Import）+ `AssetImportError{Row,Message}` + `AssetImportTemplateCSV` — Task 2 定义、Task 3 调用，一致。✓
- `NewHandler` 新签名（events, assets, account, ...）— Task 2 Step 4 定义并同步改 `NewTraffic` 调用，一致。✓
- 前端工具 `assetMatchesEvent/countAssetEvents/eventMatchesAnyAsset/normalizeAddr` — Task 4 定义、Task 5/6 消费，一致。✓
- API `lyAssetList/Create/Update/Delete/Import/TemplateUrl` + `LyAsset` — Task 5 定义、Task 6 消费 `lyAssetList`/`LyAsset`，一致。✓
- 跳转参数 `?asset=<address>` — Task 5 jumpToEvents 写入、Task 6 读取，一致。✓
