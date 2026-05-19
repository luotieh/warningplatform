package asset

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	assetContract "vulnscan-backend/asset/asset-contract"
	"vulnscan-backend/model"
	"vulnscan-backend/pkg/assethost"
	"vulnscan-backend/scanrunner"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type EnrichHandler struct {
	database      *db.DB
	scanDB        *gorm.DB
	scanScheduler *scanrunner.Scheduler
}

func NewEnrichHandler(database *db.DB) *EnrichHandler {
	return &EnrichHandler{database: database}
}

// BindScanRunner 由 DI 在扫描调度器就绪后注入，用于信息富化走漏扫引擎。
func (h *EnrichHandler) BindScanRunner(session *gorm.DB, sched *scanrunner.Scheduler) {
	h.scanDB = session
	h.scanScheduler = sched
}

func (h *EnrichHandler) session() *gorm.DB {
	sess, _ := h.database.GetDBSession()
	return sess
}

// ── 资产详情：端口 / 服务（从扫描发现聚合，兼容 SQLite 与 JSON 字段）──

func scanFindingDataString(data model.JSONMap, key string) string {
	if data == nil {
		return ""
	}
	v, ok := data[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
}

func scanFindingDataInt(data model.JSONMap, key string) int {
	s := scanFindingDataString(data, key)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func portFindingsToPortInfo(rows []model.ScanFinding) []portInfo {
	out := make([]portInfo, 0, len(rows))
	seen := make(map[string]struct{})
	for _, f := range rows {
		port := f.Port
		if port == 0 {
			port = scanFindingDataInt(f.Data, "port")
		}
		proto := strings.TrimSpace(f.Protocol)
		if proto == "" {
			proto = scanFindingDataString(f.Data, "protocol")
		}
		svc := scanFindingDataString(f.Data, "service")
		ver := scanFindingDataString(f.Data, "version")
		key := fmt.Sprintf("%d|%s|%s|%s", port, proto, svc, ver)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, portInfo{
			Port:     port,
			Protocol: proto,
			Service:  svc,
			Version:  ver,
		})
	}
	return out
}

type serviceAggKey struct {
	ServiceName string
	Version     string
	Port        string
	Protocol    string
}

func serviceFindingsToServiceInfo(rows []model.ScanFinding) []serviceInfo {
	counts := make(map[serviceAggKey]int)
	for _, f := range rows {
		svc := scanFindingDataString(f.Data, "service")
		if svc == "" {
			svc = strings.TrimSpace(f.Title)
		}
		ver := scanFindingDataString(f.Data, "version")
		portStr := scanFindingDataString(f.Data, "port")
		if portStr == "" || portStr == "0" {
			if f.Port > 0 {
				portStr = strconv.Itoa(f.Port)
			} else {
				portStr = "0"
			}
		}
		proto := strings.TrimSpace(f.Protocol)
		if proto == "" {
			proto = scanFindingDataString(f.Data, "protocol")
		}
		k := serviceAggKey{svc, ver, portStr, proto}
		counts[k]++
	}
	out := make([]serviceInfo, 0, len(counts))
	for k, n := range counts {
		out = append(out, serviceInfo{
			ServiceName: k.ServiceName,
			Version:     k.Version,
			Port:        k.Port,
			Protocol:    k.Protocol,
			Count:       n,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		pi, _ := strconv.Atoi(out[i].Port)
		pj, _ := strconv.Atoi(out[j].Port)
		if pi != pj {
			return pi < pj
		}
		return out[i].ServiceName < out[j].ServiceName
	})
	return out
}

func mergedOpenPortCount(ports []portInfo, services []serviceInfo) int {
	uniq := make(map[int]struct{})
	for _, p := range ports {
		if p.Port > 0 {
			uniq[p.Port] = struct{}{}
		}
	}
	for _, s := range services {
		n, err := strconv.Atoi(s.Port)
		if err == nil && n > 0 {
			uniq[n] = struct{}{}
		}
	}
	return len(uniq)
}

func (h *EnrichHandler) AssetDetail(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	var asset model.Asset
	if err := h.session().First(&asset, "id = ?", id).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	addressLike := "%" + asset.Address + "%"
	var ports []portInfo
	var portFindings []model.ScanFinding
	_ = h.session().Model(&model.ScanFinding{}).
		Where("target LIKE ? AND type = ?", addressLike, "port_open").
		Order("port ASC").
		Limit(400).
		Find(&portFindings).Error
	ports = portFindingsToPortInfo(portFindings)

	var vulns []vulnBrief
	h.session().Model(&model.Vulnerability{}).
		Select("id, title, severity, status, target, created_at").
		Where("target LIKE ?", "%"+asset.Address+"%").
		Order("severity DESC, created_at DESC").
		Limit(50).
		Find(&vulns)

	var scanHistory []scanHistoryItem
	h.session().Raw(`SELECT DISTINCT t.id, t.name, t.status, t.created_at, t.finished_at
		FROM vs_scan_task t
		WHERE t.targets LIKE ?
		ORDER BY t.created_at DESC
		LIMIT 20`, "%"+asset.Address+"%").Scan(&scanHistory)

	var services []serviceInfo
	var serviceFindings []model.ScanFinding
	_ = h.session().Model(&model.ScanFinding{}).
		Where("target LIKE ? AND type = ?", addressLike, "service").
		Limit(800).
		Find(&serviceFindings).Error
	services = serviceFindingsToServiceInfo(serviceFindings)

	type monitorTaskBrief struct {
		ID             string     `json:"id"`
		TaskName       string     `json:"task_name"`
		TargetHomepage string     `json:"target_homepage"`
		Enabled        bool       `json:"enabled"`
		NextRunAt      *time.Time `json:"next_run_at"`
	}
	var monitorTasks []monitorTaskBrief
	h.session().Table("monitor_tasks").
		Select("id, task_name, target_homepage, enabled, next_run_at").
		Where("asset_id = ?", id).
		Order("created_at DESC").Limit(10).
		Find(&monitorTasks)

	var assetVulns []vulnBrief
	h.session().Table("vs_vulnerability").
		Select("id, title, severity, status, target, created_at").
		Where("asset_id = ?", id).
		Order("severity DESC, created_at DESC").
		Limit(50).
		Find(&assetVulns)

	web.OK(c).Data(gin.H{
		"asset":         asset,
		"ports":         ports,
		"vulns":         vulns,
		"asset_vulns":   assetVulns,
		"scan_history":  scanHistory,
		"services":      services,
		"monitor_tasks": monitorTasks,
		"summary": gin.H{
			"port_count":    mergedOpenPortCount(ports, services),
			"vuln_count":    len(vulns),
			"scan_count":    len(scanHistory),
			"monitor_count": len(monitorTasks),
			"risk_score":    asset.RiskScore,
			"last_scan":     asset.LastScanAt,
		},
	}).Send()
}

func (h *EnrichHandler) AggregateFromScans(c *gin.Context) {
	scope := iamsdk.DataFilterScope(c, assetFieldMapping)

	var findings []struct {
		Target   string
		Type     string
		Port     int
		Protocol string
		Service  string
	}
	h.session().Model(&model.ScanFinding{}).
		Select("DISTINCT target, type, COALESCE(port, 0) as port, protocol, service").
		Where("type IN ?", []string{"port_open", "service", "host_alive"}).
		Scopes(scope).
		Find(&findings)

	assetMap := make(map[string]*model.Asset)
	now := time.Now()

	for _, f := range findings {
		host := extractHost(f.Target)
		if host == "" {
			continue
		}

		key := host
		if f.Port > 0 {
			key = host + ":" + strconv.Itoa(f.Port)
		}

		if _, ok := assetMap[key]; ok {
			asset := assetMap[key]
			if f.Service != "" && asset.Service == "" {
				asset.Service = f.Service
			}
			continue
		}

		assetType := "host"
		if strings.Contains(host, ".") && !isIP(host) {
			assetType = "domain"
		}

		assetMap[key] = &model.Asset{
			Name:     key,
			Type:     assetType,
			Address:  host,
			Port:     f.Port,
			Protocol: f.Protocol,
			Service:  f.Service,
			Status:   1,
		}
	}

	created := 0
	updated := 0
	for _, asset := range assetMap {
		var existing model.Asset
		result := h.session().Where("address = ? AND port = ?", asset.Address, asset.Port).First(&existing)
		if result.Error == nil {
			h.session().Model(&existing).Updates(map[string]interface{}{
				"service":      asset.Service,
				"protocol":     asset.Protocol,
				"status":       1,
				"last_scan_at": &now,
			})
			updated++
		} else {
			asset.ID = qulid.GenerateID()
			asset.LastScanAt = &now
			h.session().Create(asset)
			created++
		}
	}

	web.OK(c).Data(gin.H{
		"total_discovered": len(assetMap),
		"created":          created,
		"updated":          updated,
	}).Send()
}

func (h *EnrichHandler) AssetStats(c *gin.Context) {
	listQuery, ok := web.BindQuery[assetContract.AssetQuery](c)
	if !ok {
		return
	}
	listQuery.Page = 0
	listQuery.PageSize = 0

	scope := iamsdk.DataFilterScope(c, assetFieldMapping)

	var totalAssets int64
	if err := buildAssetListQuery(h.session(), listQuery, scope).Count(&totalAssets).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	var activeAssets int64
	if err := buildAssetListQuery(h.session(), listQuery, scope).Where("status = 1").Count(&activeAssets).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	var keyAssets int64
	if err := buildAssetListQuery(h.session(), listQuery, scope).Where("is_key = ?", true).Count(&keyAssets).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	var riskHigh int64
	if err := buildAssetListQuery(h.session(), listQuery, scope).Where("risk_score >= 70").Count(&riskHigh).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	type typeStat struct {
		Type  string `json:"type"`
		Count int64  `json:"count"`
	}
	var typeStats []typeStat
	if err := buildAssetListQuery(h.session(), listQuery, scope).
		Select("type, COUNT(*) as count").
		Group("type").
		Find(&typeStats).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	type groupStat struct {
		GroupID string `json:"group_id"`
		Count   int64  `json:"count"`
	}
	var groupStats []groupStat
	if err := buildAssetListQuery(h.session(), listQuery, scope).
		Where("group_id != ''").
		Select("group_id, COUNT(*) as count").
		Group("group_id").
		Find(&groupStats).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	var vulnAssets int64
	h.session().Model(&model.Vulnerability{}).
		Select("COUNT(DISTINCT target)").
		Where("status NOT IN ?", []string{"fixed", "ignored"}).
		Count(&vulnAssets)

	web.OK(c).Data(gin.H{
		"total":      totalAssets,
		"active":     activeAssets,
		"inactive":   totalAssets - activeAssets,
		"key_assets": keyAssets,
		"risk_high":  riskHigh,
		"with_vulns": vulnAssets,
		"by_type":    typeStats,
		"by_group":   groupStats,
	}).Send()
}

// RegionScope 返回资产台账中实际出现的地域编码及数量（受数据权限约束，不含空地域）。
func (h *EnrichHandler) RegionScope(c *gin.Context) {
	scope := iamsdk.DataFilterScope(c, assetFieldMapping)

	type row struct {
		RegionCode string `json:"region_code"`
		Count      int64  `json:"count"`
	}
	var rows []row
	if err := h.session().Model(&model.Asset{}).
		Scopes(scope).
		Where("region_code != '' AND region_code IS NOT NULL").
		Select("region_code, COUNT(*) as count").
		Group("region_code").
		Order("region_code ASC").
		Find(&rows).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).Data(rows).Send()
}

func (h *EnrichHandler) GroupList(c *gin.Context) {
	scope := iamsdk.DataFilterScope(c, assetFieldMapping)
	var groups []model.AssetGroup
	h.session().Model(&model.AssetGroup{}).Scopes(scope).Order("created_at DESC").Find(&groups)

	type groupWithCount struct {
		model.AssetGroup
		AssetCount int64 `json:"asset_count"`
	}

	countMap := make(map[string]int64)
	if len(groups) > 0 {
		ids := make([]string, 0, len(groups))
		for _, g := range groups {
			ids = append(ids, g.ID)
		}
		type countRow struct {
			GroupID string `gorm:"column:group_id"`
			Cnt     int64  `gorm:"column:cnt"`
		}
		var counts []countRow
		h.session().Model(&model.Asset{}).
			Select("group_id, COUNT(*) as cnt").
			Where("group_id IN ?", ids).
			Group("group_id").
			Find(&counts)
		for _, cr := range counts {
			countMap[cr.GroupID] = cr.Cnt
		}
	}

	result := make([]groupWithCount, 0, len(groups))
	for _, g := range groups {
		result = append(result, groupWithCount{AssetGroup: g, AssetCount: countMap[g.ID]})
	}

	web.OK(c).Data(result).Send()
}

func (h *EnrichHandler) GroupCreate(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		ParentID    string `json:"parent_id"`
		IsDynamic   bool   `json:"is_dynamic"`
		RuleField   string `json:"rule_field"`
		RuleOp      string `json:"rule_op"`
		RuleValue   string `json:"rule_value"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	group := model.AssetGroup{
		ID:          qulid.GenerateID(),
		Name:        req.Name,
		Description: req.Description,
		ParentID:    req.ParentID,
		CreatedBy:   user.UserID,
		OrganizeID:  user.OrganizeID,
		IsDynamic:   req.IsDynamic,
		RuleField:   req.RuleField,
		RuleOp:      req.RuleOp,
		RuleValue:   req.RuleValue,
	}

	if err := h.session().Create(&group).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	if req.IsDynamic {
		h.executeDynamicGroupRule(&group)
	}

	web.OK(c).Data(group).Send()
}

func (h *EnrichHandler) executeDynamicGroupRule(group *model.AssetGroup) {
	if group.RuleField == "" || group.RuleOp == "" || group.RuleValue == "" {
		return
	}

	allowedFields := map[string]bool{
		"type": true, "system_type": true, "security_protection_level": true,
		"data_source": true, "address": true,
		"domain": true, "service": true, "os": true,
	}
	if !allowedFields[group.RuleField] {
		return
	}

	var condition string
	var args []interface{}
	switch group.RuleOp {
	case "eq":
		condition = group.RuleField + " = ?"
		args = []interface{}{group.RuleValue}
	case "contains":
		condition = group.RuleField + " LIKE ?"
		args = []interface{}{"%" + group.RuleValue + "%"}
	case "prefix":
		condition = group.RuleField + " LIKE ?"
		args = []interface{}{group.RuleValue + "%"}
	case "neq":
		condition = group.RuleField + " != ?"
		args = []interface{}{group.RuleValue}
	default:
		return
	}

	result := h.session().Model(&model.Asset{}).Where(condition, args...).
		Update("group_id", group.ID)

	h.session().Model(&model.AssetGroup{}).Where("id = ?", group.ID).
		Update("asset_count", result.RowsAffected)
}

func (h *EnrichHandler) GroupRefresh(c *gin.Context) {
	id := c.Param("id")
	var group model.AssetGroup
	if err := h.session().First(&group, "id = ?", id).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	if !group.IsDynamic {
		web.Fail(c).Msg("非动态分组不可刷新").Send()
		return
	}

	h.executeDynamicGroupRule(&group)

	var count int64
	h.session().Model(&model.Asset{}).Where("group_id = ?", id).Count(&count)
	web.OK(c).Data(gin.H{"matched": count}).Send()
}

func (h *EnrichHandler) GroupUpdate(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		ParentID    *string `json:"parent_id"`
		IsDynamic   *bool   `json:"is_dynamic"`
		RuleField   *string `json:"rule_field"`
		RuleOp      *string `json:"rule_op"`
		RuleValue   *string `json:"rule_value"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.ParentID != nil {
		updates["parent_id"] = *req.ParentID
	}
	if req.IsDynamic != nil {
		updates["is_dynamic"] = *req.IsDynamic
	}
	if req.RuleField != nil {
		updates["rule_field"] = *req.RuleField
	}
	if req.RuleOp != nil {
		updates["rule_op"] = *req.RuleOp
	}
	if req.RuleValue != nil {
		updates["rule_value"] = *req.RuleValue
	}

	if err := h.session().Model(&model.AssetGroup{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *EnrichHandler) GroupDelete(c *gin.Context) {
	id := c.Param("id")

	var assetCount int64
	h.session().Model(&model.Asset{}).Where("group_id = ?", id).Count(&assetCount)
	if assetCount > 0 {
		web.Fail(c).Msg("该分组下仍有资产，请先迁移或删除").Send()
		return
	}

	if err := h.session().Where("id = ?", id).Delete(&model.AssetGroup{}).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *EnrichHandler) BatchAssignGroup(c *gin.Context) {
	var req struct {
		AssetIDs []string `json:"asset_ids" binding:"required"`
		GroupID  string   `json:"group_id" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	result := h.session().Model(&model.Asset{}).
		Where("id IN ?", req.AssetIDs).
		Update("group_id", req.GroupID)

	if result.Error != nil {
		web.Fail(c).Err(result.Error).Send()
		return
	}

	web.OK(c).Data(gin.H{"affected": result.RowsAffected}).Send()
}

type portInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

type vulnBrief struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	Target    string    `json:"target"`
	CreatedAt time.Time `json:"created_at"`
}

type scanHistoryItem struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

type serviceInfo struct {
	ServiceName string `json:"service_name"`
	Version     string `json:"version"`
	Port        string `json:"port"`
	Protocol    string `json:"protocol"`
	Count       int    `json:"count"`
}

func extractHost(target string) string {
	target = strings.TrimSpace(target)
	for _, prefix := range []string{"https://", "http://"} {
		target = strings.TrimPrefix(target, prefix)
	}
	parts := strings.SplitN(target, "/", 2)
	host := parts[0]
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host
}

func isIP(s string) bool {
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return strings.Count(s, ".") == 3
}

// ── 资产去重 ──

func (h *EnrichHandler) Dedup(c *gin.Context) {
	type dupGroup struct {
		Address string
		Port    int
		Cnt     int64
	}
	var dups []dupGroup
	h.session().Model(&model.Asset{}).
		Select("address, port, COUNT(*) as cnt").
		Group("address, port").
		Having("COUNT(*) > 1").
		Find(&dups)

	merged := 0
	for _, d := range dups {
		var assets []model.Asset
		h.session().Where("address = ? AND port = ?", d.Address, d.Port).
			Order("updated_at DESC").Find(&assets)

		if len(assets) <= 1 {
			continue
		}

		tx := h.session().Begin()
		keep := assets[0]
		for _, a := range assets[1:] {
			if keep.Service == "" && a.Service != "" {
				keep.Service = a.Service
			}
			if keep.Domain == "" && a.Domain != "" {
				keep.Domain = a.Domain
			}
			if keep.IPv4 == "" && a.IPv4 != "" {
				keep.IPv4 = a.IPv4
			}
			if keep.Version == "" && a.Version != "" {
				keep.Version = a.Version
			}
			if keep.OS == "" && a.OS != "" {
				keep.OS = a.OS
			}
			if keep.DataNumber == "" && a.DataNumber != "" {
				keep.DataNumber = a.DataNumber
			}
			if a.VulnCount > keep.VulnCount {
				keep.VulnCount = a.VulnCount
			}
			if a.RiskScore > keep.RiskScore {
				keep.RiskScore = a.RiskScore
			}

			if err := tx.Where("id = ?", a.ID).Delete(&model.Asset{}).Error; err != nil {
				tx.Rollback()
				continue
			}
			merged++
		}

		if err := tx.Model(&model.Asset{}).Where("id = ?", keep.ID).Updates(map[string]interface{}{
			"service": keep.Service, "domain": keep.Domain, "ipv4": keep.IPv4,
			"version": keep.Version, "os": keep.OS,
			"vuln_count": keep.VulnCount, "risk_score": keep.RiskScore,
		}).Error; err != nil {
			tx.Rollback()
			continue
		}
		tx.Commit()
	}

	web.OK(c).Data(gin.H{
		"dup_groups":     len(dups),
		"merged_deleted": merged,
	}).Send()
}

// ── 扫描子域名发现入库 / 地址修复 ──

func subdomainFindingHost(f *model.ScanFinding) string {
	if f == nil {
		return ""
	}
	if h := assethost.ExtractHost(f.Target); h != "" {
		return h
	}
	if d := scanFindingDataString(f.Data, "domain"); d != "" {
		return assethost.ExtractHost(d)
	}
	return ""
}

// ImportSubdomainsFromScan 将扫描任务中的子域名发现写入资产台账（每条发现一条资产，地址为完整 FQDN）。
func (h *EnrichHandler) ImportSubdomainsFromScan(c *gin.Context) {
	var req struct {
		TaskID string `json:"task_id" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	taskID := strings.TrimSpace(req.TaskID)
	if taskID == "" {
		web.Fail(c).Msg("请提供扫描任务 ID").Send()
		return
	}

	var findings []model.ScanFinding
	if err := h.session().Where("task_id = ? AND type = ?", taskID, "subdomain").
		Order("created_at ASC").Find(&findings).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	if len(findings) == 0 {
		web.OK(c).Data(gin.H{"total": 0, "created": 0, "skipped": 0}).Send()
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	created, skipped := 0, 0
	for i := range findings {
		f := findings[i]
		host := subdomainFindingHost(&f)
		if host == "" {
			skipped++
			continue
		}
		name := strings.TrimSpace(f.Title)
		if name == "" {
			name = "发现子域名: " + host
		}

		var existing model.Asset
		err := h.session().Where(
			"LOWER(address) = ? OR LOWER(domain) = ? OR name = ?",
			host, host, name,
		).First(&existing).Error
		if err == nil {
			skipped++
			continue
		}

		addr := host
		if norm, err := NormalizeAccessAddress(host, "domain_site"); err == nil && norm != "" {
			addr = norm
		}
		item := model.Asset{
			ID:          qulid.GenerateID(),
			Name:        name,
			Type:        "domain",
			Address:     addr,
			Domain:      host,
			AssetFamily: "domain_site",
			Status:      1,
			DataSource:  model.DataSourceScan,
			CreatedBy:   user.UserID,
			OrganizeID:  user.OrganizeID,
		}
		normalizeAssetAddressFields(&item)
		if err := h.session().Create(&item).Error; err != nil {
			skipped++
			continue
		}
		created++
	}

	web.OK(c).Data(gin.H{
		"total":   len(findings),
		"created": created,
		"skipped": skipped,
	}).Send()
}

// RepairSubdomainAddresses 根据资产名称「发现子域名: {fqdn}」修复被错误写成根域的访问地址。
func (h *EnrichHandler) RepairSubdomainAddresses(c *gin.Context) {
	scope := iamsdk.DataFilterScope(c, assetFieldMapping)
	var assets []model.Asset
	if err := h.session().Model(&model.Asset{}).Scopes(scope).
		Where("name LIKE ?", "发现子域名:%").Find(&assets).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	fixed, skipped := 0, 0
	for i := range assets {
		a := assets[i]
		host := assethost.HostFromSubdomainDiscoveryName(a.Name)
		if host == "" {
			skipped++
			continue
		}
		cur := assethost.ExtractHost(a.Address)
		if cur == host {
			skipped++
			continue
		}
		if cur != "" && !assethost.IsStrictSubdomainOf(host, cur) && cur != host {
			// 地址已是其它独立主机名，不自动覆盖
			skipped++
			continue
		}

		family := firstNonEmpty(a.AssetFamily, "domain_site")
		addr := host
		if norm, err := NormalizeAccessAddress(host, family); err == nil && norm != "" {
			addr = norm
		}
		updates := map[string]any{"address": addr}
		dom := strings.TrimSpace(a.Domain)
		if dom == "" || assethost.IsStrictSubdomainOf(host, dom) || assethost.ExtractHost(dom) == host {
			updates["domain"] = host
		}
		if err := h.session().Model(&model.Asset{}).Where("id = ?", a.ID).Updates(updates).Error; err != nil {
			skipped++
			continue
		}
		fixed++
	}

	web.OK(c).Data(gin.H{
		"total":   len(assets),
		"fixed":   fixed,
		"skipped": skipped,
	}).Send()
}

// ── 网络空间搜索结果入库 ──

func (h *EnrichHandler) ImportFromCyberspace(c *gin.Context) {
	var req struct {
		Items []struct {
			IP       string `json:"ip"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Service  string `json:"service"`
			Version  string `json:"version"`
			Title    string `json:"title"`
			OS       string `json:"os"`
			Country  string `json:"country"`
			Org      string `json:"org"`
			Hostname string `json:"hostname"`
		} `json:"items" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	created, skipped := 0, 0

	for _, item := range req.Items {
		if item.IP == "" {
			skipped++
			continue
		}

		var existing model.Asset
		result := h.session().Where("address = ? AND port = ?", item.IP, item.Port).First(&existing)
		if result.Error == nil {
			skipped++
			continue
		}

		name := item.IP
		if item.Port > 0 {
			name = item.IP + ":" + strconv.Itoa(item.Port)
		}

		assetType := "host"
		domain := ""
		if item.Hostname != "" {
			domain = item.Hostname
			assetType = "web"
		}

		asset := model.Asset{
			ID:         qulid.GenerateID(),
			Name:       name,
			Address:    item.IP,
			IPv4:       item.IP,
			Port:       item.Port,
			Protocol:   item.Protocol,
			Service:    item.Service,
			Version:    item.Version,
			OS:         item.OS,
			Domain:     domain,
			Type:       assetType,
			Status:     1,
			DataSource: "external",
			CreatedBy:  user.UserID,
			OrganizeID: user.OrganizeID,
			Remark:     item.Country + " " + item.Org,
		}

		if err := h.session().Create(&asset).Error; err == nil {
			created++
		} else {
			skipped++
		}
	}

	web.OK(c).Data(gin.H{
		"total":   len(req.Items),
		"created": created,
		"skipped": skipped,
	}).Send()
}

// ── 信息富化 ──

func scanTargetForAsset(a *model.Asset) string {
	if a == nil {
		return ""
	}
	return assethost.PrimaryHost(a.Address, a.URL, a.Domain, a.IPv4)
}

func (h *EnrichHandler) EnrichAsset(c *gin.Context) {
	id := c.Param("id")
	var asset model.Asset
	if err := h.session().First(&asset, "id = ?", id).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	if h.scanDB == nil || h.scanScheduler == nil {
		web.Fail(c).Msg("扫描调度器未初始化，无法提交富化任务").Send()
		return
	}
	target := scanTargetForAsset(&asset)
	if target == "" {
		web.Fail(c).Msg("该资产没有可扫描的主机地址（域名 / IP / 地址）").Send()
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	name := fmt.Sprintf("资产富化: %s", strings.TrimSpace(asset.Name))
	if strings.TrimSpace(asset.Name) == "" {
		name = fmt.Sprintf("资产富化: %s", target)
	}
	res, err := scanrunner.LaunchScan(h.scanDB, h.scanScheduler, scanrunner.LaunchScanParams{
		Name:       name,
		Targets:    []string{target},
		TemplateID: scanrunner.AssetEnrichTemplateID,
		Priority:   6,
		CreatedBy:  user.UserID,
		OrganizeID: user.OrganizeID,
		TaskType:   model.TaskTypeAssetEnrich,
		AssetIDs:   []string{id},
	})
	if errors.Is(err, scanrunner.ErrTemplateNotFound) {
		web.Fail(c).Msg("内置富化扫描模板不存在，请重启服务以同步模板").Send()
		return
	}
	if err != nil {
		web.Fail(c).Msg("提交扫描任务失败: " + err.Error()).Send()
		return
	}
	task := res.Task
	out := gin.H{
		"asset_id":      id,
		"task_id":       task.ID,
		"status":        task.Status,
		"template":      task.TemplateName,
		"split_mode":    res.SplitMode,
		"engine_enrich": true,
	}
	if res.SplitMode {
		out["sub_count"] = res.SubCount
	}
	web.OK(c).Data(out).Send()
}

func (h *EnrichHandler) BatchEnrich(c *gin.Context) {
	var req struct {
		IDs      []string `json:"ids"`
		AssetIDs []string `json:"asset_ids"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	ids := req.IDs
	if len(ids) == 0 {
		ids = req.AssetIDs
	}
	if len(ids) == 0 {
		web.Fail(c).Msg("请提供资产 id 列表（ids 或 asset_ids）").Send()
		return
	}
	if h.scanDB == nil || h.scanScheduler == nil {
		web.Fail(c).Msg("扫描调度器未初始化，无法提交富化任务").Send()
		return
	}

	var assets []model.Asset
	h.session().Where("id IN ?", ids).Find(&assets)

	targets := make([]string, 0, len(assets))
	assetIDs := make([]string, 0, len(assets))
	for i := range assets {
		t := scanTargetForAsset(&assets[i])
		if t == "" {
			continue
		}
		targets = append(targets, t)
		assetIDs = append(assetIDs, assets[i].ID)
	}
	if len(targets) == 0 {
		web.Fail(c).Msg("所选资产均无有效扫描目标").Send()
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	name := fmt.Sprintf("批量资产富化(%d)", len(targets))
	res, err := scanrunner.LaunchScan(h.scanDB, h.scanScheduler, scanrunner.LaunchScanParams{
		Name:       name,
		Targets:    targets,
		TemplateID: scanrunner.AssetEnrichTemplateID,
		Priority:   6,
		CreatedBy:  user.UserID,
		OrganizeID: user.OrganizeID,
		TaskType:   model.TaskTypeAssetEnrich,
		AssetIDs:   assetIDs,
	})
	if errors.Is(err, scanrunner.ErrTemplateNotFound) {
		web.Fail(c).Msg("内置富化扫描模板不存在，请重启服务以同步模板").Send()
		return
	}
	if err != nil {
		web.Fail(c).Msg("提交扫描任务失败: " + err.Error()).Send()
		return
	}
	task := res.Task
	out := gin.H{
		"task_id":       task.ID,
		"status":        task.Status,
		"template":      task.TemplateName,
		"target_count":  len(targets),
		"skipped":       len(ids) - len(targets),
		"split_mode":    res.SplitMode,
		"engine_enrich": true,
	}
	if res.SplitMode {
		out["sub_count"] = res.SubCount
	}
	web.OK(c).Data(out).Send()
}

func (h *EnrichHandler) RecalcRisk(c *gin.Context) {
	id := c.Param("id")
	var asset model.Asset
	if err := h.session().First(&asset, "id = ?", id).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	score, detail := h.calcRiskScore(&asset)

	h.session().Model(&model.Asset{}).Where("id = ?", id).Update("risk_score", score)
	h.session().Create(&model.AssetRiskHistory{
		AssetID:       id,
		Score:         score,
		VulnScore:     detail["vuln"],
		ExposureScore: detail["exposure"],
		AlertScore:    detail["alert"],
		SSLScore:      detail["ssl"],
		RecordedAt:    time.Now(),
	})

	web.OK(c).Data(gin.H{"score": score, "detail": detail}).Send()
}

func (h *EnrichHandler) RecalcAllRisk(c *gin.Context) {
	const batchSize = 200

	var total int64
	h.session().Model(&model.Asset{}).Count(&total)

	now := time.Now()
	updated := 0

	for offset := 0; offset < int(total); offset += batchSize {
		var batch []model.Asset
		h.session().Model(&model.Asset{}).Offset(offset).Limit(batchSize).Find(&batch)
		if len(batch) == 0 {
			break
		}

		var histories []model.AssetRiskHistory
		ids := make([]string, 0, len(batch))
		scores := make(map[string]float64, len(batch))

		for i := range batch {
			score, detail := h.calcRiskScore(&batch[i])
			scores[batch[i].ID] = score
			ids = append(ids, batch[i].ID)
			histories = append(histories, model.AssetRiskHistory{
				AssetID:       batch[i].ID,
				Score:         score,
				VulnScore:     detail["vuln"],
				ExposureScore: detail["exposure"],
				AlertScore:    detail["alert"],
				SSLScore:      detail["ssl"],
				RecordedAt:    now,
			})
		}

		for _, id := range ids {
			h.session().Model(&model.Asset{}).Where("id = ?", id).Update("risk_score", scores[id])
		}
		if len(histories) > 0 {
			h.session().CreateInBatches(histories, 100)
		}
		updated += len(batch)
	}

	web.OK(c).Data(gin.H{"updated": updated}).Send()
}

func (h *EnrichHandler) RiskTrend(c *gin.Context) {
	id := c.Param("id")
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days <= 0 || days > 365 {
		days = 30
	}

	since := time.Now().AddDate(0, 0, -days)
	var history []model.AssetRiskHistory
	h.session().Where("asset_id = ? AND recorded_at >= ?", id, since).
		Order("recorded_at ASC").Find(&history)

	web.OK(c).Data(history).Send()
}

func (h *EnrichHandler) RiskRanking(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	var assets []model.Asset
	h.session().Order("risk_score DESC").Limit(limit).Find(&assets)

	type RankItem struct {
		ID        string  `json:"id"`
		Name      string  `json:"name"`
		Address   string  `json:"address"`
		RiskScore float64 `json:"risk_score"`
		VulnCount int     `json:"vuln_count"`
		Type      string  `json:"type"`
	}
	result := make([]RankItem, 0, len(assets))
	for _, a := range assets {
		result = append(result, RankItem{
			ID: a.ID, Name: a.Name, Address: a.Address,
			RiskScore: a.RiskScore, VulnCount: a.VulnCount, Type: a.Type,
		})
	}

	web.OK(c).Data(result).Send()
}

func (h *EnrichHandler) calcRiskScore(asset *model.Asset) (float64, map[string]float64) {
	detail := map[string]float64{"vuln": 0, "exposure": 0, "alert": 0, "ssl": 0}

	targets := h.buildTargetMatchers(asset)
	if len(targets) == 0 {
		return 0, detail
	}

	var vulnCounts struct {
		Critical int64
		High     int64
		Medium   int64
		Low      int64
	}
	h.session().Model(&model.Vulnerability{}).
		Where("target IN ?", targets).
		Where("status NOT IN ?", []string{"fixed", "ignored"}).
		Select(`
			SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
			SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
			SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) as medium,
			SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END) as low
		`).Scan(&vulnCounts)

	detail["vuln"] = float64(vulnCounts.Critical)*10 + float64(vulnCounts.High)*5 +
		float64(vulnCounts.Medium)*2 + float64(vulnCounts.Low)*0.5
	if detail["vuln"] > 40 {
		detail["vuln"] = 40
	}

	var portCount int64
	h.session().Model(&model.ScanFinding{}).
		Where("target IN ? AND type = 'port_open'", targets).
		Count(&portCount)
	detail["exposure"] = float64(portCount) * 2
	if detail["exposure"] > 25 {
		detail["exposure"] = 25
	}

	var alertCount int64
	h.session().Model(&model.AssetRiskHistory{}).
		Where("asset_id = ? AND recorded_at >= ?", asset.ID, time.Now().AddDate(0, 0, -30)).
		Count(&alertCount)
	detail["alert"] = float64(alertCount) * 1
	if detail["alert"] > 15 {
		detail["alert"] = 15
	}

	if asset.SSLExpiresAt != nil {
		daysLeft := int(time.Until(*asset.SSLExpiresAt).Hours() / 24)
		if daysLeft < 0 {
			detail["ssl"] = 20
		} else if daysLeft < 30 {
			detail["ssl"] = 15
		} else if daysLeft < 60 {
			detail["ssl"] = 10
		} else if daysLeft < 90 {
			detail["ssl"] = 5
		}
	}

	total := detail["vuln"] + detail["exposure"] + detail["alert"] + detail["ssl"]
	if total > 100 {
		total = 100
	}

	return total, detail
}

func (h *EnrichHandler) buildTargetMatchers(asset *model.Asset) []string {
	seen := make(map[string]bool)
	var targets []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			targets = append(targets, s)
		}
	}
	add(asset.Address)
	add(asset.IPv4)
	add(asset.Domain)
	if asset.URL != "" {
		add(asset.URL)
	}
	if asset.Port > 0 {
		add(fmt.Sprintf("%s:%d", asset.Address, asset.Port))
		if asset.IPv4 != "" {
			add(fmt.Sprintf("%s:%d", asset.IPv4, asset.Port))
		}
		if asset.Domain != "" {
			add(fmt.Sprintf("%s:%d", asset.Domain, asset.Port))
		}
	}
	return targets
}

// ── 资产报告 ──

func (h *EnrichHandler) ComplianceReport(c *gin.Context) {
	scope := iamsdk.DataFilterScope(c, assetFieldMapping)

	type complianceCounts struct {
		Total           int64 `gorm:"column:total"`
		WithLevel       int64 `gorm:"column:with_level"`
		WithResponsible int64 `gorm:"column:with_responsible"`
		WithNumber      int64 `gorm:"column:with_number"`
		WithFiling      int64 `gorm:"column:with_filing"`
		WithIcp         int64 `gorm:"column:with_icp"`
	}
	var cc complianceCounts
	h.session().Model(&model.Asset{}).Scopes(scope).
		Select(`COUNT(*) as total,
			SUM(CASE WHEN security_protection_level != '' THEN 1 ELSE 0 END) as with_level,
			SUM(CASE WHEN responsible_user_name != '' THEN 1 ELSE 0 END) as with_responsible,
			SUM(CASE WHEN data_number != '' THEN 1 ELSE 0 END) as with_number,
			SUM(CASE WHEN filing_cert_number != '' THEN 1 ELSE 0 END) as with_filing,
			SUM(CASE WHEN icp_filing_number != '' THEN 1 ELSE 0 END) as with_icp`).
		Scan(&cc)

	total := cc.Total
	withLevel := cc.WithLevel
	withResponsible := cc.WithResponsible
	withNumber := cc.WithNumber
	withFiling := cc.WithFiling
	withIcp := cc.WithIcp

	type levelDist struct {
		Level string `json:"level"`
		Count int64  `json:"count"`
	}
	var levels []levelDist
	h.session().Model(&model.Asset{}).Scopes(scope).
		Select("security_protection_level as level, COUNT(*) as count").
		Where("security_protection_level != ''").
		Group("security_protection_level").Find(&levels)

	var highRisk int64
	h.session().Model(&model.Asset{}).Scopes(scope).
		Where("risk_score >= 70").Count(&highRisk)

	var sslExpiring int64
	h.session().Model(&model.Asset{}).Scopes(scope).
		Where("ssl_expires_at IS NOT NULL AND ssl_expires_at <= ?", time.Now().AddDate(0, 0, 60)).
		Count(&sslExpiring)

	safeDiv := func(a, b int64) float64 {
		if b == 0 {
			return 0
		}
		return float64(a) / float64(b) * 100
	}

	web.OK(c).Data(gin.H{
		"generated_at": time.Now().Format("2006-01-02 15:04:05"),
		"summary": gin.H{
			"total_assets": total,
			"high_risk":    highRisk,
			"ssl_expiring": sslExpiring,
		},
		"compliance": gin.H{
			"level_coverage":       fmt.Sprintf("%.1f%%", safeDiv(withLevel, total)),
			"responsible_coverage": fmt.Sprintf("%.1f%%", safeDiv(withResponsible, total)),
			"number_coverage":      fmt.Sprintf("%.1f%%", safeDiv(withNumber, total)),
			"filing_coverage":      fmt.Sprintf("%.1f%%", safeDiv(withFiling, total)),
			"icp_coverage":         fmt.Sprintf("%.1f%%", safeDiv(withIcp, total)),
		},
		"distribution": gin.H{
			"by_level": levels,
		},
		"risks": gin.H{
			"high_risk_count": highRisk,
			"ssl_expiring":    sslExpiring,
		},
	}).Send()
}
