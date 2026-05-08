package asset

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type EnrichHandler struct {
	database *db.DB
}

func NewEnrichHandler(database *db.DB) *EnrichHandler {
	return &EnrichHandler{database: database}
}

func (h *EnrichHandler) session() *gorm.DB {
	sess, _ := h.database.GetDBSession()
	return sess
}

func (h *EnrichHandler) AssetDetail(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	var asset model.Asset
	if err := h.session().First(&asset, "id = ?", id).Error; err != nil {
		web.Resp(c, web.NotFound)
		return
	}

	var ports []portInfo
	h.session().Raw(`SELECT DISTINCT port, protocol, service, version
		FROM vs_scan_finding
		WHERE target LIKE ? AND type = 'port_open'
		ORDER BY port`, "%"+asset.Address+"%").Scan(&ports)

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
	h.session().Raw(`SELECT DISTINCT
		COALESCE(data->>'service', '') as service_name,
		COALESCE(data->>'version', '') as version,
		COALESCE(data->>'port', '0') as port,
		COUNT(*) as count
		FROM vs_scan_finding
		WHERE target LIKE ? AND type = 'service'
		GROUP BY service_name, version, port`, "%"+asset.Address+"%").Scan(&services)

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
			"port_count":    len(ports),
			"vuln_count":    len(vulns),
			"scan_count":    len(scanHistory),
			"monitor_count": len(monitorTasks),
			"risk_score":    asset.RiskScore,
			"last_scan":     asset.LastScanAt,
		},
	}).Send()
}

func (h *EnrichHandler) AggregateFromScans(c *gin.Context) {
	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)

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
	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)

	var totalAssets int64
	h.session().Model(&model.Asset{}).Scopes(scope).Count(&totalAssets)

	var activeAssets int64
	h.session().Model(&model.Asset{}).Scopes(scope).Where("status = 1").Count(&activeAssets)

	type typeStat struct {
		Type  string `json:"type"`
		Count int64  `json:"count"`
	}
	var typeStats []typeStat
	h.session().Model(&model.Asset{}).
		Select("type, COUNT(*) as count").
		Scopes(scope).
		Group("type").
		Find(&typeStats)

	type groupStat struct {
		GroupID string `json:"group_id"`
		Count   int64  `json:"count"`
	}
	var groupStats []groupStat
	h.session().Model(&model.Asset{}).
		Select("group_id, COUNT(*) as count").
		Scopes(scope).
		Where("group_id != ''").
		Group("group_id").
		Find(&groupStats)

	var vulnAssets int64
	h.session().Model(&model.Vulnerability{}).
		Select("COUNT(DISTINCT target)").
		Where("status NOT IN ?", []string{"fixed", "ignored"}).
		Count(&vulnAssets)

	web.OK(c).Data(gin.H{
		"total":      totalAssets,
		"active":     activeAssets,
		"inactive":   totalAssets - activeAssets,
		"with_vulns": vulnAssets,
		"by_type":    typeStats,
		"by_group":   groupStats,
	}).Send()
}

func (h *EnrichHandler) GroupList(c *gin.Context) {
	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
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

	web.RespContent(c, web.Success, result)
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
		web.Resp(c, web.InternalError)
		return
	}

	if req.IsDynamic {
		h.executeDynamicGroupRule(&group)
	}

	web.RespContent(c, web.Success, group)
}

func (h *EnrichHandler) executeDynamicGroupRule(group *model.AssetGroup) {
	if group.RuleField == "" || group.RuleOp == "" || group.RuleValue == "" {
		return
	}

	allowedFields := map[string]bool{
		"type": true, "system_type": true, "security_protection_level": true,
		"lifecycle_state": true, "data_source": true, "address": true,
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
		web.Resp(c, web.NotFound)
		return
	}

	if !group.IsDynamic {
		web.Fail(c).Msg("非动态分组不可刷新").Send()
		return
	}

	h.executeDynamicGroupRule(&group)

	var count int64
	h.session().Model(&model.Asset{}).Where("group_id = ?", id).Count(&count)
	web.RespContent(c, web.Success, gin.H{"matched": count})
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
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
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
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
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
		web.Resp(c, web.InternalError)
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

// ── 资产关联关系 ──

func (h *EnrichHandler) RelationList(c *gin.Context) {
	assetID := c.Param("id")
	if assetID == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	var relations []model.AssetRelation
	h.session().Where("source_id = ? OR target_id = ?", assetID, assetID).
		Order("created_at DESC").Find(&relations)

	type RelationVO struct {
		model.AssetRelation
		SourceName string `json:"source_name"`
		TargetName string `json:"target_name"`
		SourceAddr string `json:"source_address"`
		TargetAddr string `json:"target_address"`
	}
	var ids []string
	for _, r := range relations {
		ids = append(ids, r.SourceID, r.TargetID)
	}
	nameMap := make(map[string]model.Asset)
	if len(ids) > 0 {
		var assets []model.Asset
		h.session().Select("id, name, address").Where("id IN ?", ids).Find(&assets)
		for _, a := range assets {
			nameMap[a.ID] = a
		}
	}
	result := make([]RelationVO, 0, len(relations))
	for _, r := range relations {
		vo := RelationVO{AssetRelation: r}
		if s, ok := nameMap[r.SourceID]; ok {
			vo.SourceName = s.Name
			vo.SourceAddr = s.Address
		}
		if t, ok := nameMap[r.TargetID]; ok {
			vo.TargetName = t.Name
			vo.TargetAddr = t.Address
		}
		result = append(result, vo)
	}

	web.RespContent(c, web.Success, result)
}

func (h *EnrichHandler) RelationCreate(c *gin.Context) {
	var req struct {
		SourceID     string `json:"source_id" binding:"required"`
		TargetID     string `json:"target_id" binding:"required"`
		RelationType string `json:"relation_type" binding:"required"`
		Description  string `json:"description"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	if req.SourceID == req.TargetID {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	rel := model.AssetRelation{
		SourceID:     req.SourceID,
		TargetID:     req.TargetID,
		RelationType: req.RelationType,
		Description:  req.Description,
		CreatedBy:    user.UserID,
	}

	if err := h.session().Create(&rel).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, rel)
}

func (h *EnrichHandler) RelationDelete(c *gin.Context) {
	id := c.Param("relationId")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	idNum, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if err := h.session().Where("id = ?", idNum).Delete(&model.AssetRelation{}).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.Resp(c, web.Success)
}

func (h *EnrichHandler) ChildrenList(c *gin.Context) {
	parentID := c.Param("id")
	if parentID == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	var children []model.Asset
	h.session().Where("parent_id = ?", parentID).Order("name").Find(&children)

	web.RespContent(c, web.Success, children)
}

func (h *EnrichHandler) SetParent(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		ParentID string `json:"parent_id"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	if id == req.ParentID {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if err := h.session().Model(&model.Asset{}).Where("id = ?", id).
		Update("parent_id", req.ParentID).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.Resp(c, web.Success)
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
			if keep.SystemName == "" && a.SystemName != "" {
				keep.SystemName = a.SystemName
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
			"version": keep.Version, "os": keep.OS, "system_name": keep.SystemName,
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
			SystemName: item.Title,
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

func (h *EnrichHandler) EnrichAsset(c *gin.Context) {
	id := c.Param("id")
	var asset model.Asset
	if err := h.session().First(&asset, "id = ?", id).Error; err != nil {
		web.Resp(c, web.NotFound)
		return
	}

	updates := make(map[string]interface{})
	results := make(map[string]interface{})

	host := asset.Address
	if asset.IPv4 != "" {
		host = asset.IPv4
	}
	if asset.Domain != "" {
		host = asset.Domain
	}

	if ip := asset.IPv4; ip == "" && asset.Address != "" {
		if resolved := resolveIP(asset.Address); resolved != "" {
			updates["ipv4"] = resolved
			results["resolved_ip"] = resolved
		}
	}

	if sslInfo := checkSSL(host, asset.Port); sslInfo != nil {
		results["ssl"] = sslInfo
		if sslInfo["expires_at"] != nil {
			updates["ssl_expires_at"] = sslInfo["expires_at"]
		}
	}

	if rdns := reverseDNS(asset.IPv4); rdns != "" {
		results["reverse_dns"] = rdns
		if asset.Domain == "" {
			updates["domain"] = rdns
		}
	}

	if len(updates) > 0 {
		h.session().Model(&model.Asset{}).Where("id = ?", id).Updates(updates)
	}

	results["asset_id"] = id
	results["updated_fields"] = len(updates)
	web.OK(c).Data(results).Send()
}

func (h *EnrichHandler) BatchEnrich(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	var assets []model.Asset
	h.session().Where("id IN ?", req.IDs).Find(&assets)

	type enrichResult struct {
		ID      string
		Updates map[string]interface{}
	}

	const workers = 5
	jobs := make(chan model.Asset, len(assets))
	results := make(chan enrichResult, len(assets))

	for w := 0; w < workers; w++ {
		go func() {
			for asset := range jobs {
				updates := make(map[string]interface{})
				host := asset.Address
				if asset.Domain != "" {
					host = asset.Domain
				}

				if asset.IPv4 == "" {
					if resolved := resolveIP(asset.Address); resolved != "" {
						updates["ipv4"] = resolved
					}
				}

				if sslInfo := checkSSL(host, asset.Port); sslInfo != nil {
					if sslInfo["expires_at"] != nil {
						updates["ssl_expires_at"] = sslInfo["expires_at"]
					}
				}

				results <- enrichResult{ID: asset.ID, Updates: updates}
			}
		}()
	}

	for _, a := range assets {
		jobs <- a
	}
	close(jobs)

	enriched := 0
	for i := 0; i < len(assets); i++ {
		r := <-results
		if len(r.Updates) > 0 {
			h.session().Model(&model.Asset{}).Where("id = ?", r.ID).Updates(r.Updates)
			enriched++
		}
	}

	web.OK(c).Data(gin.H{"enriched": enriched, "total": len(req.IDs)}).Send()
}

func resolveIP(host string) string {
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

func reverseDNS(ip string) string {
	if ip == "" {
		return ""
	}
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func checkSSL(host string, port int) map[string]interface{} {
	if port == 0 {
		port = 443
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]
	return map[string]interface{}{
		"subject":    cert.Subject.CommonName,
		"issuer":     cert.Issuer.CommonName,
		"not_before": cert.NotBefore,
		"expires_at": cert.NotAfter,
		"dns_names":  cert.DNSNames,
		"is_expired": time.Now().After(cert.NotAfter),
		"days_left":  int(time.Until(cert.NotAfter).Hours() / 24),
	}
}

// ── 风险评分 ──

func (h *EnrichHandler) RecalcRisk(c *gin.Context) {
	id := c.Param("id")
	var asset model.Asset
	if err := h.session().First(&asset, "id = ?", id).Error; err != nil {
		web.Resp(c, web.NotFound)
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

	web.RespContent(c, web.Success, history)
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

	web.RespContent(c, web.Success, result)
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
	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)

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

	type lifecycleDist struct {
		State string `json:"state"`
		Count int64  `json:"count"`
	}
	var states []lifecycleDist
	h.session().Model(&model.Asset{}).Scopes(scope).
		Select("lifecycle_state as state, COUNT(*) as count").
		Group("lifecycle_state").Find(&states)

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
			"by_level":     levels,
			"by_lifecycle": states,
		},
		"risks": gin.H{
			"high_risk_count": highRisk,
			"ssl_expiring":    sslExpiring,
		},
	}).Send()
}
