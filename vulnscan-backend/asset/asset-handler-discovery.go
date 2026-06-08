package asset

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"code.yt-security.com/public/scanengine/module/portscan"
	assetContract "vulnscan-backend/asset/asset-contract"
	"vulnscan-backend/model"
	"vulnscan-backend/scanrunner"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type DiscoveryHandler struct {
	database      *db.DB
	scanDB        *gorm.DB
	scanScheduler *scanrunner.Scheduler
	assetSvc      assetContract.ServiceAsset
}

func NewDiscoveryHandler(database *db.DB, assetSvc assetContract.ServiceAsset) *DiscoveryHandler {
	return &DiscoveryHandler{database: database, assetSvc: assetSvc}
}

func (h *DiscoveryHandler) BindScanRunner(session *gorm.DB, sched *scanrunner.Scheduler) {
	h.scanDB = session
	h.scanScheduler = sched
}

func (h *DiscoveryHandler) session() *gorm.DB {
	sess, _ := h.database.GetDBSession()
	return sess
}

type createDiscoveryProbeReq struct {
	Name        string   `json:"name"`
	Targets     []string `json:"targets"`
	TargetsText string   `json:"targets_text"`
	PortsPreset string   `json:"ports_preset"`
	PortsCustom string   `json:"ports_custom"`
	TimeoutMs   int      `json:"timeout_ms"`
}

type discoveryProbeQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Status   string `form:"status"`
}

type discoveryCandidateQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Status   string `form:"status"`
	Keyword  string `form:"keyword"`
}

type discoveryIDsReq struct {
	IDs    []string `json:"ids" binding:"required,min=1"`
	Remark string   `json:"remark"`
}

type discoveryVerifyReq struct {
	IDs              []string `json:"ids" binding:"required,min=1"`
	TargetOrganizeID string   `json:"target_organize_id" binding:"required"`
	Remark           string   `json:"remark"`
}

func enrichDiscoveryCandidateAssets(sess *gorm.DB, items []model.AssetDiscoveryCandidate) {
	scanrunner.ApplyLibraryMatchToDiscoveryCandidates(sess, items)
	scanrunner.PersistDiscoveryLibraryMatches(sess, items)
}

func enrichDiscoveryCandidateOrganizes(sess *gorm.DB, items []model.AssetDiscoveryCandidate) {
	if len(items) == 0 {
		return
	}
	ids := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for i := range items {
		oid := strings.TrimSpace(items[i].TargetOrganizeID)
		if oid == "" {
			continue
		}
		if _, ok := seen[oid]; ok {
			continue
		}
		seen[oid] = struct{}{}
		ids = append(ids, oid)
	}
	if len(ids) == 0 {
		return
	}
	var orgs []model.Organize
	if err := sess.Where("id IN ?", ids).Find(&orgs).Error; err != nil {
		return
	}
	nameByID := make(map[string]string, len(orgs))
	for _, o := range orgs {
		nameByID[o.ID] = o.Name
	}
	for i := range items {
		if n, ok := nameByID[items[i].TargetOrganizeID]; ok {
			items[i].TargetOrganizeName = n
		}
	}
}

func parseDiscoveryTargets(req createDiscoveryProbeReq) []string {
	if len(req.Targets) > 0 {
		return req.Targets
	}
	if strings.TrimSpace(req.TargetsText) == "" {
		return nil
	}
	return strings.FieldsFunc(req.TargetsText, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	})
}

func discoveryActor(c *gin.Context) (userID, organizeID string) {
	user, ok := iamsdk.GetCurrentUser(c)
	if !ok || user == nil {
		return "system", ""
	}
	return user.UserID, user.OrganizeID
}

func (h *DiscoveryHandler) probeDB() *gorm.DB {
	if h.scanDB != nil {
		return h.scanDB
	}
	return h.session()
}

func normalizePortsPreset(preset, custom string) (string, error) {
	custom = strings.TrimSpace(custom)
	if custom != "" {
		preset = custom
	}
	p := strings.TrimSpace(preset)
	switch p {
	case "", "top1000":
		return "top1000", nil
	case "top100", "full":
		return p, nil
	default:
		ports := portscan.ParsePortsPreset(p)
		if len(ports) == 0 {
			return "", fmt.Errorf("自定义端口无效，请使用逗号分隔的端口或范围，如 22,80,443,8000-8100")
		}
		if len(ports) > 4096 {
			return "", fmt.Errorf("自定义端口数量过多（%d），请缩小范围或使用 top1000", len(ports))
		}
		return p, nil
	}
}

type discoveryProbeListItem struct {
	model.AssetDiscoveryProbe
	TaskStatus string `json:"task_status,omitempty"`
	AliveHosts int    `json:"alive_hosts,omitempty"`
	OpenPorts  int    `json:"open_ports,omitempty"`
}

func (h *DiscoveryHandler) backfillProbesFromScanTasks(sess *gorm.DB) {
	var tasks []model.ScanTask
	if err := sess.Where("type = ? AND (parent_id = '' OR parent_id IS NULL)", model.TaskTypeAssetDiscovery).
		Order("created_at DESC").Limit(200).Find(&tasks).Error; err != nil {
		return
	}
	for _, t := range tasks {
		var n int64
		if err := sess.Model(&model.AssetDiscoveryProbe{}).Where("task_id = ?", t.ID).Count(&n).Error; err != nil || n > 0 {
			continue
		}
		portsPreset := "top1000"
		if params := t.Parameters; params != nil {
			if mc, ok := params["module_configs"].(map[string]interface{}); ok {
				if hd, ok := mc["host_discover"].(map[string]interface{}); ok {
					if ps, ok := hd["ports"].(string); ok && strings.TrimSpace(ps) != "" {
						portsPreset = strings.TrimSpace(ps)
					}
				}
			}
		}
		now := time.Now()
		probe := model.AssetDiscoveryProbe{
			ID:          ulid.GenerateID(),
			Name:        t.Name,
			TaskID:      t.ID,
			TargetsRaw:  strings.Join(t.Targets, "\n"),
			TargetCount: t.TotalTargets,
			PortsPreset: portsPreset,
			Status:      model.AssetDiscoveryProbeRunning,
			CreatedBy:   t.CreatedBy,
			OrganizeID:  t.OrganizeID,
			CreatedAt:   t.CreatedAt,
			UpdatedAt:   now,
		}
		switch t.Status {
		case model.TaskStatusCompleted, model.TaskStatusPartial:
			probe.Status = model.AssetDiscoveryProbeCompleted
			probe.FinishedAt = t.FinishedAt
		case model.TaskStatusFailed:
			probe.Status = model.AssetDiscoveryProbeFailed
			probe.ErrorMsg = t.ErrorMsg
			probe.FinishedAt = t.FinishedAt
		case model.TaskStatusCancelled:
			probe.Status = model.AssetDiscoveryProbeCancelled
			probe.FinishedAt = t.FinishedAt
		default:
			if t.StartedAt != nil {
				probe.StartedAt = t.StartedAt
			}
		}
		if err := sess.Create(&probe).Error; err != nil {
			slog.Warn("[AssetDiscovery] 回填探测记录失败", "task_id", t.ID, "error", err)
			continue
		}
		taskIDs := scanrunner.DiscoveryScanTaskIDs(sess, t.ID)
		if _, err := scanrunner.SyncAssetDiscoveryCandidates(sess, probe.ID, taskIDs); err != nil {
			slog.Warn("[AssetDiscovery] 回填同步候选失败", "probe_id", probe.ID, "error", err)
		}
		_ = scanrunner.UpdateProbeStatusFromTask(sess, &probe, &t)
	}
}

func (h *DiscoveryHandler) CreateProbe(c *gin.Context) {
	var req createDiscoveryProbeReq
	if !web.ValidationJson(c, &req) {
		return
	}
	rawTargets := parseDiscoveryTargets(req)
	if len(rawTargets) == 0 {
		web.Fail(c).Msg("请填写探测目标（支持 IP、域名、CIDR 网段，每行一个）").Send()
		return
	}
	if h.scanDB == nil || h.scanScheduler == nil {
		web.Fail(c).Msg("扫描调度器未初始化，无法启动资产探测").Send()
		return
	}

	expanded, err := scanrunner.ExpandScanTargets(rawTargets, 4096)
	if err != nil {
		web.Fail(c).Msg(err.Error()).Send()
		return
	}

	portsPreset, err := normalizePortsPreset(req.PortsPreset, req.PortsCustom)
	if err != nil {
		web.Fail(c).Msg(err.Error()).Send()
		return
	}
	timeoutMs := req.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 800
	}
	if timeoutMs < 200 {
		web.Fail(c).Msg("发现超时不能低于 200ms，CIDR 网段扫描建议 500–2000ms").Send()
		return
	}
	timeoutSec := float64(timeoutMs) / 1000.0

	userID, organizeID := discoveryActor(c)
	probeID := ulid.GenerateID()
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = fmt.Sprintf("资产探测 %s", time.Now().Format("2006-01-02 15:04"))
	}

	moduleConfigs := map[string]interface{}{
		"host_discover": map[string]interface{}{
			"ports":   portsPreset,
			"timeout": timeoutSec,
		},
	}
	params := map[string]interface{}{
		"module_configs":           moduleConfigs,
		"asset_discovery_probe_id": probeID,
		"skip_vuln_when_no_http":   true,
	}

	res, err := scanrunner.LaunchScan(h.scanDB, h.scanScheduler, scanrunner.LaunchScanParams{
		Name:       name,
		Targets:    expanded,
		TemplateID: scanrunner.AssetDiscoveryTemplateID,
		Parameters: params,
		Priority:   5,
		CreatedBy:  userID,
		OrganizeID: organizeID,
		TaskType:   model.TaskTypeAssetDiscovery,
	})
	if errors.Is(err, scanrunner.ErrTemplateNotFound) {
		web.Fail(c).Msg("内置资产探测模板不存在，请重启服务以同步内置模板（或调用模板管理「同步内置模板」）").Send()
		return
	}
	if err != nil {
		slog.Error("[AssetDiscovery] 启动扫描失败", "error", err, "targets", len(expanded))
		web.Fail(c).Msg("启动探测失败: " + err.Error()).Send()
		return
	}

	targetsRaw := strings.Join(rawTargets, "\n")
	now := time.Now()
	probe := model.AssetDiscoveryProbe{
		ID:          probeID,
		Name:        name,
		TaskID:      res.Task.ID,
		TargetsRaw:  targetsRaw,
		TargetCount: len(expanded),
		PortsPreset: portsPreset,
		Status:      model.AssetDiscoveryProbeRunning,
		CreatedBy:   userID,
		OrganizeID:  organizeID,
		StartedAt:   &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.probeDB().Create(&probe).Error; err != nil {
		slog.Error("[AssetDiscovery] 写入探测记录失败", "error", err, "probe_id", probeID, "task_id", res.Task.ID)
		web.Fail(c).Msg("创建探测记录失败，请确认已重启后端并完成数据库迁移: " + err.Error()).Send()
		return
	}

	web.Succeed(c).Data(gin.H{
		"probe":      probe,
		"task_id":    res.Task.ID,
		"split_mode": res.SplitMode,
		"sub_count":  res.SubCount,
		"expanded":   len(expanded),
	}).Send()
}

func (h *DiscoveryHandler) ListProbes(c *gin.Context) {
	query, ok := web.BindQuery[discoveryProbeQuery](c)
	if !ok {
		return
	}
	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 {
		query.PageSize = 20
	}

	sess := h.probeDB()
	h.backfillProbesFromScanTasks(sess)

	q := sess.Model(&model.AssetDiscoveryProbe{})
	if kw := strings.TrimSpace(query.Keyword); kw != "" {
		like := "%" + kw + "%"
		q = q.Where("name LIKE ? OR targets_raw LIKE ?", like, like)
	}
	if st := strings.TrimSpace(query.Status); st != "" {
		q = q.Where("status = ?", st)
	}

	var total int64
	var items []model.AssetDiscoveryProbe
	if err := q.Count(&total).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	if err := q.Order("created_at DESC").
		Offset((query.Page - 1) * query.PageSize).
		Limit(query.PageSize).
		Find(&items).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	out := make([]discoveryProbeListItem, 0, len(items))
	taskIDs := make([]string, 0, len(items))
	for _, p := range items {
		if p.TaskID != "" {
			taskIDs = append(taskIDs, p.TaskID)
		}
		out = append(out, discoveryProbeListItem{AssetDiscoveryProbe: p})
	}
	if len(taskIDs) > 0 {
		var tasks []model.ScanTask
		_ = sess.Where("id IN ?", taskIDs).Find(&tasks).Error
		byID := make(map[string]model.ScanTask, len(tasks))
		for _, t := range tasks {
			byID[t.ID] = t
		}
		for i := range out {
			if t, ok := byID[out[i].TaskID]; ok {
				out[i].TaskStatus = t.Status
				out[i].AliveHosts = t.AliveHosts
				out[i].OpenPorts = t.OpenPorts
			}
		}
	}
	web.Succeed(c).List(total, out).Send()
}

func (h *DiscoveryHandler) GetProbe(c *gin.Context) {
	id := c.Param("id")
	var probe model.AssetDiscoveryProbe
	if err := h.probeDB().First(&probe, "id = ?", id).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	if probe.TaskID != "" {
		var task model.ScanTask
		if err := h.probeDB().First(&task, "id = ?", probe.TaskID).Error; err == nil {
			_ = scanrunner.UpdateProbeStatusFromTask(h.probeDB(), &probe, &task)
			_ = h.probeDB().First(&probe, "id = ?", id).Error
		}
	}
	web.Succeed(c).Data(probe).Send()
}

func (h *DiscoveryHandler) ListCandidates(c *gin.Context) {
	probeID := c.Param("id")
	query, ok := web.BindQuery[discoveryCandidateQuery](c)
	if !ok {
		return
	}
	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 {
		query.PageSize = 50
	}

	sess := h.probeDB()
	q := sess.Model(&model.AssetDiscoveryCandidate{}).Where("probe_id = ?", probeID)
	if st := strings.TrimSpace(query.Status); st != "" {
		q = q.Where("status = ?", st)
	}
	if kw := strings.TrimSpace(query.Keyword); kw != "" {
		like := "%" + kw + "%"
		q = q.Where("address LIKE ? OR service LIKE ? OR title LIKE ?", like, like, like)
	}

	scanrunner.DedupeDiscoveryCandidatesByProbe(sess, probeID)

	var total int64
	var items []model.AssetDiscoveryCandidate
	if err := q.Count(&total).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	if err := q.Order("address ASC").
		Offset((query.Page - 1) * query.PageSize).
		Limit(query.PageSize).
		Find(&items).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	enrichDiscoveryCandidateAssets(sess, items)
	enrichDiscoveryCandidateOrganizes(sess, items)
	var dedupedTotal int
	items, dedupedTotal = scanrunner.DedupeDiscoveryCandidateRows(items, int(total))
	total = int64(dedupedTotal)
	web.Succeed(c).List(total, items).Send()
}

func (h *DiscoveryHandler) SyncCandidates(c *gin.Context) {
	probeID := c.Param("id")
	var probe model.AssetDiscoveryProbe
	if err := h.probeDB().First(&probe, "id = ?", probeID).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	if probe.TaskID == "" {
		web.Fail(c).Msg("探测任务尚未关联扫描引擎").Send()
		return
	}
	taskIDs := scanrunner.DiscoveryScanTaskIDs(h.probeDB(), probe.TaskID)
	n, err := scanrunner.SyncAssetDiscoveryCandidates(h.probeDB(), probe.ID, taskIDs)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(gin.H{"synced": n}).Send()
}

func (h *DiscoveryHandler) VerifyCandidates(c *gin.Context) {
	var req discoveryVerifyReq
	if !web.ValidationJson(c, &req) {
		return
	}
	targetOrganizeID := strings.TrimSpace(req.TargetOrganizeID)
	if targetOrganizeID == "" {
		web.Fail(c).Msg("请选择核验目标单位").Send()
		return
	}
	var org model.Organize
	if err := h.probeDB().First(&org, "id = ?", targetOrganizeID).Error; err != nil {
		web.Fail(c).Msg("目标单位不存在").Send()
		return
	}

	userID, _ := discoveryActor(c)
	now := time.Now()
	updates := map[string]interface{}{
		"status":             model.AssetDiscoveryCandidateVerified,
		"target_organize_id": targetOrganizeID,
		"verify_remark":      strings.TrimSpace(req.Remark),
		"verified_by":        userID,
		"verified_at":        &now,
		"updated_at":         now,
	}
	res := h.probeDB().Model(&model.AssetDiscoveryCandidate{}).
		Where("id IN ? AND status = ?", req.IDs, model.AssetDiscoveryCandidatePending).
		Updates(updates)
	if res.Error != nil {
		web.Fail(c).Err(res.Error).Send()
		return
	}
	if probeID := c.Param("id"); probeID != "" {
		_ = scanrunner.RefreshProbeCandidateCounts(h.probeDB(), probeID)
	}
	web.Succeed(c).Data(gin.H{
		"updated":              res.RowsAffected,
		"target_organize_id":   targetOrganizeID,
		"target_organize_name": org.Name,
	}).Send()
}

func (h *DiscoveryHandler) RejectCandidates(c *gin.Context) {
	h.updateCandidateStatus(c, model.AssetDiscoveryCandidateRejected)
}

func (h *DiscoveryHandler) updateCandidateStatus(c *gin.Context, status string) {
	var req discoveryIDsReq
	if !web.ValidationJson(c, &req) {
		return
	}
	userID, _ := discoveryActor(c)
	now := time.Now()
	updates := map[string]interface{}{
		"status":        status,
		"verify_remark": strings.TrimSpace(req.Remark),
		"verified_by":   userID,
		"verified_at":   &now,
		"updated_at":    now,
	}
	res := h.probeDB().Model(&model.AssetDiscoveryCandidate{}).
		Where("id IN ? AND status = ?", req.IDs, model.AssetDiscoveryCandidatePending).
		Updates(updates)
	if res.Error != nil {
		web.Fail(c).Err(res.Error).Send()
		return
	}
	if probeID := c.Param("id"); probeID != "" {
		_ = scanrunner.RefreshProbeCandidateCounts(h.probeDB(), probeID)
	}
	web.Succeed(c).Data(gin.H{"updated": res.RowsAffected}).Send()
}

func (h *DiscoveryHandler) ImportCandidates(c *gin.Context) {
	var req discoveryIDsReq
	if !web.ValidationJson(c, &req) {
		return
	}
	userID, _ := discoveryActor(c)
	sess := h.probeDB()

	var candidates []model.AssetDiscoveryCandidate
	if err := sess.Where("id IN ?", req.IDs).
		Where("status = ?", model.AssetDiscoveryCandidateVerified).
		Find(&candidates).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	if len(candidates) == 0 {
		web.Fail(c).Msg("仅可将「已下发核验」的候选入库，请先选择目标单位完成下发核验").Send()
		return
	}

	imported := 0
	skipped := 0
	seenHost := map[string]struct{}{}
	var assets []model.Asset
	now := time.Now()
	for i := range candidates {
		cand := &candidates[i]
		if cand.Status == model.AssetDiscoveryCandidateImported {
			skipped++
			continue
		}
		targetOrgID := strings.TrimSpace(cand.TargetOrganizeID)
		if targetOrgID == "" {
			skipped++
			continue
		}
		hostKey := scanrunner.DiscoveryCandidateDedupKey(cand.Address)
		if hostKey == "" {
			skipped++
			continue
		}
		if _, dup := seenHost[hostKey]; dup {
			skipped++
			continue
		}
		seenHost[hostKey] = struct{}{}

		canonical := scanrunner.DiscoveryCanonicalHost(cand.Address)
		var existing model.Asset
		if err := sess.Model(&model.Asset{}).Where("status = ?", 1).
			Where("ipv4 = ? OR address = ? OR address LIKE ?", canonical, canonical, canonical+":%").
			First(&existing).Error; err == nil {
			skipped++
			_ = sess.Model(cand).Updates(map[string]interface{}{
				"status":            model.AssetDiscoveryCandidateInLibrary,
				"imported_asset_id": existing.ID,
				"updated_at":        now,
			}).Error
			continue
		}

		addr := discoveryCandidateAddress(cand)
		if addr == "" {
			skipped++
			continue
		}
		assetType := cand.AssetType
		if assetType == "" {
			assetType = "host"
		}
		name := strings.TrimSpace(cand.Title)
		if name == "" {
			name = addr
		}
		ipv4 := ""
		if ip := net.ParseIP(cand.Address); ip != nil && ip.To4() != nil {
			ipv4 = ip.String()
		}
		item := model.Asset{
			ID:         ulid.GenerateID(),
			Name:       name,
			Type:       assetType,
			Address:    addr,
			Port:       cand.Port,
			Protocol:   cand.Protocol,
			Service:    cand.Service,
			Version:    cand.Version,
			IPv4:       ipv4,
			Status:     1,
			DataSource: model.DataSourceDiscovery,
			CreatedBy:  userID,
			OrganizeID: targetOrgID,
			Remark:     strings.TrimSpace(req.Remark),
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		item.Address = canonical
		normalizeAssetAddressFields(&item)
		if err := h.assetSvc.Create(&item); err != nil {
			skipped++
			continue
		}
		imported++
		assets = append(assets, item)
		_ = sess.Model(cand).Updates(map[string]interface{}{
			"status":            model.AssetDiscoveryCandidateImported,
			"imported_asset_id": item.ID,
			"verified_by":       userID,
			"verified_at":       &now,
			"updated_at":        now,
		}).Error
	}

	if len(assets) > 0 && h.assetSvc != nil {
		// Create 已触发核验任务；批量路径再保险
	}
	probeIDs := map[string]struct{}{}
	for i := range candidates {
		if candidates[i].ProbeID != "" {
			probeIDs[candidates[i].ProbeID] = struct{}{}
		}
	}
	for pid := range probeIDs {
		_ = scanrunner.RefreshProbeCandidateCounts(h.probeDB(), pid)
	}
	web.Succeed(c).Data(gin.H{"imported": imported, "skipped": skipped}).Send()
}

func discoveryCandidateAddress(c *model.AssetDiscoveryCandidate) string {
	if c == nil {
		return ""
	}
	host := strings.TrimSpace(c.Address)
	if host == "" {
		return ""
	}
	if c.Port > 0 {
		if ip := net.ParseIP(host); ip != nil {
			return fmt.Sprintf("%s:%d", host, c.Port)
		}
		return net.JoinHostPort(host, fmt.Sprintf("%d", c.Port))
	}
	return host
}
